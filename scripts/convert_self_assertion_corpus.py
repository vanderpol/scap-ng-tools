"""Convert pinned OVAL Self-Assertion Definitions through the production CLI.

This is a production-CLI orchestrator, not a second converter. Each source
Definition is sent unchanged to ``scap_ng_tools.converter.direct04``. A
successful invocation publishes the CLI's schema-validated JSON/YAML and trace;
failures remain in a per-Definition and per-Test blocked ledger with the exact
converter diagnostic. No expected outcomes or source semantics are invented.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import re
from typing import Any
import xml.etree.ElementTree as ET
from zipfile import ZipFile

import yaml

from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot
from scap_ng_tools.converter.direct04 import validate_native_documents
from scap_ng_tools.converter.native041_variable_result_type import result_type

CORPUS_ROOT = Path("SCAP_1.4/OVAL_Test_Content")
FAMILIES = ("agnostic", "aix", "asa", "ios", "iosxe", "junos", "linux", "macos", "panos", "solaris", "unix", "windows")
ZIP_NAME = "oval-def-ext.zip"
ZIP_DEFINITION_MEMBER = "oval-def-ext.xml"
FORMAT = "scap-ng-tools-self-assertion-conversion/2"


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def source_documents(corpus: Path, families: tuple[str, ...]):
    """Yield (repository path, member path, raw XML) deterministically."""
    for family in families:
        family_rel = CORPUS_ROOT / family
        base = corpus / family_rel
        for path in sorted(base.glob("*.xml")):
            yield family_rel / path.name, family_rel / path.name, path.read_bytes()
        if family != "agnostic":
            continue
        # The embedded OVAL Definition is part of the pinned source
        # denominator, not an opt-in environment-dependent extension.
        # Missing archives/members fail closed instead of silently producing
        # the older 167-Definition ledger.
        archive = base / ZIP_NAME
        with ZipFile(archive) as package:
            raw = package.read(ZIP_DEFINITION_MEMBER)
            yield family_rel / f"{ZIP_NAME}!{ZIP_DEFINITION_MEMBER}", family_rel / f"{ZIP_NAME}!{ZIP_DEFINITION_MEMBER}", raw


def nodes(root: ET.Element, suffix: str):
    return [node for node in root.iter() if node.tag.split("}")[-1] == suffix and node.get("id")]


def source_feature_inventory(root: ET.Element, family: str, tests: dict[str, ET.Element]):
    """Inventory source constructs without assigning converter semantics.

    These labels explain why a source graph is likely held (or which native
    capability it exercises); the exact converter diagnostic remains the
    authoritative blocker in the ledgers.
    """
    by_id = {node.get("id"): node for node in root.iter() if node.get("id")}
    node_features: dict[str, set[str]] = defaultdict(set)
    common = {f"source_family:{family}"}
    for node in root.iter():
        ident = node.get("id")
        if not ident:
            continue
        local = node.tag.split("}")[-1]
        if local.endswith("_test"):
            node_features[ident].add("source_test_kind:" + local)
        if local.endswith("_variable"):
            datatype = node.get("datatype")
            if datatype:
                node_features[ident].add("variable_datatype:" + datatype)
            if any(child.tag.split("}")[-1] == "object_component" for child in node.iter()):
                node_features[ident].add("object_components")
            if any(child.tag.split("}")[-1].endswith("_function") or
                   child.tag.split("}")[-1] in {
                       "arithmetic", "begin", "concat", "end", "escape_regex",
                       "glob_to_regex", "regex_capture", "split", "substring",
                       "time_difference"} for child in node.iter()):
                node_features[ident].add("functions")
        if local == "external_variable":
            node_features[ident].add("external_variables")
        if local == "variable_object" and any(
                child.tag.split("}")[-1] in {"set", "filter"} for child in node.iter()):
            node_features[ident].add("variable_object_sets_or_filters")
        if local in {"family_test", "unknown_test"}:
            node_features[ident].add("unsupported_declaration:" + local)

    def closure(ident: str, seen: set[str] | None = None) -> set[str]:
        seen = set() if seen is None else seen
        if ident in seen:
            return set()
        seen.add(ident)
        node = by_id.get(ident)
        if node is None:
            return set()
        result = set(node_features.get(ident, ()))
        for child in node.iter():
            for key, value in child.attrib.items():
                if key.endswith("_ref") and value:
                    result.update(closure(value, seen))
            if child.tag.split("}")[-1] == "var_ref" and child.text:
                result.update(closure(child.text, seen))
        return result

    test_features = {test_id: sorted(common | closure(test_id))
                     for test_id in tests}
    definition_features = {}
    for definition in nodes(root, "definition"):
        refs = [node.get("test_ref") for node in definition.iter()
                if node.tag.split("}")[-1] == "criterion" and node.get("test_ref")]
        features = set(common)
        for test_id in refs:
            features.update(test_features.get(test_id, ()))
        definition_features[definition.get("id")] = sorted(features)
    return definition_features, test_features


def definitions_and_tests(raw: bytes, family: str = "unknown"):
    """Inventory Definitions and all Tests with transitive ownership.

    XCCDF/OVAL source commonly puts a Test only in an extended Definition.
    A flat criterion scan gives the extending Definition no Test owner and
    makes the Test ledger appear complete while its ownership is wrong.
    Preserve source order, expand extend_definition transitively, and fail
    closed on cycles or missing extended Definitions.
    """
    root = ET.fromstring(raw)
    definitions = {}
    direct_refs = {}
    for definition in nodes(root, "definition"):
        ident = definition.get("id")
        refs = []
        for node in definition.iter():
            if node.tag.split("}")[-1] == "criterion" and node.get("test_ref"):
                test_id = node.get("test_ref")
                if test_id not in refs:
                    refs.append(test_id)
        definitions[ident] = refs
        direct_refs[ident] = refs
    tests = {node.get("id"): node for node in root.iter()
             if node.get("id") and node.tag.split("}")[-1].endswith("_test")}

    def closure(ident, visiting=None, visited=None):
        visiting = set() if visiting is None else visiting
        visited = {} if visited is None else visited
        if ident in visiting:
            raise ValueError("cyclic source extend_definition: " + ident)
        if ident in visited:
            return list(visited[ident])
        if ident not in definitions:
            raise ValueError("unresolved source extended Definition: " + ident)
        visiting.add(ident)
        result = list(direct_refs[ident])
        for definition in root.iter():
            if definition.get("id") != ident or definition.tag.split("}")[-1] != "definition":
                continue
            for child in definition.iter():
                if child.tag.split("}")[-1] == "extend_definition":
                    target = child.get("definition_ref")
                    if not target:
                        raise ValueError("missing source extended Definition reference")
                    for test_id in closure(target, visiting, visited):
                        if test_id not in result:
                            result.append(test_id)
            break
        visiting.remove(ident)
        visited[ident] = tuple(result)
        return result

    ownership = defaultdict(list)
    expanded = {}
    for definition_id in definitions:
        refs = closure(definition_id)
        expanded[definition_id] = refs
        for test_id in refs:
            if test_id not in tests:
                raise ValueError("unknown source Test in criteria: " + test_id)
            ownership[test_id].append(definition_id)
    definitions = expanded
    test_defs = {test_id: owners for test_id, owners in ownership.items()}
    definition_features, test_features = source_feature_inventory(root, family, tests)
    return definitions, tests, test_defs, definition_features, test_features


def slug(value: str) -> str:
    return value.replace(":", "_").replace("/", "_")


def source_variable_datatype_mismatches(raw: bytes) -> list[dict[str, str]]:
    """Return source-declared Variable type mismatches with source evidence.

    OVAL 5.12.3 requires a Variable declaration to agree with the result type
    of its expression, and requires an entity using ``var_ref`` to agree with
    the referenced Variable declaration.  The production converter has a
    bounded compatibility adapter for the former so it can preserve an
    otherwise useful artifact, but the source disposition must remain
    ``source_invalid`` until the XML is corrected.  This helper deliberately
    does not normalize or rewrite source XML.
    """
    root = ET.fromstring(raw)
    variables = {
        node.get("id"): node
        for node in root.iter()
        if node.get("id") and node.tag.rsplit("}", 1)[-1].endswith("_variable")
    }
    mismatches: list[dict[str, str]] = []

    # Check the declaration against the expression's statically derived type.
    # The same shared type function used by production conversion is used only
    # as a read-only source audit; no host values are acquired here.
    def resolve(identifier: str):
        return variables.get(identifier)

    for identifier, variable in variables.items():
        declared = variable.get("datatype")
        if not declared or variable.tag.rsplit("}", 1)[-1] not in {
                "local_variable", "constant_variable"}:
            continue
        try:
            expression_type = result_type(variable, resolve)
        except (KeyError, TypeError, ValueError):
            # An independently reported converter/source hold is more useful
            # than inventing a type mismatch from an unresolved graph.
            continue
        if expression_type and expression_type != declared:
            mismatches.append({
                "kind": "variable_expression_result",
                "element": variable.tag.rsplit("}", 1)[-1],
                "element_id": identifier,
                "variable_id": identifier,
                "declared_datatype": declared,
                "expression_result_datatype": expression_type,
            })

    # Check every source entity that references a Variable.  This remains a
    # separate witness because it is an entity/Variable boundary violation,
    # not the same defect as a Variable expression result mismatch.
    for node in root.iter():
        reference = node.get("var_ref")
        entity_datatype = node.get("datatype")
        variable = variables.get(reference)
        variable_datatype = variable.get("datatype") if variable is not None else None
        if (reference and entity_datatype and variable_datatype and
                entity_datatype != variable_datatype):
            mismatches.append({
                "kind": "entity_variable_reference",
                "element": node.tag.rsplit("}", 1)[-1],
                "element_id": node.get("id", ""),
                "variable_id": reference,
                "declared_datatype": variable_datatype,
                "variable_datatype": variable_datatype,
                "entity_datatype": entity_datatype,
            })
    return sorted(mismatches, key=lambda item: (
        item["kind"], item.get("element", ""), item.get("element_id", ""),
        item["variable_id"]))


def source_definition_variable_ids(raw: bytes, definition_id: str) -> set[str]:
    """Return Variables reachable from one Definition's source reference graph.

    Source files commonly contain several Definitions and shared Variables.
    A file-level mismatch must not poison unrelated Definitions.  Traverse
    only explicit OVAL references from the selected Definition, including
    nested ``var_ref`` child elements and ``*_ref`` attributes.
    """
    root = ET.fromstring(raw)
    by_id = {node.get("id"): node for node in root.iter() if node.get("id")}
    start = by_id.get(definition_id)
    if start is None:
        return set()
    pending = [start]
    visited: set[str] = set()
    variables: set[str] = set()
    while pending:
        node = pending.pop()
        identity = node.get("id")
        if identity and identity in visited:
            continue
        if identity:
            visited.add(identity)
            if node.tag.rsplit("}", 1)[-1].endswith("_variable"):
                variables.add(identity)
        refs: list[str] = []
        for child in node.iter():
            for name, value in child.attrib.items():
                if name.endswith("_ref") and value:
                    refs.append(value)
            if child.tag.rsplit("}", 1)[-1] == "var_ref" and child.text:
                refs.append(child.text.strip())
        for reference in refs:
            target = by_id.get(reference)
            if target is not None and reference not in visited:
                pending.append(target)
    return variables


def classify_failure(stderr: str, stdout: str, *,
                     source_mismatches: list[dict[str, str]] | None = None,
                     supported_source_capabilities: dict[str, set[str]] | None = None) -> str:
    """Classify a failed source conversion without hiding source holds.

    Diagnostics often contain both ``unsupported`` and ``deprecated``.  The
    source disposition is more specific and must win, otherwise a deprecated
    construct is incorrectly reported as a converter implementation gap.
    """
    message = (stderr.strip() or stdout.strip()).lower()
    if "deprecated" in message:
        return "deprecated_source_construct"
    if "possible_restriction" in message or "external variable" in message:
        return "canonical_input_constraint_hold"
    if source_mismatches:
        return "source_invalid_var_ref_datatype"
    if "invalid int literal" in message or "policy source literal must be nonnegative" in message:
        return "source_typed_literal_invalid"
    if "traversal" in message and ("schema" in message or "validation" in message):
        return "canonical_traversal_schema_hold"
    capability = re.search(
        r"unsupported\s+(test|object|state)\s+capability:\s*\{[^}]+\}([a-z0-9_]+)",
        message)
    if capability and supported_source_capabilities is not None:
        kind, source_name = capability.groups()
        if source_name not in supported_source_capabilities.get(kind, set()):
            return "canonical_capability_gap"
    if any(token in message for token in ("unsupported", "held", "not migrated")):
        return "unsupported"
    if "schema" in message or "validation" in message:
        return "schema_or_validation_failure"
    return "converter_failure"


def public_command(command: list[str], *, schema_root: Path, source: Path,
                   output: Path) -> list[str]:
    """Keep the ledger command useful without leaking ephemeral host paths."""
    replacements = {
        str(schema_root): "<schema-root>",
        str(source): "<temporary-source>/{0}".format(source.name),
        str(output): "<temporary-output>",
    }
    result = []
    for index, argument in enumerate(command):
        if index == 0:
            result.append("python")
            continue
        result.append(replacements.get(argument, argument))
    return result


def run_one(*, python: str, schema_root: Path, source: Path, source_sha: str,
            source_commit: str, source_path: str, definition: str, out: Path):
    command = [python, "-m", "scap_ng_tools.converter.direct04",
               "--schema-root", str(schema_root), "--source", str(source),
               "--sha256", source_sha, "--oval-definition", definition,
               "--source-commit", source_commit, "--source-path", source_path,
               "--output", str(out)]
    process = subprocess.run(command, capture_output=True, text=True, timeout=120,
                             check=False)
    files = {name: out / name for name in
             ("assessment.json", "assessment.yaml", "conversion-scope.json", "source-trace.json")}
    success = process.returncode == 0 and all(path.is_file() for path in files.values())
    return command, process, files, success


def independent_artifacts(snapshot: Pinned041SchemaSnapshot, files: dict[str, Path]):
    document = json.loads(files["assessment.json"].read_text())
    yaml_document = yaml.safe_load(files["assessment.yaml"].read_text())
    if document != yaml_document:
        raise ValueError("converter JSON/YAML read-back differs")
    validate_native_documents(snapshot, {"assessment.json": document})
    validate_native_documents(snapshot, {"assessment.yaml": yaml_document})
    return {name: {"sha256": digest(path.read_bytes()), "bytes": path.stat().st_size}
            for name, path in files.items()}


def convert(*, corpus: Path, schema_root: Path, source_commit: str,
            output: Path, python: str, families: tuple[str, ...] = ("agnostic",)):
    if output.exists():
        raise ValueError(f"refusing to overwrite existing output: {output}")
    snapshot = Pinned041SchemaSnapshot(schema_root)
    supported_source_capabilities = {"test": set(), "object": set(), "state": set()}
    for mapping in snapshot.supported_mappings():
        source = mapping.get("source", {})
        for kind in supported_source_capabilities:
            name = source.get(kind)
            if name:
                supported_source_capabilities[kind].add(name)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix="self-assertion-conversion-", dir=output.parent))
    try:
        definition_rows: list[dict[str, Any]] = []
        test_rows: list[dict[str, Any]] = []
        converted_rows: list[dict[str, Any]] = []
        # First inventory the source graph.  Conversion is deliberately done
        # in a second pass so a Test shared by multiple Definitions gets one
        # ledger row with all of its owners, rather than whichever owner was
        # visited last.
        source_graph = []
        with tempfile.TemporaryDirectory(prefix="self-assertion-source-") as extracted:
            extracted_root = Path(extracted)
            for source_path, provenance_path, raw in source_documents(corpus, families):
                family = str(source_path).split("/")[-2]
                definitions, tests, test_defs, definition_features, test_features = definitions_and_tests(raw, family)
                source_sha = digest(raw)
                # Keep ordinary XML at its pinned checkout path.  The
                # production standalone lane can then independently verify
                # the declared commit/blob, rather than seeing a copied temp
                # file.  A Definition embedded in the committed ZIP has no
                # standalone Git path and necessarily uses an extracted file.
                source_text_path = corpus / provenance_path
                if not source_text_path.is_file():
                    source_text_path = extracted_root / (slug(str(source_path)) + ".xml")
                    source_text_path.write_bytes(raw)
                elif source_text_path.read_bytes() != raw:
                    raise ValueError(f"source path bytes changed while inventorying: {provenance_path}")
                source_graph.append({
                    "source_path": source_path,
                    "provenance_path": provenance_path,
                    "raw": raw,
                    "source_sha256": source_sha,
                    "source_text_path": source_text_path,
                    "definitions": definitions,
                    "tests": tests,
                    "test_defs": test_defs,
                    "definition_features": definition_features,
                    "test_features": test_features,
                    "source_variable_datatype_mismatches": source_variable_datatype_mismatches(raw),
                })
            definition_results = {}
            for graph in source_graph:
                source_path = graph["source_path"]
                family = str(source_path).split("/")[-2]
                provenance_path = graph["provenance_path"]
                source_sha = graph["source_sha256"]
                source_text_path = graph["source_text_path"]
                definitions = graph["definitions"]
                definition_features = graph["definition_features"]
                for definition_id, refs in definitions.items():
                    # Every pinned OVAL platform family is an authoring target.
                    # Runtime qualification remains separate, but a platform must
                    # not be hidden as an owner exclusion when the canonical pack
                    # already has a capability mapping. Unsupported or schema-held
                    # AIX content must be reported through the ordinary blocker
                    # ledger with its exact source diagnostic.
                    artifact_dir = temp / "definitions" / slug(str(source_path)) / slug(definition_id)
                    command, process, files, success = run_one(
                        python=python, schema_root=schema_root, source=source_text_path,
                        source_sha=source_sha, source_commit=source_commit,
                        source_path=str(provenance_path), definition=definition_id,
                        out=artifact_dir)
                    recorded_command = (public_command(
                        command, schema_root=schema_root, source=source_text_path,
                        output=artifact_dir) if command else None)
                    reachable_variables = source_definition_variable_ids(graph["raw"], definition_id)
                    source_mismatches = [
                        mismatch for mismatch in graph["source_variable_datatype_mismatches"]
                        if mismatch["variable_id"] in reachable_variables
                    ]
                    failure_class = None if success else classify_failure(
                        process.stderr, process.stdout, source_mismatches=source_mismatches,
                        supported_source_capabilities=supported_source_capabilities)
                    diagnostic = None if success else (process.stderr.strip() or process.stdout.strip())
                    if source_mismatches and failure_class == "source_invalid_var_ref_datatype":
                        diagnostic = (
                            (diagnostic + "; " if diagnostic else "") +
                            "source evidence: " + json.dumps(
                                source_mismatches, sort_keys=True, separators=(",", ":"))
                        )
                    row = {
                        "source_path": str(provenance_path),
                        "source_sha256": source_sha,
                        "definition_id": definition_id,
                        "source_test_ids": refs,
                        "source_test_count": len(refs),
                        "feature_categories": definition_features.get(definition_id, []),
                        "converter_command": recorded_command,
                        "converter_returncode": process.returncode,
                        "conversion_status": "CONVERTED_UNVERIFIED" if success else "blocked",
                        "scope_classification": "in_scope",
                        "owner_decision": None,
                        "schema_validated": False,
                        "independent_semantic_proof": False,
                        "scanner_execution": False,
                        "failure_class": failure_class,
                        "diagnostic": diagnostic,
                        "source_semantic_evidence": source_mismatches,
                        "artifacts": None,
                    }
                    trace = None
                    bindings = {}
                    if success:
                        try:
                            artifacts = independent_artifacts(snapshot, files)
                            trace = json.loads(files["source-trace.json"].read_text())
                            bindings = {entry["source_test"]: entry["native_test"]
                                        for entry in trace.get("test_bindings", [])}
                        except Exception as error:
                            # A zero exit status is not enough for publication:
                            # malformed or independently invalid output belongs
                            # in the same complete blocked ledger as a CLI
                            # rejection.
                            success = False
                            row["conversion_status"] = "blocked"
                            row["failure_class"] = "schema_or_validation_failure"
                            row["diagnostic"] = str(error)
                        else:
                            row["schema_validated"] = True
                            row["artifacts"] = artifacts
                            # Preserve generated artifacts for forensic comparison,
                            # but source-invalid XML is not a source-parity success.
                            if source_mismatches:
                                row["conversion_status"] = "source_invalid"
                                row["failure_class"] = "source_invalid_var_ref_datatype"
                                row["diagnostic"] = (
                                    "source evidence: " + json.dumps(
                                        source_mismatches, sort_keys=True,
                                        separators=(",", ":")))
                            else:
                                converted_rows.append(row)
                    definition_rows.append(row)
                    definition_results[(str(provenance_path), definition_id)] = {
                        "status": row["conversion_status"],
                        "schema_validated": row["schema_validated"],
                        "native_bindings": bindings,
                        "failure_class": row["failure_class"],
                        "diagnostic": row["diagnostic"],
                        "source_semantic_evidence": row.get("source_semantic_evidence", []),
                    }
            for graph in source_graph:
                provenance_path = str(graph["provenance_path"])
                source_sha = graph["source_sha256"]
                definitions = graph["definitions"]
                tests = graph["tests"]
                test_defs = graph["test_defs"]
                test_features = graph["test_features"]
                for test_id in sorted(tests):
                    owner_ids = list(test_defs.get(test_id, []))
                    owner_results = [definition_results[(provenance_path, owner)]
                                     for owner in owner_ids]
                    bindings = [result["native_bindings"].get(test_id)
                                for result in owner_results]
                    native_ids = sorted({value for value in bindings if value})
                    invalid_results = [result for result in owner_results
                                       if result["status"] == "source_invalid"]
                    if invalid_results:
                        status = "source_invalid"
                        schema_validated = all(result["schema_validated"] for result in invalid_results)
                        failure_class = "source_invalid_var_ref_datatype"
                        diagnostic = next((result["diagnostic"] for result in invalid_results
                                           if result["diagnostic"]),
                                          "source Variable/entity datatype mismatch")
                    elif native_ids:
                        status = "CONVERTED_UNVERIFIED"
                        schema_validated = True
                        failure_class = None
                        diagnostic = None
                    elif owner_ids:
                        status = "blocked"
                        schema_validated = False
                        failure_class = next((result["failure_class"] for result in owner_results
                                               if result["failure_class"]), "converter_failure")
                        diagnostic = next((result["diagnostic"] for result in owner_results
                                           if result["diagnostic"]), "source Test was not emitted by converter")
                    else:
                        # A standalone source document can contain helper Tests
                        # not referenced by a Definition; retain them rather
                        # than silently dropping them.
                        status = "blocked"
                        schema_validated = False
                        failure_class = "unmapped_source_test"
                        diagnostic = "source Test is not referenced by a Definition criterion"
                    source_semantic_evidence = []
                    for owner in owner_ids:
                        evidence = definition_results[(provenance_path, owner)].get(
                            "source_semantic_evidence", [])
                        for entry in evidence:
                            if entry not in source_semantic_evidence:
                                source_semantic_evidence.append(entry)
                    test_rows.append({
                        "source_path": provenance_path,
                        "source_sha256": source_sha,
                        "definition_ids": owner_ids,
                        "definition_results": [
                            {
                                "definition_id": owner,
                                "conversion_status": result["status"],
                                "schema_validated": result["schema_validated"],
                                "native_test_id": result["native_bindings"].get(test_id),
                                "failure_class": result["failure_class"],
                                "diagnostic": result["diagnostic"],
                            }
                            for owner, result in zip(owner_ids, owner_results)
                        ],
                        "test_id": test_id,
                        "feature_categories": test_features.get(test_id, []),
                        "conversion_status": status,
                        "scope_classification": "in_scope",
                        "owner_decision": None,
                        "schema_validated": schema_validated,
                        "native_test_ids": native_ids,
                        "execution": "not_run",
                        "failure_class": failure_class,
                        "diagnostic": diagnostic,
                        "source_semantic_evidence": source_semantic_evidence,
                    })
        # The XML graph yields exactly the pinned corpus denominator.
        test_rows.sort(key=lambda row: (row["source_path"], row["test_id"]))
        if not definition_rows or not test_rows:
            raise ValueError(f"empty pinned corpus selection: definitions={len(definition_rows)} tests={len(test_rows)}")
        # Publish a machine-readable blocked view, while definitions.json and
        # tests.jsonl remain the authoritative complete ledgers.
        blocked_definitions = [row for row in definition_rows
                               if row["conversion_status"] == "blocked"]
        blocked_tests = [row for row in test_rows
                         if row["conversion_status"] == "blocked"]
        (temp / "blocked.json").write_text(json.dumps({
            "definitions": blocked_definitions,
            "tests": blocked_tests,
        }, indent=2) + "\n")
        (temp / "blocked-definitions.json").write_text(
            json.dumps(blocked_definitions, indent=2) + "\n")
        with (temp / "blocked-tests.jsonl").open("w") as stream:
            for row in blocked_tests:
                stream.write(json.dumps(row, sort_keys=True) + "\n")

        source_invalid_definitions = [row for row in definition_rows
                                      if row["conversion_status"] == "source_invalid"]
        source_invalid_tests = [row for row in test_rows
                                if row["conversion_status"] == "source_invalid"]
        (temp / "source-invalid-definitions.json").write_text(
            json.dumps(source_invalid_definitions, indent=2) + "\n")
        with (temp / "source-invalid-tests.jsonl").open("w") as stream:
            for row in source_invalid_tests:
                stream.write(json.dumps(row, sort_keys=True) + "\n")

        source_mappings = []
        for row in converted_rows:
            relative = Path("definitions") / slug(row["source_path"]) / slug(row["definition_id"])
            trace = json.loads((temp / relative / "source-trace.json").read_text())
            source_mappings.append({
                "source_path": row["source_path"],
                "source_sha256": row["source_sha256"],
                "definition_id": row["definition_id"],
                "source_test_ids": row["source_test_ids"],
                "native_test_ids": [entry["native_test"]
                                    for entry in trace.get("test_bindings", [])],
                "source_trace": (relative / "source-trace.json").as_posix(),
            })
        (temp / "source-mappings.json").write_text(
            json.dumps(source_mappings, indent=2) + "\n")
        validation = {
            "format": FORMAT,
            "source_commit": source_commit,
            "schema_family_sha256": snapshot.manifest()["aggregate_sha256"],
            "independent_schema_validation": "PASS" if converted_rows else "FAIL",
            "json_yaml_readback_equal": all(
                row["schema_validated"] for row in converted_rows),
            "schema_valid_yaml_documents": len(converted_rows),
            "blocked_artifacts": len(blocked_definitions),
            "source_invalid_artifacts": len(source_invalid_definitions),
            "source_invalid_schema_valid_yaml_documents": sum(
                row["schema_validated"] for row in source_invalid_definitions),
            "execution": "not_run",
            "expected_outcomes_derived": False,
            "embedded_archives_included": any("!" in str(row["source_path"]) for row in source_graph),
            "owner_exclusions": {},
            "test_ledger_reconciliation": {
                "source_universe": "all XML Tests, including helper/unowned Tests",
                "complete": True,
                "identity": "(source_path, test_id)",
                "ownership": "transitive extend_definition closure",
            },
        }
        (temp / "validation.json").write_text(json.dumps(validation, indent=2) + "\n")
        feature_inventory = {
            "policy": "source-graph labels only; converter diagnostics remain authoritative; no semantics inferred",
            "blocked_definition_feature_counts": dict(sorted(Counter(
                feature for row in blocked_definitions for feature in row["feature_categories"]
            ).items())),
            "blocked_test_feature_counts": dict(sorted(Counter(
                feature for row in blocked_tests for feature in row["feature_categories"]
            ).items())),
            "source_invalid_definition_feature_counts": dict(sorted(Counter(
                feature for row in source_invalid_definitions for feature in row["feature_categories"]
            ).items())),
            "source_invalid_test_feature_counts": dict(sorted(Counter(
                feature for row in source_invalid_tests for feature in row["feature_categories"]
            ).items())),
        }
        (temp / "feature-inventory.json").write_text(
            json.dumps(feature_inventory, indent=2) + "\n")
        notices = Path(__file__).resolve().parents[1] / "docs/evidence/issue37-variables/NOTICES.txt"
        if notices.is_file():
            shutil.copyfile(notices, temp / "NOTICES.txt")
        else:
            (temp / "NOTICES.txt").write_text(
                "Derivative native conversion review artifacts from pinned SCAP 1.4 OVAL content; "
                "original XML is unchanged.\n")
        converted_test_count = sum(row["conversion_status"] == "CONVERTED_UNVERIFIED"
                                  for row in test_rows)
        source_invalid_definition_count = len(source_invalid_definitions)
        source_invalid_test_count = len(source_invalid_tests)
        blocked_definition_count = sum(row["conversion_status"] == "blocked"
                                      for row in definition_rows)
        excluded_definition_count = sum(row["conversion_status"] == "intentionally_excluded"
                                       for row in definition_rows)
        excluded_test_count = sum(row["conversion_status"] == "intentionally_excluded"
                                  for row in test_rows)
        (temp / "README.md").write_text(
            "# Pinned Self-Assertion conversion\n\n"
            f"Production CLI conversion of the pinned `{', '.join(families)}` corpus at `{source_commit}`. "
            "The complete ledgers preserve every source Definition and Test; blocked "
            "entries retain the exact converter diagnostic.\n\n"
            f"- Definitions: {len(definition_rows)} ({len(converted_rows)} converted, "
            f"{source_invalid_definition_count} source-invalid, {blocked_definition_count} blocked, "
            f"{excluded_definition_count} excluded)\n"
            f"- Tests: {len(test_rows)} ({converted_test_count} converted, "
            f"{source_invalid_test_count} source-invalid, {len(blocked_tests)} blocked, "
            f"{excluded_test_count} excluded)\n"
            "- Generated native documents are schema-valid; source-invalid rows remain explicit and are not source-parity successes.\n"
            "- No expected outcomes, collected Items, or execution results are derived.\n"
            "- See `source-mappings.json`, `feature-inventory.json`, `definitions.json`, `tests.jsonl`, and the blocked/source-invalid ledgers.\n"
        )
        (temp / "definitions.json").write_text(json.dumps(definition_rows, indent=2) + "\n")
        with (temp / "tests.jsonl").open("w") as stream:
            for row in test_rows:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        legacy_agnostic = families == ("agnostic",)
        manifest = {
            "format": ("scap-ng-tools-self-assertion-agnostic-conversion/1"
                       if legacy_agnostic else FORMAT),
            "source_repository": "OVAL-Community/SCAP-Self-Assertion",
            "source_commit": source_commit,
            ("source_root" if legacy_agnostic else "source_roots"):
                (str(CORPUS_ROOT / "agnostic") if legacy_agnostic else
                 [str(CORPUS_ROOT / family) for family in families]),
            "schema": snapshot.manifest(),
            "converter": "scap_ng_tools.converter.direct04",
            "conversion_policy": "production CLI only; no manual native rewrites or expected outcomes",
            "feature_inventory": feature_inventory,
            "source_inventory": {
                "embedded_archives_included": any("!" in str(row["source_path"]) for row in source_graph),
                "owner_exclusions": {},
                "test_ledger_reconciliation": {
                    "source_universe": "all XML Tests, including helper/unowned Tests",
                    "complete": True,
                    "identity": "(source_path, test_id)",
                    "ownership": "transitive extend_definition closure",
                },
            },
            "summary": {
                "definitions": len(definition_rows),
                "tests": len(test_rows),
                "converted_definitions": len(converted_rows),
                "blocked_definitions": blocked_definition_count,
                "source_invalid_definitions": source_invalid_definition_count,
                "excluded_definitions": excluded_definition_count,
                "schema_valid_yaml_documents": len(converted_rows),
                "source_invalid_schema_valid_yaml_documents": sum(
                    row["schema_validated"] for row in source_invalid_definitions),
                "converted_tests": converted_test_count,
                "blocked_tests": len(blocked_tests),
                "source_invalid_tests": source_invalid_test_count,
                "excluded_tests": excluded_test_count,
                "test_ledger_reconciled": len(test_rows),
                "execution": "not_run",
            },
        }
        # Integrity covers every published file except manifest.json itself;
        # the manifest can therefore be checked without a recursive digest.
        manifest["artifacts"] = {
            path.relative_to(temp).as_posix(): {
                "sha256": digest(path.read_bytes()), "bytes": path.stat().st_size
            }
            for path in sorted(temp.rglob("*"))
            if path.is_file() and path.name != "manifest.json"
        }
        (temp / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        temp.rename(output)
        return manifest
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--family", action="append", choices=FAMILIES,
                        help="OVAL content family; repeat for a subset (default: ALL 12 XML families)")
    parser.add_argument("--python", default=os.environ.get("PYTHON", os.sys.executable))
    args = parser.parse_args()
    families = tuple(dict.fromkeys(args.family or FAMILIES))
    result = convert(corpus=args.corpus, schema_root=args.schema_root,
                     source_commit=args.source_commit, output=args.output,
                     python=args.python, families=families)
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
