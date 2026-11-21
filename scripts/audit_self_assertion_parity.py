#!/usr/bin/env python3
"""Independent, fail-closed source-accounting gate for pinned OVAL Test Content.

The converter is not an oracle. This tool reads original XML and a separately
generated converter package; it never translates OVAL into SCAP-NG or invents
scanner outcomes. The report distinguishes identity/cardinality checks from
unproved runtime equivalence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import struct
import json
import re
import subprocess
import tarfile
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from zipfile import ZipFile

PREFIX = "SCAP_1.4/OVAL_Test_Content/"
HISTORICAL_PIN = "e3538595c5083b9c34d937a81d319234df9bbfaa"
# Active corrected upstream source. Historical receipts remain explicitly
# pinned to HISTORICAL_PIN and are never relabeled by this default.
PIN = "d91e6ba33841e3202dc27d3e0d469a7abd939b16"
MAX_XML = 8 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
CHECK = {"all": "every", "at least one": "one_or_more",
         "only one": "exactly_one", "none satisfy": "none"}
EXISTENCE = {"at_least_one_exists": "one_or_more",
             "only_one_exists": "exactly_one", "none_exist": "none",
             "any_exist": "zero_or_more", "all_exist": "one_or_more"}

def tag(element):
    return element.tag.rsplit("}", 1)[-1]

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def parse_oval(raw, path):
    if len(raw) > MAX_XML or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError(f"{path}: source XML exceeds limit or contains DTD/entities")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"{path}: malformed XML: {exc}") from exc
    if tag(root) != "oval_definitions":
        raise ValueError(f"{path}: not an OVAL Definitions document")
    groups = {tag(child): child for child in root}
    generator = groups.get("generator")
    schema_version = (generator.findtext(
        "{http://oval.mitre.org/XMLSchema/oval-common-5}schema_version")
        if generator is not None else None)
    defs = {}
    tests = {}
    variables = {}
    for group_name, output in (("definitions", defs), ("tests", tests),
                               ("variables", variables)):
        for child in groups.get(group_name, ()):
            ident = child.get("id")
            if not ident:
                continue
            if ident in output:
                raise ValueError(f"{path}: duplicate {group_name} ID {ident}")
            output[ident] = child
    features = Counter()
    for variable in variables.values():
        for child in variable.iter():
            name = tag(child)
            if name in {"concat", "count", "merge", "unique", "regex_capture",
                        "arithmetic", "begin", "end", "escape_regex",
                        "glob_to_regex", "split", "substring",
                        "time_difference", "object_component",
                        "variable_component", "literal_component"}:
                features[name] += 1
    lookup = {node.get("id"): node for node in root.iter() if node.get("id")}
    direct_refs = {}
    for ident, definition in defs.items():
        direct_refs[ident] = list(dict.fromkeys(
            node.get("test_ref") for node in definition.iter()
            if tag(node) == "criterion" and node.get("test_ref")))
    refs, visiting, visited = {}, set(), {}
    def definition_tests(ident):
        if ident in visiting:
            raise ValueError(f"{path}: cyclic source extend_definition: {ident}")
        if ident in visited:
            return list(visited[ident])
        if ident not in defs:
            raise ValueError(f"{path}: unresolved source extended Definition: {ident}")
        visiting.add(ident)
        result = list(direct_refs[ident])
        for child in defs[ident].iter():
            if tag(child) != "extend_definition":
                continue
            target = child.get("definition_ref")
            if not target:
                raise ValueError(f"{path}: missing source extended Definition reference")
            for test_id in definition_tests(target):
                if test_id not in result:
                    result.append(test_id)
        visiting.remove(ident)
        visited[ident] = tuple(result)
        return result
    for ident in defs:
        refs[ident] = definition_tests(ident)
    return {"path": path, "sha256": digest(raw),
            "source_oval_schema_version": schema_version,
            "definitions": defs, "tests": tests, "variables": variables,
            "nodes": lookup,
            "test_refs": refs,
            "features": dict(sorted(features.items()))}

def verify_source_checkout(source_root, expected_commit=PIN):
    # Verify the exact upstream commit AND a clean Test Content subtree.
    # The converter's declaration of source_commit is not independent proof.
    checkout = source_root.resolve().parents[1]
    for args in (("rev-parse", "HEAD"),
                 ("status", "--porcelain", "--", "SCAP_1.4/OVAL_Test_Content")):
        command = ["git", "-C", str(checkout), *args]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, timeout=15)
        if result.returncode:
            raise ValueError("cannot verify upstream source Git checkout")
        if args[0] == "rev-parse" and result.stdout.strip() != expected_commit:
            raise ValueError("upstream source checkout is not the approved commit")
        if args[0] == "status" and result.stdout.strip():
            raise ValueError("upstream source Test Content has local modifications")
    return True

def sources(source_root):
    if not source_root.is_dir():
        raise ValueError(f"source directory does not exist: {source_root}")
    records = {}
    for path in sorted(source_root.rglob("*.xml")):
        if path.is_symlink():
            raise ValueError(f"source XML is symlink: {path}")
        relative = PREFIX + path.relative_to(source_root).as_posix()
        records[relative] = parse_oval(path.read_bytes(), relative)
    # Treat every archive as part of the inventory, not just the agnostic
    # ZIP. Only OVAL Definition documents become native conversion inputs;
    # unrelated fixture XML remains an explicit classification item.
    archive_inventory = []
    for archive in sorted(source_root.rglob("*.zip")):
        inspected = {"path": PREFIX + archive.relative_to(source_root).as_posix(),
                     "xml_members": 0, "oval_members": 0, "other_members": 0}
        with ZipFile(archive) as package:
            for member in package.infolist():
                if member.is_dir():
                    continue
                inspected["other_members"] += 1
                if not member.filename.lower().endswith(".xml"):
                    continue
                inspected["xml_members"] += 1
                if member.file_size > MAX_XML or member.compress_size > MAX_ARCHIVE:
                    raise ValueError(f"archive member exceeds limit: {member.filename}")
                raw = package.read(member)
                # Parse every XML member; a prefixed root or XML declaration
                # must not make an OVAL Definition disappear from accounting.
                try:
                    parsed = ET.fromstring(raw)
                except ET.ParseError:
                    inspected["invalid_fixture_xml"] = inspected.get("invalid_fixture_xml", 0) + 1
                    continue
                if tag(parsed) != "oval_definitions":
                    continue
                relative = inspected["path"] + "!" + member.filename
                if relative in records:
                    raise ValueError("duplicate embedded XML path: " + relative)
                records[relative] = parse_oval(raw, relative)
                inspected["oval_members"] += 1
        archive_inventory.append(inspected)
    for archive in sorted(source_root.rglob("*.tarz")):
        inspected = {"path": PREFIX + archive.relative_to(source_root).as_posix(),
                     "xml_members": 0, "oval_members": 0, "other_members": 0}
        try:
            with tarfile.open(archive, mode="r:*") as package:
                for member in package.getmembers():
                    if not member.isfile():
                        continue
                    inspected["other_members"] += 1
                    if not member.name.lower().endswith(".xml"):
                        continue
                    inspected["xml_members"] += 1
                    if member.size > MAX_XML:
                        raise ValueError("tar member exceeds limit: " + member.name)
                    extracted = package.extractfile(member)
                    if extracted is None:
                        raise ValueError("unreadable tar member: " + member.name)
                    raw = extracted.read(MAX_XML + 1)
                    if len(raw) > MAX_XML:
                        raise ValueError("tar XML member exceeds limit: " + member.name)
                    try:
                        parsed = ET.fromstring(raw)
                    except ET.ParseError:
                        inspected["invalid_fixture_xml"] = inspected.get("invalid_fixture_xml", 0) + 1
                        continue
                    if tag(parsed) != "oval_definitions":
                        continue
                    relative = inspected["path"] + "!" + member.name
                    records[relative] = parse_oval(raw, relative)
                    inspected["oval_members"] += 1
        except tarfile.TarError as exc:
            inspected["status"] = "unclassified_nonzip_archive"
            inspected["reason"] = str(exc)[:200]
        archive_inventory.append(inspected)
    return records, archive_inventory

def source_tree_summary(records):
    dirs = defaultdict(lambda: {"xml": 0, "definitions": 0, "tests": 0})
    duplicate_definitions = []
    definition_paths = {}
    test_paths = {}
    conflicts = []
    features = Counter()
    for path, record in sorted(records.items()):
        family = path[len(PREFIX):].split("/", 1)[0]
        dirs[family]["xml"] += 1
        dirs[family]["definitions"] += len(record["definitions"])
        dirs[family]["tests"] += len(record["tests"])
        features.update(record["features"])
        # Independent OVAL XML files reuse Definition/Test ID strings.
        # The canonical source identity is (relative source file, XML ID).
        # Deduplicating across files silently erased 47 source Definitions.
        for ident in record["definitions"]:
            definition_paths[(path, ident)] = path
        for ident in record["tests"]:
            test_paths[(path, ident)] = path
    return ({"xml_documents": len(records), "definitions": len(definition_paths),
             "tests": len(test_paths), "by_family": dict(sorted(dirs.items())),
             "source_features": dict(sorted(features.items())),
             "duplicate_definitions": duplicate_definitions},
            definition_paths, conflicts)

def read_pack(pack, expected_commit=PIN):
    definitions_path = pack / "definitions.json"
    if not definitions_path.is_file():
        raise ValueError(f"converter package missing definitions.json: {pack}")
    rows = json.loads(definitions_path.read_text(encoding="utf-8"))
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("definitions.json must be an array")
    if manifest.get("source_commit") != expected_commit:
        raise ValueError("converter package uses a different original source commit")
    return rows, manifest

def read_test_ledger(pack):
    ledger_path = pack / "tests.jsonl"
    if not ledger_path.is_file():
        raise ValueError("converter package missing tests.jsonl")
    rows = []
    seen = set()
    for line_number, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"tests.jsonl line {line_number} is invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"tests.jsonl line {line_number} is not an object")
        key = (row.get("source_path"), row.get("test_id"))
        if (not isinstance(key[0], str) or not isinstance(key[1], str) or
                not key[0] or not key[1] or key in seen):
            raise ValueError(f"tests.jsonl duplicate/invalid source Test at line {line_number}")
        seen.add(key)
        rows.append(row)
    return rows

def exclusion_problem(path, ident, row, kind):
    return {"type": "exclusion_without_owner_approval",
            "kind": kind, "source": path,
            ("definition" if kind == "definition" else "test"): ident,
            "reason": "all pinned OVAL platform families are in authoring scope; exclusions require explicit owner approval"}

def validate_exclusion_authorization(path, ident, row, kind, problems):
    """Reject exclusions unless a separately recorded owner decision exists.

    Platform families are not implicitly excluded. In particular, the old AIX
    issue-56 exception is historical and must not survive into the current
    all-platform source-to-native ledger.
    """
    status = row.get("conversion_status")
    owner = row.get("owner_decision")
    scope = row.get("scope_classification")
    if (status in ("excluded", "intentionally_excluded") or owner is not None or
            (scope is not None and scope != "in_scope")):
        problems.append(exclusion_problem(path, ident, row, kind))


def slug(value):
    return value.replace(":", "_").replace("/", "_")

def compare_variable_test_binding(source, source_test, native_test, trace):
    # An OVAL independent variable_test selects its Variable indirectly
    # through a variable_object. Native variable.value selects it directly.
    if tag(source_test) != "variable_test":
        return
    objects = [node.get("object_ref") for node in source_test.iter()
               if tag(node) == "object" and node.get("object_ref")]
    if len(objects) != 1:
        raise ValueError("original variable_test has unqualified Object references")
    source_object = source["nodes"].get(objects[0])
    if source_object is None or tag(source_object) != "variable_object":
        raise ValueError("original variable_test Object is not a variable_object")
    refs = [(node.text or "").strip() for node in source_object.iter()
            if tag(node) == "var_ref" and (node.text or "").strip()]
    mapping = {entry["source_id"]: entry["native_id"]
               for entry in trace.get("native_identities", [])
               if entry.get("kind") == "variable"}
    if len(refs) == 1:
        expected = mapping.get(refs[0])
    else:
        expected = next((item.get("native_id") for item in
                         trace.get("native_synthetic_variables", [])
                         if item.get("source_object") == objects[0]), None)
    if not expected or native_test.get("capability") != "variable.value":
        raise ValueError("missing Variable Object-to-native capability mapping")
    if native_test.get("variable") != expected:
        raise ValueError("original variable_object Test binding differs")

def reachable_source_tests(source, definition_id):
    """Reachability across recursive extend_definition, scoped to one XML.

    Definition/test IDs are only unique inside their source file; never combine
    graphs from different XML files sharing an OVAL ID.
    """
    tests = set()
    visiting = set()
    visited = set()
    def walk(ident):
        if ident in visiting:
            raise ValueError("cyclic source extend_definition: " + ident)
        if ident in visited:
            return
        definition = source["definitions"].get(ident)
        if definition is None:
            raise ValueError("unresolved original extended Definition: " + ident)
        visiting.add(ident)
        for item in definition.iter():
            if tag(item) == "criterion":
                test_id = item.get("test_ref")
                if not test_id or test_id not in source["tests"]:
                    raise ValueError("unknown source Test in criteria")
                tests.add(test_id)
            elif tag(item) == "extend_definition":
                target = item.get("definition_ref")
                if not target:
                    raise ValueError("missing source extended Definition reference")
                walk(target)
        visiting.remove(ident)
        visited.add(ident)
    walk(definition_id)
    return tests

def normalize_source_evaluate(source, definition_id):
    # Evaluate the original criteria AST recursively, including referenced
    # Definitions; a native Assessment inlines their Test branches.
    active = set()
    def definition_tree(ident):
        if ident in active:
            raise ValueError("cyclic source extend_definition")
        definition = source["definitions"].get(ident)
        if definition is None:
            raise ValueError("source extended Definition not found: " + str(ident))
        active.add(ident)
        nodes = [c for c in definition if tag(c) == "criteria"]
        if len(nodes) != 1:
            raise ValueError("source Definition does not have one criteria node")
        tree = parse(nodes[0])
        active.remove(ident)
        return tree
    def parse(node):
        name = tag(node)
        if name == "criterion":
            ident = node.get("test_ref")
            if ident not in source["tests"]:
                raise ValueError("unresolved source criterion Test")
            result = ("test", ident)
        elif name == "extend_definition":
            result = definition_tree(node.get("definition_ref"))
        elif name == "criteria":
            children = tuple(parse(child) for child in node
                             if tag(child) in ("criteria", "criterion", "extend_definition"))
            op = (node.get("operator") or "AND").lower()
            if op not in ("and", "or", "xor", "one") or not children:
                raise ValueError("unsupported source criteria Boolean operator/arity")
            result = children[0] if len(children) == 1 and op in ("and", "or") else (op, children)
        else:
            raise ValueError("unrecognized criteria node " + name)
        return ("not", result) if node.get("negate", "false").lower() == "true" else result
    return definition_tree(definition_id)

def _expanded_group_source(node, expanded_native_to_source, expanded_source_checks):
    """Return a source Test ID when *node* is one explicit Set expansion."""
    if not isinstance(node, dict) or len(node) != 1:
        return None
    op, value = next(iter(node.items()))
    if op == "test" and value in expanded_native_to_source:
        return expanded_native_to_source[value]
    if op == "not" and isinstance(value, dict):
        # ``none satisfy`` is lowered as NOT(OR(child Tests)); only a NOT
        # directly around that logical child group owns this NOT. A second
        # nested NOT is the authored Definition criterion negate.
        child_op = next(iter(value), None)
        if child_op not in ("and", "or", "xor", "one"):
            return None
        source_id = _expanded_group_source(
            value, expanded_native_to_source, expanded_source_checks)
        return (source_id if source_id and
                expanded_source_checks.get(source_id) == "none satisfy" else None)
    if op in ("and", "or", "xor", "one") and isinstance(value, list) and len(value) > 1:
        source_ids = {_expanded_group_source(
            item, expanded_native_to_source, expanded_source_checks)
                      for item in value}
        if None not in source_ids and len(source_ids) == 1:
            return next(iter(source_ids))
    return None


def normalize_native_evaluate(node, native_to_source, expanded_native_to_source=None,
                              expanded_source_checks=None):
    if not isinstance(node, dict) or len(node) != 1:
        raise ValueError("malformed native Evaluate")
    expanded_native_to_source = expanded_native_to_source or {}
    expanded_source_checks = expanded_source_checks or {}
    collapsed = _expanded_group_source(
        node, expanded_native_to_source, expanded_source_checks)
    if collapsed is not None:
        return ("test", collapsed)
    op, val = next(iter(node.items()))
    if op == "test":
        if val not in native_to_source:
            raise ValueError("unmapped native Test " + str(val))
        return ("test", native_to_source[val])
    if op == "not":
        return ("not", normalize_native_evaluate(
            val, native_to_source, expanded_native_to_source, expanded_source_checks))
    if op in ("and", "or", "xor", "one") and isinstance(val, list):
        children = tuple(normalize_native_evaluate(
            v, native_to_source, expanded_native_to_source, expanded_source_checks)
            for v in val)
        return children[0] if len(children) == 1 and op in ("and", "or") else (op, children)
    raise ValueError("unknown native Evaluate operator " + str(op))

def source_literal(value, datatype):
    if datatype in {
        "string", "binary", "version", "evr_string", "debian_evr_string",
        "fileset_revision", "ios_version", "ipv4_address", "ipv6_address",
    }:
        # These OVAL domains retain their source lexical value in the native
        # typed literal; no lexical cast is performed here.
        return value
    if datatype in ("int", "integer"):
        return int(value.strip(), 10)
    if datatype == "boolean":
        if value.strip().lower() not in ("true", "false", "1", "0"):
            raise ValueError("unrecognized original boolean value")
        return value.strip().lower() in ("true", "1")
    if datatype == "float":
        # The source converter's float contract is binary32.  This independent
        # receipt parser performs the final IEEE-754 rounding only for value
        # comparison; it never treats a string as numeric elsewhere.
        try:
            return struct.unpack(">f", struct.pack(">f", float(value.strip())))[0]
        except (OverflowError, ValueError) as error:
            raise ValueError("invalid original float value") from error
    raise ValueError("unqualified original Variable datatype: " + str(datatype))

def audit_source_set_filter_retention(source, selected_tests, native, synthetic=(), expanded=()):
    """Fail closed when the converter silently drops source Set/Filter logic.

    Restores 0.3 source-graph coverage for OVAL Object Sets and Filter States.
    This is a necessary structural retention gate, not an equivalence proof:
    nested Set order and filters' Item/status behavior require independent
    source-vs-native execution or a proven semantic lowering.
    """
    original = {"union": 0, "intersection": 0, "difference": 0,
                "include": 0, "exclude": 0}
    pending = list(selected_tests)
    visited = set()
    while pending:
        ident = pending.pop()
        if ident in visited:
            continue
        visited.add(ident)
        node = source["nodes"].get(ident)
        if node is None:
            raise ValueError("unresolved original source graph reference: " + ident)
        for child in node.iter():
            local = tag(child)
            if local == "set":
                operation = {"UNION": "union", "INTERSECTION": "intersection",
                             "COMPLEMENT": "difference"}.get(
                                 child.get("set_operator", "UNION"))
                if operation is None:
                    raise ValueError("unsupported original Set operator")
                original[operation] += 1
            elif local == "filter":
                action = child.get("action", "exclude")
                if action not in ("include", "exclude"):
                    raise ValueError("unsupported original Filter action")
                original[action] += 1
            for attr, target in child.attrib.items():
                if attr.endswith("_ref") and target in source["nodes"]:
                    pending.append(target)
            if local in ("object_reference", "filter", "var_ref"):
                target = (child.text or "").strip()
                if target:
                    if target not in source["nodes"]:
                        raise ValueError("unresolved original source text reference: " + target)
                    pending.append(target)

    if not any(original.values()):
        return
    observed = {key: 0 for key in original}
    for item in synthetic:
        operation = {"UNION": "union", "INTERSECTION": "intersection",
                     "COMPLEMENT": "difference"}.get(item.get("set_operator", "UNION"))
        if operation:
            observed[operation] += 1
    # A finite Variable Object UNION may be lowered into child Tests plus an
    # Evaluate expression instead of a native Set node. The expansion trace is
    # the explicit retained source boundary for that representation.
    expanded_sources = {item.get("source_test") for item in expanded
                        if isinstance(item, dict) and item.get("source_test")}
    observed["union"] += len(expanded_sources)
    stack = [native]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            set_value = item.get("set")
            if isinstance(set_value, dict):
                op = set_value.get("operator")
                if op in ("union", "intersection", "difference"):
                    observed[op] += 1
            filters = item.get("filters")
            if isinstance(filters, list):
                for filt in filters:
                    if isinstance(filt, dict):
                        for action in ("include", "exclude"):
                            if action in filt:
                                observed[action] += 1
            stack.extend(item.values())
    missing = sorted(key for key, count in original.items()
                     if count and not observed[key])
    if missing:
        raise ValueError(
            "original OVAL Set/Filter source semantics missing from native "
            "Assessment: " + ", ".join(missing))

def required_variable_declarations(source, tests):
    # Only declarations reachable from this Definition's Tests are required.
    # One XML file may contain multiple independent Definitions; unrelated
    # Variables must not be falsely treated as omitted from each conversion.
    pending = list(tests)
    seen = set()
    required = set()
    while pending:
        ident = pending.pop()
        if ident in seen:
            continue
        seen.add(ident)
        if ident in source["variables"]:
            required.add(ident)
        node = source["nodes"].get(ident)
        if node is None:
            continue
        for child in node.iter():
            for key, value in child.attrib.items():
                if key.endswith("_ref") and value in source["nodes"]:
                    pending.append(value)
            if tag(child) in ("var_ref", "var_ref_text"):
                ref = (child.text or "").strip()
                if ref in source["nodes"]:
                    pending.append(ref)
    return required

SOURCE_TO_NATIVE_TYPES = {
    "int": "integer", "integer": "integer", "evr_string": "rpm_evr",
    "debian_evr_string": "debian_evr", "ipv4_address": "ipv4",
    "ipv6_address": "ipv6", "string": "string", "boolean": "boolean",
    "float": "float", "binary": "binary", "version": "version",
    "fileset_revision": "fileset_revision", "ios_version": "ios_version",
}

NATIVE_LITERAL_TYPES = {
    "string", "boolean", "integer", "float", "binary", "version", "ipv4",
    "ipv6", "rpm_evr", "debian_evr", "fileset_revision", "ios_version",
}


def load_field_datatypes(schema_root):
    """Load the pinned schema capability field domains for type inference.

    A native ``values`` expression deliberately carries no declaration-level
    datatype.  Its type is the canonical mapping type of the selected Item
    field.  This loader is only an independent parity aid: it never creates a
    cast and it refuses fields whose reviewed mapping admits multiple types.
    """
    if schema_root is None:
        return {}
    root = Path(schema_root)
    # Pinned041SchemaSnapshot accepts either a canonical checkout root or its
    # flat schema directory. Keep this independent parity aid on the same
    # path contract; otherwise every collected-field Variable appears
    # unresolved when callers pass a canonical checkout root.
    if not (root / "capability-mappings").is_dir() and (root / "schema").is_dir():
        root = root / "schema"
    directory = root / "capability-mappings" / "supported"
    result = {}
    for path in sorted(directory.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        capability = document.get("capability")
        fields = document.get("native", {}).get("field_datatypes", {})
        if not isinstance(capability, str) or not isinstance(fields, dict):
            continue
        for field, datatypes in fields.items():
            if isinstance(field, str) and isinstance(datatypes, list):
                result[(capability, field)] = tuple(datatypes)
    return result


def _native_scalar_type(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    raise ValueError("native Variable literal is not scalar")


def _native_expression_type(expression, known, field_datatypes=None, native=None):
    """Derive a native Variable type without trusting a declaration tag.

    SCAP-NG 0.4.1 intentionally removed declaration-level ``datatype``.  This
    independent parity check therefore derives the type from the expression,
    mirroring the closed operation result domains while refusing unresolved
    collected-field domains rather than guessing a cast.
    """
    if not isinstance(expression, dict) or len(expression) != 1:
        raise ValueError("native Variable expression is malformed")
    operation, value = next(iter(expression.items()))
    if operation == "literal":
        if isinstance(value, dict):
            datatype = value.get("datatype")
            if datatype not in NATIVE_LITERAL_TYPES:
                raise ValueError("native typed literal datatype is unresolved")
            return datatype
        values = value if isinstance(value, list) else [value]
        if not values:
            raise ValueError("native empty literal datatype is unresolved")
        types = {_native_scalar_type(item) for item in values}
        if len(types) != 1:
            raise ValueError("native literal has mixed datatypes")
        return next(iter(types))
    if operation == "variable":
        name = value
        if name not in known:
            raise ValueError("native Variable reference is unresolved: " + str(name))
        return known[name]
    if operation == "values":
        payload = value if isinstance(value, dict) else {}
        field = payload.get("field")
        selected = payload.get("object")
        if isinstance(selected, str) and isinstance(native, dict):
            selected = native.get("shared_objects", {}).get(selected)
        capability = selected.get("capability") if isinstance(selected, dict) else None
        datatypes = ((field_datatypes or {}).get((capability, field), ())
                     if isinstance(field, str) else ())
        if len(datatypes) != 1 or datatypes[0] not in NATIVE_LITERAL_TYPES:
            raise ValueError("native collected-field datatype is unresolved")
        return datatypes[0]
    if operation == "count":
        _native_expression_type(value, known, field_datatypes, native)
        return "integer"
    if operation in {"split", "substring", "begin", "end", "concat", "merge", "regex_capture"}:
        payloads = []
        if operation in {"split", "substring", "begin", "end", "regex_capture"}:
            payloads = [value.get("value")] if isinstance(value, dict) else []
        elif operation == "concat":
            payloads = value if isinstance(value, list) else []
        else:
            payloads = value.get("values", []) if isinstance(value, dict) else []
            payloads = payloads if isinstance(payloads, list) else [payloads]
        if not payloads:
            raise ValueError("native text operation has no input")
        for payload in payloads:
            _native_expression_type(payload, known, field_datatypes, native)
        return "string"
    if operation == "time_difference":
        return "integer"
    if operation == "arithmetic":
        operands = value.get("values", []) if isinstance(value, dict) else []
        if not isinstance(operands, list) or len(operands) < 2:
            raise ValueError("native arithmetic operands are malformed")
        types = {_native_expression_type(item, known, field_datatypes, native) for item in operands}
        if not types <= {"integer", "float"}:
            raise ValueError("native arithmetic datatype is not numeric")
        return "float" if "float" in types else "integer"
    if operation == "unique":
        operands = value if isinstance(value, list) else [value]
        if not operands:
            raise ValueError("native unique has no input")
        types = {_native_expression_type(item, known, field_datatypes, native) for item in operands}
        if len(types) != 1:
            raise ValueError("native unique datatype is ambiguous")
        return next(iter(types))
    raise ValueError("native Variable operation is unresolved: " + operation)


def _native_variable_types(native_vars, field_datatypes=None, native=None):
    known = {}
    pending = dict(native_vars)
    while pending:
        progressed = False
        for name, declaration in list(pending.items()):
            try:
                known[name] = _native_expression_type(
                    declaration.get("expression"), known, field_datatypes, native)
            except ValueError as error:
                if "reference is unresolved" in str(error):
                    continue
                raise
            del pending[name]
            progressed = True
        if not progressed:
            name = next(iter(pending))
            _native_expression_type(pending[name].get("expression"), known, field_datatypes, native)
    return known


def _source_expression_type(node, source):
    """Derive OVAL function output type for source-invalid diagnostics."""
    operation = tag(node)
    if operation == "literal_component":
        return SOURCE_TO_NATIVE_TYPES.get(node.get("datatype", "string"),
                                         node.get("datatype", "string"))
    if operation == "variable_component":
        variable = source["variables"].get(node.get("var_ref"))
        return (SOURCE_TO_NATIVE_TYPES.get(variable.get("datatype"), variable.get("datatype"))
                if variable is not None else None)
    if operation == "object_component":
        return None
    children = [child for child in node if isinstance(child.tag, str)]
    if operation == "time_difference":
        return "integer"
    if operation == "arithmetic":
        types = {_source_expression_type(child, source) for child in children}
        if types <= {"integer", "float"} and types:
            return "float" if "float" in types else "integer"
        return None
    if operation in {"concat", "split", "substring", "begin", "end", "regex_capture",
                     "merge", "unique", "glob_to_regex", "escape_regex"}:
        return "string"
    if operation == "count":
        return "integer"
    return None


_REGEX_META = set('.^$*+?{}[]\\|()')


def _escape_regex_literal(value):
    return ''.join('\\' + character if character in _REGEX_META else character
                   for character in value)


def _glob_to_regex_literal(pattern, *, glob_noescape=False):
    result = ['^']
    segment_start = True
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == '/':
            result.append('/')
            segment_start = True
            index += 1
            continue
        if segment_start:
            escaped_dot = (character == '\\' and index + 1 < len(pattern)
                           and pattern[index + 1] == '.')
            if character != '.' and not escaped_dot:
                result.append('(?=[^\\.])')
            segment_start = False
        if character == '\\' and not glob_noescape:
            index += 1
            if index == len(pattern):
                result.append('\\\\')
                break
            result.append(_escape_regex_literal(pattern[index]))
            index += 1
            continue
        if character == '\\' and glob_noescape:
            result.append('\\\\')
            index += 1
            continue
        if character == '*':
            result.append('[^/]*')
            index += 1
            continue
        if character == '?':
            result.append('[^/]')
            index += 1
            continue
        if character == '[':
            nested = 0
            cursor = index + 1
            while cursor < len(pattern):
                if pattern[cursor] == '[':
                    nested += 1
                elif pattern[cursor] == ']':
                    if nested:
                        nested -= 1
                    else:
                        break
                cursor += 1
            if cursor >= len(pattern):
                raise ValueError('invalid source glob_to_regex bracket expression')
            result.append(pattern[index:cursor + 1])
            index = cursor + 1
            continue
        result.append(('\\' + character) if character in _REGEX_META else character)
        index += 1
    result.append('$')
    return ''.join(result)


def _source_literal_function_values(source_node, source):
    children = [child for child in source_node if isinstance(child.tag, str)]
    if len(children) != 1:
        raise ValueError('source literal function arity differs')
    child = children[0]
    if tag(child) == 'literal_component':
        if child.get('datatype', 'string') != 'string':
            raise ValueError('source literal function datatype differs')
        return [child.text or '']
    if tag(child) == 'variable_component':
        variable = source['variables'].get(child.get('var_ref'))
        if (variable is None or tag(variable) != 'constant_variable' or
                variable.get('datatype') != 'string'):
            raise ValueError('source literal function operand is dynamic')
        return [node.text or '' for node in variable if tag(node) == 'value']
    raise ValueError('source literal function operand is dynamic')


def _native_literal_payload(expression):
    if not isinstance(expression, dict) or set(expression) != {"literal"}:
        return None, None
    value = expression["literal"]
    if isinstance(value, dict):
        return value.get("datatype"), value.get("value")
    return None, value


def _source_expression_matches(source_node, native_expression, source_to_native,
                               source=None, inlined=None):
    """Check source function options, order and operands exactly."""
    inlined = set() if inlined is None else inlined
    operation = tag(source_node)
    if operation in {"begin", "end"}:
        if not isinstance(native_expression, dict) or set(native_expression) != {operation}:
            return False
        payload = native_expression[operation]
        if payload.get("character") != source_node.get("character"):
            return False
        children = [child for child in source_node if isinstance(child.tag, str)]
        return (len(children) == 1 and
                _source_expression_matches(children[0], payload.get("value"),
                                           source_to_native, source, inlined))
    if operation in {"arithmetic", "concat", "split", "substring", "regex_capture"}:
        if not isinstance(native_expression, dict) or set(native_expression) != {operation}:
            return False
        payload = native_expression[operation]
        children = [child for child in source_node if isinstance(child.tag, str)]
        if operation == "arithmetic":
            if payload.get("arithmetic_operation") != source_node.get("arithmetic_operation"):
                return False
            operands = payload.get("values")
            return (isinstance(operands, list) and len(operands) == len(children) and
                    all(_source_expression_matches(child, value, source_to_native,
                                                    source, inlined)
                        for child, value in zip(children, operands)))
        if operation == "concat":
            return (isinstance(payload, list) and len(payload) == len(children) and
                    all(_source_expression_matches(child, value, source_to_native,
                                                   source, inlined)
                        for child, value in zip(children, payload)))
        if operation == "regex_capture":
            if payload.get("pattern") != source_node.get("pattern") or len(children) != 1:
                return False
            return _source_expression_matches(children[0], payload.get("value"),
                                              source_to_native, source, inlined)
        if operation == "split":
            if payload.get("delimiter") != source_node.get("delimiter") or len(children) != 1:
                return False
            return _source_expression_matches(children[0], payload.get("value"),
                                              source_to_native, source, inlined)
        # substring option values are serialized as integers in native JSON.
        if (payload.get("substring_start") != int(source_node.get("substring_start")) or
                payload.get("substring_length") != int(source_node.get("substring_length")) or
                len(children) != 1):
            return False
        return _source_expression_matches(children[0], payload.get("value"),
                                          source_to_native, source, inlined)
    if operation == "time_difference":
        if not isinstance(native_expression, dict) or set(native_expression) != {"time_difference"}:
            return False
        payload = native_expression["time_difference"]
        for key in ("format_1", "format_2"):
            if key in source_node.attrib and payload.get(key) != source_node.get(key):
                return False
        children = [child for child in source_node if isinstance(child.tag, str)]
        values = payload.get("values")
        return (isinstance(values, list) and len(values) == len(children) and
                all(_source_expression_matches(child, value, source_to_native,
                                               source, inlined)
                    for child, value in zip(children, values)))
    if operation == "literal_component":
        datatype = source_node.get("datatype", "string")
        expected = source_literal(source_node.text or "", datatype)
        native_type, native_value = _native_literal_payload(native_expression)
        expected_type = SOURCE_TO_NATIVE_TYPES.get(datatype, datatype)
        return native_type == expected_type and native_value in (expected, [expected])
    if operation == "variable_component":
        reference = source_to_native.get(source_node.get("var_ref"))
        if reference:
            return (isinstance(native_expression, dict) and
                    set(native_expression) == {"variable"} and
                    native_expression["variable"] == reference)
        if source is not None and source_node.get("var_ref") in inlined:
            variable = source["variables"].get(source_node.get("var_ref"))
            values = [source_literal(child.text or "", variable.get("datatype"))
                      for child in (variable if variable is not None else ()) if tag(child) == "value"]
            native_type, native_value = _native_literal_payload(native_expression)
            expected_type = SOURCE_TO_NATIVE_TYPES.get(variable.get("datatype"),
                                                       variable.get("datatype"))
            return (native_type == expected_type and
                    native_value in (values[0], values) if len(values) == 1 else
                    native_type == expected_type and native_value == values)
        return False
    if operation in {"escape_regex", "glob_to_regex"}:
        native_type, native_value = _native_literal_payload(native_expression)
        if native_type != "string":
            return False
        values = _source_literal_function_values(source_node, source)
        if operation == "escape_regex":
            expected = [_escape_regex_literal(value) for value in values]
        else:
            raw = source_node.get("glob_noescape", "false").lower()
            if raw not in ("true", "false"):
                raise ValueError("unqualified source glob_noescape")
            expected = [_glob_to_regex_literal(value, glob_noescape=raw == "true")
                        for value in values]
        return (native_value in (expected[0], expected)
                if len(expected) == 1 else native_value == expected)
    if operation == "object_component":
        return False
    return False


def compare_mapped_variables(source, native, trace, selected_tests, field_datatypes=None):
    source_to_native = {}
    for row in trace.get("native_identities", []):
        if row.get("kind") != "variable":
            continue
        srcid, nativeid = row.get("source_id"), row.get("native_id")
        if not srcid or not nativeid or srcid in source_to_native:
            raise ValueError("duplicate/invalid source Variable mapping")
        source_to_native[srcid] = nativeid
    synthetic = trace.get("native_synthetic_variables", [])
    object_to_native = {
        row.get("source_id"): row.get("native_id")
        for row in trace.get("native_identities", [])
        if row.get("kind") == "object" and row.get("source_id") and row.get("native_id")
    }
    if not isinstance(synthetic, list):
        raise ValueError("native synthetic Variable metadata is malformed")
    synthetic_ids = set()
    materialized_source_variables = set(trace.get("native_inlined_variables", []))
    if not all(isinstance(item, str) for item in materialized_source_variables):
        raise ValueError("native inlined Variable metadata is malformed")
    for item in synthetic:
        if not isinstance(item, dict) or not isinstance(item.get("native_id"), str):
            raise ValueError("native synthetic Variable metadata is malformed")
        synthetic_ids.add(item["native_id"])
        materialized_source_variables.update(item.get("source_variable_ids", []))
    native_vars = {key: value for key, value in native.get("variables", {}).items()
                   if key not in synthetic_ids}
    if synthetic_ids - set(native.get("variables", {})):
        raise ValueError("synthetic Variable metadata has no native declaration")
    # Enum-domain projections are derived native Variables, not source
    # declarations. They must carry an exact source/native identity relation;
    # otherwise set equality below would either reject valid output or permit
    # an untraceable extra declaration.
    enum_equivalences = trace.get("enum_variable_equivalences", [])
    if not isinstance(enum_equivalences, list):
        raise ValueError("enum Variable equivalence metadata is malformed")
    enum_native_ids = set()
    for equivalence in enum_equivalences:
        if not isinstance(equivalence, dict):
            raise ValueError("enum Variable equivalence metadata is malformed")
        source_id = equivalence.get("source_variable")
        source_native = equivalence.get("source_native_variable")
        native_id = equivalence.get("native_variable")
        aliases = equivalence.get("aliases")
        if (not isinstance(source_id, str) or not isinstance(source_native, str) or
                not isinstance(native_id, str) or not isinstance(aliases, dict) or
                source_to_native.get(source_id) != source_native or
                native_id not in native_vars or native_id in enum_native_ids):
            raise ValueError("enum Variable equivalence does not preserve source identity")
        enum_native_ids.add(native_id)
    missing = (required_variable_declarations(source, selected_tests) -
               set(source_to_native) - materialized_source_variables)
    if missing:
        raise ValueError("required original Variable declarations omitted: " + str(sorted(missing)))
    if not set(source_to_native).issubset(source["variables"]):
        raise ValueError("fabricated original Variable declaration mapping")
    if set(native_vars) != set(source_to_native.values()) | enum_native_ids:
        raise ValueError("native Variable declarations do not match source trace")
    derived_types = _native_variable_types(
        native.get("variables", {}), field_datatypes, native)
    checked = 0
    for srcid, nativeid in source_to_native.items():
        src = source["variables"].get(srcid)
        dst = native_vars.get(nativeid)
        if src is None or not isinstance(dst, dict):
            raise ValueError("missing original/native Variable declaration: " + srcid)
        kind = tag(src)
        expected_kind = {"constant_variable": "constant", "local_variable": "local"}.get(kind)
        if expected_kind is None or dst.get("kind") != expected_kind:
            raise ValueError("source/native Variable kind mismatch: " + srcid)
        dtype = src.get("datatype")
        expected_type = SOURCE_TO_NATIVE_TYPES.get(dtype, dtype)
        if derived_types.get(nativeid) != expected_type:
            parts = [child for child in src if isinstance(child.tag, str)]
            source_type = (_source_expression_type(parts[0], source)
                           if tag(src) == "local_variable" and len(parts) == 1 else None)
            if source_type is not None and source_type != expected_type:
                raise ValueError("source-invalid Variable datatype declaration: " + srcid)
            raise ValueError("source/native Variable datatype mismatch: " + srcid)
        expression = dst.get("expression")
        if not isinstance(expression, dict) or len(expression) != 1:
            raise ValueError("invalid native Variable expression: " + srcid)
        if kind == "constant_variable":
            values = [source_literal(child.text or "", dtype)
                      for child in src if tag(child) == "value"]
            native_values = expression.get("literal")
            native_type = expected_type
            if isinstance(native_values, dict):
                native_type = native_values.get("datatype")
                native_values = native_values.get("value")
            if (native_type != expected_type or
                    not isinstance(native_values, list) or values != native_values):
                raise ValueError("source/native constant values, order or duplicates differ: " + srcid)
        else:
            parts = [child for child in src if isinstance(child.tag, str)]
            if len(parts) != 1:
                raise ValueError("local Variable graph has unqualified component count: " + srcid)
            child = parts[0]
            if tag(child) == "variable_component":
                reference = source_to_native.get(child.get("var_ref"))
                if reference:
                    if expression.get("variable") != reference:
                        raise ValueError("original Variable alias is not preserved: " + srcid)
                elif not _source_expression_matches(child, expression, source_to_native,
                                                     source, trace.get("native_inlined_variables", [])):
                    raise ValueError("original Variable alias is not preserved: " + srcid)
            elif tag(child) == "literal_component":
                native_type, native_value = _native_literal_payload(expression)
                datatype = child.get("datatype") or dtype
                expected = source_literal(child.text or "", datatype)
                expected_type = SOURCE_TO_NATIVE_TYPES.get(datatype, datatype)
                if native_type != expected_type or native_value not in (expected, [expected]):
                    raise ValueError("original local literal differs: " + srcid)
            elif tag(child) == "object_component":
                object_id = child.get("object_ref")
                source_object = source["nodes"].get(object_id)
                object_refs = [(node.text or "").strip() for node in (source_object.iter() if source_object is not None else ())
                               if tag(node) == "var_ref" and (node.text or "").strip()]
                if len(object_refs) == 1 and object_refs[0] in source_to_native:
                    expected = source_to_native[object_refs[0]]
                    if expression.get("variable") != expected:
                        raise ValueError("original object_component source is not preserved: " + srcid)
                else:
                    expected = next((item.get("native_id") for item in synthetic
                                     if item.get("source_object") == object_id), None)
                    if expected and expression.get("variable") == expected:
                        continue
                    # A normal capability Object may be inlined into a native
                    # ``values`` expression rather than emitted as a shared
                    # Object.  Preserve the exact source field and require a
                    # concrete native object payload; its selector parity is
                    # checked by the Test binding gate.
                    payload = expression.get("values") if isinstance(expression, dict) else None
                    if not isinstance(payload, dict) or payload.get("field") != child.get("item_field"):
                        raise ValueError("original object_component source is not preserved: " + srcid)
                    native_object = payload.get("object")
                    if isinstance(native_object, str):
                        if object_to_native.get(object_id) != native_object:
                            raise ValueError("original object_component source is not preserved: " + srcid)
                    elif not isinstance(native_object, dict):
                        raise ValueError("original object_component source is not preserved: " + srcid)
            elif tag(child) in {"begin", "end", "arithmetic", "concat", "split", "substring", "regex_capture", "escape_regex", "glob_to_regex"}:
                if not _source_expression_matches(child, expression, source_to_native,
                                                   source, trace.get("native_inlined_variables", [])):
                    raise ValueError("original local function differs: " + srcid)
            else:
                # Full recursive function comparison is a separate gate; do
                # not mark complex conversion as semantically proved here.
                raise ValueError("unqualified original Variable expression: " + tag(child))
        checked += 1
    return checked

_SOURCE_INVALID_VARIABLES = re.compile(
    r"source-invalid Variable datatype (?:declaration|normalization):\s*(?P<ids>.+)$"
)


def source_invalid_disposition(source, definition_id, reason, trace):
    """Return source-linked evidence for a typed Variable hold.

    A converter may emit a schema-valid compatibility document while the OVAL
    source itself declares a Variable datatype that disagrees with the
    expression's result. Keep that distinction machine-readable instead of
    leaving the row as an undifferentiated parity failure. XML node hashes
    are hashes of the parsed, deterministic ElementTree serialization; the
    complete source-document hash remains the authoritative identity.
    """
    match = _SOURCE_INVALID_VARIABLES.fullmatch(reason)
    variable_ids = sorted({item.strip() for item in match.group("ids").split(",")
                           if item.strip()}) if match else []
    selected_tests = []
    try:
        selected_tests = sorted(reachable_source_tests(source, definition_id))
    except (KeyError, TypeError, ValueError):
        # The surrounding audit still records the primary source-invalid
        # disposition; malformed graph diagnostics remain separate problems.
        selected_tests = []
    variable_rows = []
    for variable_id in variable_ids:
        variable = source.get("variables", {}).get(variable_id)
        if variable is None:
            variable_rows.append({"variable_id": variable_id,
                                  "source_variable_present": False})
            continue
        children = [child for child in variable if isinstance(child.tag, str)]
        expression_type = None
        if tag(variable) == "local_variable" and len(children) == 1:
            expression_type = _source_expression_type(children[0], source)
        source_refs = sorted({node.get("id") for node in source.get("nodes", {}).values()
                              if node.get("id") and
                              (node.get("var_ref") == variable_id or any(
                                  tag(child) == "var_ref" and (child.text or "").strip() == variable_id
                                  for child in node
                              ))})
        variable_rows.append({
            "variable_id": variable_id,
            "source_variable_present": True,
            "source_variable_kind": tag(variable),
            "declared_datatype": variable.get("datatype"),
            "expression_tag": tag(children[0]) if len(children) == 1 else None,
            "expression_result_datatype": expression_type,
            "source_variable_xml_sha256": digest(ET.tostring(variable, encoding="utf-8")),
            "referenced_source_node_ids": source_refs,
        })
    normalizations = [item for item in (trace or {}).get("source_type_normalizations", [])
                      if isinstance(item, dict) and
                      item.get("source_variable") in variable_ids]
    return {
        "source_path": source.get("path"),
        "source_xml_sha256": source.get("sha256"),
        "definition_id": definition_id,
        "affected_test_ids": selected_tests,
        "variable_ids": variable_ids,
        "variables": variable_rows,
        "native_type_normalizations": normalizations,
        "disposition": "source_invalid_non_equivalence",
    }


def audit(source_root, pack, *, require_full=False, expected_xml=144,
          expected_definitions=168, expected_tests=803,
          verify_pin=False, schema_root=None, source_commit=PIN):
    pin_verified = verify_source_checkout(source_root, source_commit) if verify_pin else False
    field_datatypes = load_field_datatypes(schema_root)
    records, archive_inventory = sources(source_root)
    original, definition_paths, problems = source_tree_summary(records)
    original["archives"] = archive_inventory
    for duplicate in original["duplicate_definitions"]:
        problems.append({"type": "duplicate_source_definition", **duplicate})
    for item in archive_inventory:
        if item.get("status") == "unclassified_nonzip_archive":
            problems.append({"type": "unclassified_embedded_content", **item})
    if expected_xml and sum(1 for path in records if "!" not in path) != expected_xml:
        problems.append({"type": "original_xml_file_count_mismatch",
                         "expected": expected_xml,
                         "observed": sum("!" not in p for p in records)})
    if expected_definitions and original["definitions"] != expected_definitions:
        problems.append({"type": "original_definition_count_mismatch",
                         "expected": expected_definitions,
                         "observed": original["definitions"]})
    if expected_tests and original["tests"] != expected_tests:
        problems.append({"type": "original_test_count_mismatch",
                         "expected": expected_tests,
                         "observed": original["tests"]})
    rows, manifest = read_pack(pack, source_commit)
    test_rows = read_test_ledger(pack)
    seen = set()
    statuses = Counter()
    tested = 0
    converted = 0
    unqualified = 0
    source_invalid_rows = []
    for row in rows:
        path, ident = row.get("source_path"), row.get("definition_id")
        key = (path, ident)
        if key in seen:
            problems.append({"type": "duplicate_converter_row", "source": path, "definition": ident})
            continue
        seen.add(key)
        if path not in records or ident not in records[path]["definitions"]:
            problems.append({"type": "invented_or_unpinned_source_definition",
                             "source": path, "definition": ident})
            continue
        source = records[path]
        if row.get("source_sha256") != source["sha256"]:
            problems.append({"type": "source_sha256_mismatch", "source": path,
                             "definition": ident})
        references = set(source["test_refs"][ident])
        if set(row.get("source_test_ids", [])) != references:
            problems.append({"type": "source_test_references_mismatch",
                             "source": path, "definition": ident})
        validate_exclusion_authorization(path, ident, row, "definition", problems)
        status = row.get("conversion_status", "missing")
        statuses[status] += 1
        if status == "blocked":
            if not row.get("diagnostic"):
                problems.append({"type": "blocker_without_diagnostic", "source": path,
                                 "definition": ident})
            continue
        if status in ("excluded", "intentionally_excluded"):
            if not row.get("diagnostic"):
                problems.append({"type": "exclusion_without_owner_approval",
                                 "source": path, "definition": ident})
            continue
        if status not in ("CONVERTED_UNVERIFIED", "converted", "converted_unverified"):
            problems.append({"type": "unreviewed_converter_status", "status": status,
                             "source": path, "definition": ident})
            continue
        converted += 1
        dirname = pack / "definitions" / slug(path) / slug(ident)
        trace = {}
        try:
            native_raw = (dirname / "assessment.json").read_bytes()
            trace_raw = (dirname / "source-trace.json").read_bytes()
            for filename, raw in (("assessment.json", native_raw),
                                  ("source-trace.json", trace_raw)):
                expected = row.get("artifacts", {}).get(filename, {}).get("sha256")
                if not expected or expected != digest(raw):
                    raise ValueError("missing or incorrect artifact SHA-256 for " + filename)
            native = json.loads(native_raw)["assessment"]
            trace = json.loads(trace_raw)
            if trace.get("source_path") != path or trace.get("source_commit") != source_commit:
                raise ValueError("source path/commit mismatch in trace")
            if trace.get("source_sha256") != source["sha256"] or trace.get("definition_id") != ident:
                raise ValueError("source digest/Definition mismatch in trace")
            if trace.get("source_oval_schema_version") != source["source_oval_schema_version"]:
                raise ValueError("original OVAL schema version missing or altered in trace")
            mapping = trace.get("test_bindings", [])
            expanded = {(entry.get("source_test"), entry.get("native_test"))
                        for entry in trace.get("native_expanded_set_tests", [])
                        if isinstance(entry, dict)}
            source_to_native = {}
            native_to_source = {}
            binding_by_pair = {}
            for bound in mapping:
                a, b = bound["source_test"], bound["native_test"]
                if b in native_to_source:
                    raise ValueError("duplicate native Test mapping in trace")
                if a in source_to_native and (a, b) not in expanded:
                    raise ValueError("duplicate Test mapping in trace without explicit Set expansion")
                source_to_native.setdefault(a, []).append(b)
                native_to_source[b] = a
                binding_by_pair[(a, b)] = bound
            selected_tests = reachable_source_tests(source, ident)
            if set(source_to_native) != selected_tests:
                raise ValueError("missing or extra source Test mapping")
            if set(native.get("tests", {})) != set(native_to_source):
                raise ValueError("native Test map differs from source trace")
            for source_id, native_ids in source_to_native.items():
                source_test = source["tests"].get(source_id)
                if source_test is None:
                    raise ValueError("source Test reference undefined in source XML")
                for native_id in native_ids:
                    native_test = native["tests"][native_id]
                    # A source variable Object Set is lowered to explicit
                    # child Tests. The child Variable is the materialized
                    # operand, not the source Object's single var_ref; the
                    # expansion trace and Set-retention gate verify that
                    # transformation separately.
                    if not binding_by_pair[(source_id, native_id)].get("object_set_operand"):
                        compare_variable_test_binding(source, source_test, native_test, trace)
                if tag(source_test) == "unknown_test":
                    native_test = native["tests"][native_ids[0]]
                    # OVAL unknown_test has a fixed unknown result. Its legacy
                    # cardinality attributes are ignored by specification.
                    if native_test.get("capability") != "independent.unknown":
                        raise ValueError("fixed unknown Test has wrong native capability")
                    continue
                original_existence = source_test.get("check_existence", "at_least_one_exists")
                expected_existence = EXISTENCE.get(original_existence)
                if expected_existence is None:
                    raise ValueError("unqualified original existence: " + str(original_existence))
                for native_id in native_ids:
                    native_test = native["tests"][native_id]
                    if (native_test.get("require", {}).get("item_requirement", {})
                                  .get("items_found") != expected_existence):
                        raise ValueError("OVAL existence cardinality differs at " + source_id)
                has_states = any(tag(child) == "state" for child in source_test)
                # OVAL has no State match to evaluate for a presence-only Test
                # or when the existence boundary itself is none_exist.
                expanded_source_test = any(
                    binding_by_pair[(source_id, native_id)].get("object_set_operand")
                    for native_id in native_ids)
                if (has_states and original_existence != "none_exist" and
                        not expanded_source_test):
                    original_check = source_test.get("check", "all")
                    expected_check = CHECK.get(original_check)
                    if expected_check is None:
                        raise ValueError("unqualified original check: " + str(original_check))
                    for native_id in native_ids:
                        native_test = native["tests"][native_id]
                        requirement = native_test.get("require", {})
                        item_requirement = requirement.get("item_requirement", {})
                        if item_requirement.get("items_satisfying") == expected_check:
                            continue
                        # The canonical record evaluator applies the OVAL Test
                        # check to a field's value population after the Item
                        # record itself has matched. Converters disclose this
                        # projection through field_requirement.values_matching.
                        field_requirement = requirement.get("field_requirement", {})
                        projected = (isinstance(requirement.get("fields"), dict) and
                                     field_requirement.get("values_matching") == expected_check)
                        if not (item_requirement.get("items_satisfying") == "every" and projected):
                            raise ValueError("OVAL check cardinality differs at " + source_id)
            normalizations = trace.get("source_type_normalizations", [])
            if normalizations:
                identifiers = sorted({item.get("source_variable", "")
                                      for item in normalizations if item.get("source_variable")})
                raise ValueError("source-invalid Variable datatype normalization: " +
                                 ", ".join(identifiers))
            compare_mapped_variables(
                source, native, trace, selected_tests, field_datatypes)
            audit_source_set_filter_retention(
                source, selected_tests, native, trace.get("native_synthetic_variables", []),
                trace.get("native_expanded_set_tests", []))
            oval_tree = normalize_source_evaluate(source, ident)
            expanded_native_to_source = {
                item.get("native_test"): item.get("source_test")
                for item in trace.get("native_expanded_set_tests", [])
                if isinstance(item, dict) and item.get("native_test") and item.get("source_test")}
            expanded_source_checks = {
                source_id: source["tests"].get(source_id, {}).get("check")
                for source_id in set(expanded_native_to_source.values())}
            native_tree = normalize_native_evaluate(
                native.get("evaluate"), native_to_source, expanded_native_to_source,
                expanded_source_checks)
            if oval_tree != native_tree:
                raise ValueError("source/native Evaluate logic mismatch")
            tested += len(selected_tests)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            reason = str(exc)[:300]
            problem_type = "source_invalid" if reason.startswith("source-invalid") else "converted_parity_failure"
            problem = {"type": problem_type, "source": path,
                       "definition": ident, "reason": reason}
            if problem_type == "source_invalid":
                disposition = source_invalid_disposition(source, ident, reason, trace)
                problem.update(disposition)
                source_invalid_rows.append(disposition)
            problems.append(problem)
            continue
        # Structural parity, NOT independently executed semantic equivalence.
        unqualified += 1
    # Reconcile the complete source Test universe independently of Definition
    # conversion.  Helper/unowned Tests are still ledger rows and must carry a
    # disposition; invented or missing rows are accounting failures.
    source_test_keys = {(path, test_id)
                        for path, source in records.items()
                        for test_id in source["tests"]}
    test_seen = {(row.get("source_path"), row.get("test_id")) for row in test_rows}
    for path, test_id in sorted(source_test_keys - test_seen):
        problems.append({"type": "source_test_without_converter_disposition",
                         "source": path, "test": test_id})
    for path, test_id in sorted(test_seen - source_test_keys):
        problems.append({"type": "invented_or_unpinned_source_test",
                         "source": path, "test": test_id})
    definition_by_key = {(row.get("source_path"), row.get("definition_id")): row
                         for row in rows}
    test_statuses = Counter()
    reconciled_tests = 0
    for row in test_rows:
        path, test_id = row.get("source_path"), row.get("test_id")
        if (path, test_id) not in source_test_keys:
            continue
        source = records[path]
        source_test = source["tests"][test_id]
        if row.get("source_sha256") != source["sha256"]:
            problems.append({"type": "source_test_sha256_mismatch",
                             "source": path, "test": test_id})
        owners = [owner for definition_id in source["definitions"]
                  if test_id in source["test_refs"][definition_id]
                  for owner in [definition_id]]
        if row.get("definition_ids") != owners:
            problems.append({"type": "source_test_ownership_mismatch",
                             "source": path, "test": test_id,
                             "expected": owners, "observed": row.get("definition_ids")})
        validate_exclusion_authorization(path, test_id, row, "test", problems)
        results = row.get("definition_results", [])
        if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
            problems.append({"type": "test_definition_results_malformed",
                             "source": path, "test": test_id})
            results = [item for item in results if isinstance(item, dict)] if isinstance(results, list) else []
        if [item.get("definition_id") for item in results] != owners:
            problems.append({"type": "test_definition_results_mismatch",
                             "source": path, "test": test_id})
        expected_native = []
        for owner in owners:
            definition_row = definition_by_key.get((path, owner))
            item = next((item for item in results
                         if item.get("definition_id") == owner), None)
            if definition_row is None or item is None:
                continue
            for field in ("conversion_status", "schema_validated", "failure_class", "diagnostic"):
                if item.get(field) != definition_row.get(field):
                    problems.append({"type": "test_owner_result_mismatch",
                                     "source": path, "test": test_id,
                                     "definition": owner, "field": field})
            native_id = item.get("native_test_id")
            if native_id:
                expected_native.append(native_id)
        observed_native = row.get("native_test_ids", [])
        if not isinstance(observed_native, list):
            problems.append({"type": "test_native_bindings_mismatch",
                             "source": path, "test": test_id})
            observed_native = []
        if observed_native != sorted(set(expected_native)):
            problems.append({"type": "test_native_bindings_mismatch",
                             "source": path, "test": test_id})
        expected_status = "CONVERTED_UNVERIFIED" if expected_native else "blocked"
        if row.get("conversion_status") != expected_status:
            problems.append({"type": "test_conversion_status_mismatch",
                             "source": path, "test": test_id,
                             "expected": expected_status,
                             "observed": row.get("conversion_status")})
        status = row.get("conversion_status", "missing")
        test_statuses[status] += 1
        if status == "blocked" and not row.get("diagnostic"):
            problems.append({"type": "blocker_without_diagnostic",
                             "source": path, "test": test_id})
        if status == "intentionally_excluded" and not row.get("diagnostic"):
            problems.append({"type": "exclusion_without_owner_approval",
                             "source": path, "test": test_id})
        reconciled_tests += 1

    absent = sorted(key for key in definition_paths if key not in seen)
    for path, ident in absent:
        problems.append({"type": "source_definition_without_converter_disposition",
                         "source": path, "definition": ident})
    coverage = {"original": original, "source_git_pin_verified": pin_verified,
                "pack": {
        "source_commit": manifest.get("source_commit"),
        "manifest_sha256": digest((pack / "manifest.json").read_bytes()),
        "tests_ledger_sha256": digest((pack / "tests.jsonl").read_bytes()),
        "schema_family_sha256": manifest.get("schema", {}).get("aggregate_sha256"),
        "schema_field_datatypes_loaded": len(field_datatypes),
        "schema_field_datatypes_source": ("canonical capability-mappings/supported"
                                           if schema_root is not None else "not-loaded"),
        "definitions_in_pack": len(rows),
        "status_counts": dict(sorted(statuses.items())),
        "parity_checked_definitions": unqualified,
        "source_mapped_tests_checked": tested,
        "converted_definitions": converted,
        "source_definitions_without_disposition": len(absent),
        "tests_in_ledger": len(test_rows),
        "test_status_counts": dict(sorted(test_statuses.items())),
        "reconciled_tests": reconciled_tests,
        "source_tests_without_disposition": len(source_test_keys - test_seen),
        "source_invalid_rows": source_invalid_rows,
        "source_invalid_definition_count": len(source_invalid_rows),
    }}
    accounting_errors = {"duplicate_source_definition", "duplicate_test_id",
                         "duplicate_converter_row", "source_sha256_mismatch",
                         "invented_or_unpinned_source_definition",
                         "source_test_references_mismatch",
                         "blocker_without_diagnostic",
                         "exclusion_without_owner_approval",
                         "unreviewed_converter_status",
                         "source_definition_without_converter_disposition",
                         "source_test_without_converter_disposition",
                         "invented_or_unpinned_source_test",
                         "source_test_sha256_mismatch",
                         "source_test_ownership_mismatch",
                         "test_definition_results_malformed",
                         "test_definition_results_mismatch",
                         "test_owner_result_mismatch",
                         "test_native_bindings_mismatch",
                         "test_conversion_status_mismatch",
                         "original_xml_file_count_mismatch",
                         "original_definition_count_mismatch",
                         "original_test_count_mismatch",
                         "unclassified_embedded_content"}
    accounted = not any(problem["type"] in accounting_errors for problem in problems)
    complete = not problems and converted == original["definitions"]
    scope_complete = (not problems and
                      converted + statuses["blocked"] == original["definitions"] and
                      reconciled_tests == original["tests"] and
                      sum(test_statuses.values()) == original["tests"] and
                      not statuses["excluded"] and
                      not statuses["intentionally_excluded"] and
                      not test_statuses["excluded"] and
                      not test_statuses["intentionally_excluded"])
    return {"format": "scap-ng-oval-source-parity/1", "complete": complete,
            "scope_complete": scope_complete,
            "source_accounted": accounted, "runtime_equivalence_proved": False,
            "qualification": "STRUCTURAL_ONLY_NOT_RUNTIME_EQUIVALENCE",
            "coverage": coverage, "problems": problems}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True,
                        help="original pinned SCAP_1.4/OVAL_Test_Content directory")
    parser.add_argument("--pack", type=Path, required=True,
                        help="converter output package with manifest.json/definitions.json")
    parser.add_argument("--schema-root", type=Path,
                        help="canonical flat 0.4.1 schema root for Item field types")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-xml", type=int, default=144)
    parser.add_argument("--expected-definitions", type=int, default=168)
    parser.add_argument("--expected-tests", type=int, default=803)
    parser.add_argument("--source-commit", default=PIN,
                        help="exact upstream Self-Assertion commit (default: corrected active pin)")
    parser.add_argument("--allow-unverified-fixture-source", action="store_true",
                        help="TEST FIXTURES ONLY: skip exact Git commit verification")
    parser.add_argument("--require-full", action="store_true",
                        help="exit nonzero unless every original Definition is converted")
    parser.add_argument("--require-scope", action="store_true",
                        help="require every source row to be in current authoring scope; blocked rows remain explicit holds")
    args = parser.parse_args()
    try:
        report = audit(args.source_root, args.pack,
                       require_full=args.require_full, expected_xml=args.expected_xml,
                       expected_definitions=args.expected_definitions,
                       expected_tests=args.expected_tests,
                       verify_pin=not args.allow_unverified_fixture_source,
                       source_commit=args.source_commit,
                       schema_root=args.schema_root)
    except (OSError, ValueError, KeyError, ET.ParseError) as exc:
        parser.exit(2, f"source parity audit error: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    summary = report["coverage"]
    print(json.dumps({"complete": report["complete"],
                      "scope_complete": report["scope_complete"],
                      "source_accounted": report["source_accounted"],
                      "original": summary["original"]["definitions"],
                      "converted": summary["pack"]["converted_definitions"],
                      "undispositioned": summary["pack"]["source_definitions_without_disposition"],
                      "tests": summary["pack"]["tests_in_ledger"],
                      "test_status_counts": summary["pack"]["test_status_counts"],
                      "problems": len(report["problems"])}, sort_keys=True))
    if ((args.require_full and not report["complete"]) or
            (args.require_scope and not report["scope_complete"])):
        raise SystemExit(1)

if __name__ == "__main__":
    main()
