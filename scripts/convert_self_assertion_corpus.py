"""Convert every pinned agnostic OVAL Self-Assertion Definition.

This is a production-CLI orchestrator, not a second converter. Each source
Definition is sent unchanged to ``scap_ng_tools.converter.direct04``. A
successful invocation publishes the CLI's schema-validated JSON/YAML and trace;
failures remain in a per-Definition and per-Test blocked ledger with the exact
converter diagnostic. No expected outcomes or source semantics are invented.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any
import xml.etree.ElementTree as ET
from zipfile import ZipFile

import yaml

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import validate_native_documents

CORPUS_REL = Path("SCAP_1.4/OVAL_Test_Content/agnostic")
ZIP_NAME = "oval-def-ext.zip"
ZIP_DEFINITION_MEMBER = "oval-def-ext.xml"
FORMAT = "scap-ng-tools-self-assertion-agnostic-conversion/1"


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def source_documents(corpus: Path):
    """Yield (repository path, member path, raw XML) in deterministic order."""
    base = corpus / CORPUS_REL
    for path in sorted(base.glob("*.xml")):
        yield CORPUS_REL / path.name, CORPUS_REL / path.name, path.read_bytes()
    archive = base / ZIP_NAME
    with ZipFile(archive) as package:
        for member in (ZIP_DEFINITION_MEMBER, "oval-def-ext_external-variables.xml"):
            raw = package.read(member)
            if member == ZIP_DEFINITION_MEMBER:
                yield CORPUS_REL / f"{ZIP_NAME}!{member}", CORPUS_REL / f"{ZIP_NAME}!{member}", raw


def nodes(root: ET.Element, suffix: str):
    return [node for node in root.iter() if node.tag.split("}")[-1] == suffix and node.get("id")]


def definitions_and_tests(raw: bytes):
    root = ET.fromstring(raw)
    definitions = {}
    test_defs: dict[str, list[str]] = defaultdict(list)
    for definition in nodes(root, "definition"):
        refs = []
        for node in definition.iter():
            if node.tag.split("}")[-1] == "criterion" and node.get("test_ref"):
                test_id = node.get("test_ref")
                if test_id not in refs:
                    refs.append(test_id)
                if definition.get("id") not in test_defs[test_id]:
                    test_defs[test_id].append(definition.get("id"))
        definitions[definition.get("id")] = refs
    tests = {node.get("id"): node for node in root.iter()
             if node.get("id") and node.tag.split("}")[-1].endswith("_test")}
    return definitions, tests, test_defs


def slug(value: str) -> str:
    return value.replace(":", "_").replace("/", "_")


def classify_failure(stderr: str, stdout: str) -> str:
    message = (stderr.strip() or stdout.strip()).lower()
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


def independent_artifacts(snapshot: FrozenSchemaSnapshot, files: dict[str, Path]):
    document = json.loads(files["assessment.json"].read_text())
    yaml_document = yaml.safe_load(files["assessment.yaml"].read_text())
    if document != yaml_document:
        raise ValueError("converter JSON/YAML read-back differs")
    validate_native_documents(snapshot, {"assessment.json": document})
    validate_native_documents(snapshot, {"assessment.yaml": yaml_document})
    return {name: {"sha256": digest(path.read_bytes()), "bytes": path.stat().st_size}
            for name, path in files.items()}


def convert(*, corpus: Path, schema_root: Path, source_commit: str,
            output: Path, python: str):
    if output.exists():
        raise ValueError(f"refusing to overwrite existing output: {output}")
    snapshot = FrozenSchemaSnapshot(schema_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix="self-assertion-conversion-", dir=output.parent))
    try:
        source_root = corpus / CORPUS_REL
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
            for source_path, provenance_path, raw in source_documents(corpus):
                definitions, tests, test_defs = definitions_and_tests(raw)
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
                })
            definition_results = {}
            for graph in source_graph:
                source_path = graph["source_path"]
                provenance_path = graph["provenance_path"]
                source_sha = graph["source_sha256"]
                source_text_path = graph["source_text_path"]
                definitions = graph["definitions"]
                for definition_id, refs in definitions.items():
                    artifact_dir = temp / "definitions" / slug(str(source_path)) / slug(definition_id)
                    command, process, files, success = run_one(
                        python=python, schema_root=schema_root, source=source_text_path,
                        source_sha=source_sha, source_commit=source_commit,
                        source_path=str(provenance_path), definition=definition_id,
                        out=artifact_dir)
                    recorded_command = public_command(
                        command, schema_root=schema_root, source=source_text_path,
                        output=artifact_dir)
                    row = {
                        "source_path": str(provenance_path),
                        "source_sha256": source_sha,
                        "definition_id": definition_id,
                        "source_test_ids": refs,
                        "source_test_count": len(refs),
                        "converter_command": recorded_command,
                        "converter_returncode": process.returncode,
                        "conversion_status": "CONVERTED_UNVERIFIED" if success else "blocked",
                        "schema_validated": False,
                        "independent_semantic_proof": False,
                        "scanner_execution": False,
                        "failure_class": None if success else classify_failure(process.stderr, process.stdout),
                        "diagnostic": None if success else (process.stderr.strip() or process.stdout.strip()),
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
                            converted_rows.append(row)
                    definition_rows.append(row)
                    definition_results[(str(provenance_path), definition_id)] = {
                        "status": row["conversion_status"],
                        "schema_validated": row["schema_validated"],
                        "native_bindings": bindings,
                        "failure_class": row["failure_class"],
                        "diagnostic": row["diagnostic"],
                    }
            for graph in source_graph:
                provenance_path = str(graph["provenance_path"])
                source_sha = graph["source_sha256"]
                definitions = graph["definitions"]
                tests = graph["tests"]
                test_defs = graph["test_defs"]
                for test_id in sorted(tests):
                    owner_ids = list(test_defs.get(test_id, []))
                    owner_results = [definition_results[(provenance_path, owner)]
                                     for owner in owner_ids]
                    bindings = [result["native_bindings"].get(test_id)
                                for result in owner_results]
                    native_ids = sorted({value for value in bindings if value})
                    if native_ids:
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
                        "conversion_status": status,
                        "schema_validated": schema_validated,
                        "native_test_ids": native_ids,
                        "execution": "not_run",
                        "failure_class": failure_class,
                        "diagnostic": diagnostic,
                    })
        # The XML graph yields exactly the pinned corpus denominator.
        test_rows.sort(key=lambda row: (row["source_path"], row["test_id"]))
        if len(definition_rows) != 47 or len(test_rows) != 328:
            raise ValueError(f"pinned denominator mismatch: definitions={len(definition_rows)} tests={len(test_rows)}")
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
            "execution": "not_run",
            "expected_outcomes_derived": False,
        }
        (temp / "validation.json").write_text(json.dumps(validation, indent=2) + "\n")
        notices = Path(__file__).resolve().parents[1] / "docs/evidence/issue37-variables/NOTICES.txt"
        if notices.is_file():
            shutil.copyfile(notices, temp / "NOTICES.txt")
        else:
            (temp / "NOTICES.txt").write_text(
                "Derivative native conversion review artifacts from pinned SCAP 1.4 OVAL content; "
                "original XML is unchanged.\n")
        (temp / "README.md").write_text(
            "# Pinned agnostic Self-Assertion conversion\n\n"
            f"Production CLI conversion of the pinned corpus at `{source_commit}`. "
            "The complete ledgers preserve every source Definition and Test; blocked "
            "entries retain the exact converter diagnostic.\n\n"
            f"- Definitions: {len(definition_rows)} ({len(converted_rows)} converted, "
            f"{len(blocked_definitions)} blocked)\n"
            f"- Tests: {len(test_rows)} ({len(test_rows) - len(blocked_tests)} converted, "
            f"{len(blocked_tests)} blocked)\n"
            "- Generated native documents are schema-valid and remain `CONVERTED_UNVERIFIED`.\n"
            "- No expected outcomes, collected Items, or execution results are derived.\n"
            "- See `source-mappings.json`, `definitions.json`, `tests.jsonl`, and the blocked ledgers.\n"
        )
        (temp / "definitions.json").write_text(json.dumps(definition_rows, indent=2) + "\n")
        with (temp / "tests.jsonl").open("w") as stream:
            for row in test_rows:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        manifest = {
            "format": FORMAT,
            "source_repository": "OVAL-Community/SCAP-Self-Assertion",
            "source_commit": source_commit,
            "source_root": str(CORPUS_REL),
            "schema": snapshot.manifest(),
            "converter": "scap_ng_tools.converter.direct04",
            "conversion_policy": "production CLI only; no manual native rewrites or expected outcomes",
            "summary": {
                "definitions": len(definition_rows),
                "tests": len(test_rows),
                "converted_definitions": len(converted_rows),
                "blocked_definitions": len(definition_rows) - len(converted_rows),
                "schema_valid_yaml_documents": len(converted_rows),
                "converted_tests": sum(r["conversion_status"] == "CONVERTED_UNVERIFIED" for r in test_rows),
                "blocked_tests": sum(r["conversion_status"] == "blocked" for r in test_rows),
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
    parser.add_argument("--python", default=os.environ.get("PYTHON", os.sys.executable))
    args = parser.parse_args()
    result = convert(corpus=args.corpus, schema_root=args.schema_root,
                     source_commit=args.source_commit, output=args.output,
                     python=args.python)
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
