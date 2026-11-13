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
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from zipfile import ZipFile

PREFIX = "SCAP_1.4/OVAL_Test_Content/"
PIN = "e3538595c5083b9c34d937a81d319234df9bbfaa"
MAX_XML = 8 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
CHECK = {"all": "every", "at least one": "one_or_more",
         "only one": "exactly_one", "none satisfy": "none"}
EXISTENCE = {"at_least_one_exists": "one_or_more",
             "only_one_exists": "exactly_one", "none_exist": "none"}

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
    refs = {}
    for ident, definition in defs.items():
        refs[ident] = list(dict.fromkeys(
            node.get("test_ref") for node in definition.iter()
            if tag(node) == "criterion" and node.get("test_ref")))
    return {"path": path, "sha256": digest(raw), "definitions": defs,
            "tests": tests, "variables": variables, "test_refs": refs,
            "features": dict(sorted(features.items()))}

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
                if b"<oval_definitions" not in raw[:4096]:
                    continue
                relative = inspected["path"] + "!" + member.filename
                if relative in records:
                    raise ValueError("duplicate embedded XML path: " + relative)
                records[relative] = parse_oval(raw, relative)
                inspected["oval_members"] += 1
        archive_inventory.append(inspected)
    for archive in sorted(source_root.rglob("*.tarz")):
        archive_inventory.append({
            "path": PREFIX + archive.relative_to(source_root).as_posix(),
            "status": "unclassified_nonzip_archive",
            "reason": "requires inspection for embedded OVAL definitions"})
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
        for ident in record["definitions"]:
            if ident in definition_paths:
                duplicate_definitions.append({"id": ident, "files": [definition_paths[ident], path]})
            else:
                definition_paths[ident] = path
        for ident in record["tests"]:
            if ident in test_paths:
                conflicts.append({"type": "duplicate_test_id", "id": ident,
                                  "files": [test_paths[ident], path]})
            else:
                test_paths[ident] = path
    return ({"xml_documents": len(records), "definitions": len(definition_paths),
             "tests": len(test_paths), "by_family": dict(sorted(dirs.items())),
             "source_features": dict(sorted(features.items())),
             "duplicate_definitions": duplicate_definitions},
            definition_paths, conflicts)

def read_pack(pack):
    definitions_path = pack / "definitions.json"
    if not definitions_path.is_file():
        raise ValueError(f"converter package missing definitions.json: {pack}")
    rows = json.loads(definitions_path.read_text(encoding="utf-8"))
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("definitions.json must be an array")
    if manifest.get("source_commit") != PIN:
        raise ValueError("converter package uses a different original source commit")
    return rows, manifest

def slug(value):
    return value.replace(":", "_").replace("/", "_")

def normalize_source_evaluate(definition):
    # Some OVAL files only contain one criterion under AND; the native
    # equivalent can legitimately collapse that wrapper.
    def parse(node):
        name = tag(node)
        if name == "criterion":
            result = ("test", node.get("test_ref"))
        elif name == "extend_definition":
            result = ("extend", node.get("definition_ref"))
        elif name == "criteria":
            children = tuple(parse(child) for child in node
                             if tag(child) in ("criteria", "criterion", "extend_definition"))
            op = (node.get("operator") or "AND").lower()
            result = children[0] if len(children) == 1 and op in ("and", "or") else (op, children)
        else:
            raise ValueError("unrecognized criteria node " + name)
        return ("not", result) if node.get("negate", "false").lower() == "true" else result
    start = next((c for c in definition if tag(c) == "criteria"), None)
    return parse(start) if start is not None else None

def normalize_native_evaluate(node, native_to_source):
    if not isinstance(node, dict) or len(node) != 1:
        raise ValueError("malformed native Evaluate")
    op, val = next(iter(node.items()))
    if op == "test":
        if val not in native_to_source:
            raise ValueError("unmapped native Test " + str(val))
        return ("test", native_to_source[val])
    if op == "not":
        return ("not", normalize_native_evaluate(val, native_to_source))
    if op in ("and", "or", "xor", "one") and isinstance(val, list):
        children = tuple(normalize_native_evaluate(v, native_to_source) for v in val)
        return children[0] if len(children) == 1 and op in ("and", "or") else (op, children)
    raise ValueError("unknown native Evaluate operator " + str(op))

def audit(source_root, pack, *, require_full=False, expected_xml=144):
    records, archive_inventory = sources(source_root)
    original, definition_paths, problems = source_tree_summary(records)
    original["archives"] = archive_inventory
    for duplicate in original["duplicate_definitions"]:
        problems.append({"type": "duplicate_source_definition", **duplicate})
    for item in archive_inventory:
        if item.get("status") == "unclassified_nonzip_archive":
            problems.append({"type": "unclassified_embedded_content", **item})
    if expected_xml and sum(1 for path in records if ".zip!" not in path) != expected_xml:
        problems.append({"type": "original_xml_file_count_mismatch",
                         "expected": expected_xml,
                         "observed": sum(".zip!" not in p for p in records)})
    rows, manifest = read_pack(pack)
    seen = set()
    statuses = Counter()
    tested = 0
    converted = 0
    unqualified = 0
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
        status = row.get("conversion_status", "missing")
        statuses[status] += 1
        if status == "blocked":
            if not row.get("diagnostic"):
                problems.append({"type": "blocker_without_diagnostic", "source": path,
                                 "definition": ident})
            continue
        if status not in ("CONVERTED_UNVERIFIED", "converted", "converted_unverified"):
            problems.append({"type": "unreviewed_converter_status", "status": status,
                             "source": path, "definition": ident})
            continue
        converted += 1
        dirname = pack / "definitions" / slug(path) / slug(ident)
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
            if trace.get("source_path") != path or trace.get("source_commit") != PIN:
                raise ValueError("source path/commit mismatch in trace")
            if trace.get("source_sha256") != source["sha256"] or trace.get("definition_id") != ident:
                raise ValueError("source digest/Definition mismatch in trace")
            mapping = trace.get("test_bindings", [])
            source_to_native = {}
            for bound in mapping:
                a, b = bound["source_test"], bound["native_test"]
                if a in source_to_native or b in source_to_native.values():
                    raise ValueError("duplicate Test mapping in trace")
                source_to_native[a] = b
            if set(source_to_native) != references:
                raise ValueError("missing or extra source Test mapping")
            if set(native.get("tests", {})) != set(source_to_native.values()):
                raise ValueError("native Test map differs from source trace")
            for source_id, native_id in source_to_native.items():
                source_test = source["tests"].get(source_id)
                if source_test is None:
                    raise ValueError("source Test reference undefined in source XML")
                native_test = native["tests"][native_id]
                original_check = source_test.get("check", "all")
                expected_check = CHECK.get(original_check)
                if expected_check is None:
                    raise ValueError("unqualified original check: " + str(original_check))
                if (
                    native_test.get("require", {}).get("item_requirement", {})
                               .get("items_satisfying") != expected_check
                ):
                    raise ValueError("OVAL check cardinality differs at " + source_id)
                original_existence = source_test.get("check_existence", "at_least_one_exists")
                expected_existence = EXISTENCE.get(original_existence)
                if expected_existence is None:
                    raise ValueError("unqualified original existence: " + str(original_existence))
                if (
                    native_test.get("require", {}).get("item_requirement", {})
                               .get("items_found") != expected_existence
                ):
                    raise ValueError("OVAL existence cardinality differs at " + source_id)
            native_to_source = {v: k for k, v in source_to_native.items()}
            oval_tree = normalize_source_evaluate(source["definitions"][ident])
            native_tree = normalize_native_evaluate(native.get("evaluate"), native_to_source)
            if oval_tree != native_tree:
                raise ValueError("source/native Evaluate logic mismatch")
            tested += len(references)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            problems.append({"type": "converted_parity_failure", "source": path,
                             "definition": ident, "reason": str(exc)[:300]})
            continue
        # Structural parity, NOT independently executed semantic equivalence.
        unqualified += 1
    absent = sorted((path, ident) for ident, path in definition_paths.items()
                    if (path, ident) not in seen)
    for path, ident in absent:
        problems.append({"type": "source_definition_without_converter_disposition",
                         "source": path, "definition": ident})
    coverage = {"original": original, "pack": {
        "source_commit": manifest.get("source_commit"),
        "schema_family_sha256": manifest.get("schema", {}).get("aggregate_sha256"),
        "definitions_in_pack": len(rows),
        "status_counts": dict(sorted(statuses.items())),
        "parity_checked_definitions": unqualified,
        "source_mapped_tests_checked": tested,
        "converted_definitions": converted,
        "source_definitions_without_disposition": len(absent),
    }}
    complete = not problems and converted == original["definitions"]
    return {"format": "scap-ng-oval-source-parity/1", "complete": complete,
            "source_accounted": not absent, "runtime_equivalence_proved": False,
            "qualification": "STRUCTURAL_ONLY_NOT_RUNTIME_EQUIVALENCE",
            "coverage": coverage, "problems": problems}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True,
                        help="original pinned SCAP_1.4/OVAL_Test_Content directory")
    parser.add_argument("--pack", type=Path, required=True,
                        help="converter output package with manifest.json/definitions.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-xml", type=int, default=144)
    parser.add_argument("--require-full", action="store_true",
                        help="exit nonzero for ANY missing/blocked Definition or mismatch")
    args = parser.parse_args()
    try:
        report = audit(args.source_root, args.pack,
                       require_full=args.require_full, expected_xml=args.expected_xml)
    except (OSError, ValueError, KeyError, ET.ParseError) as exc:
        parser.exit(2, f"source parity audit error: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    summary = report["coverage"]
    print(json.dumps({"complete": report["complete"],
                      "source_accounted": report["source_accounted"],
                      "original": summary["original"]["definitions"],
                      "converted": summary["pack"]["converted_definitions"],
                      "undispositioned": summary["pack"]["source_definitions_without_disposition"],
                      "problems": len(report["problems"])}, sort_keys=True))
    if args.require_full and not report["complete"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
