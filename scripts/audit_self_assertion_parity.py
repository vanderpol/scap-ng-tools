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
import subprocess
import tarfile
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
             "only_one_exists": "exactly_one", "none_exist": "none",
             "all_exist": "one_or_more"}

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
    lookup = {node.get("id"): node for node in root.iter() if node.get("id")}
    refs = {}
    for ident, definition in defs.items():
        refs[ident] = list(dict.fromkeys(
            node.get("test_ref") for node in definition.iter()
            if tag(node) == "criterion" and node.get("test_ref")))
    return {"path": path, "sha256": digest(raw), "definitions": defs,
            "tests": tests, "variables": variables, "nodes": lookup,
            "test_refs": refs,
            "features": dict(sorted(features.items()))}

def verify_source_checkout(source_root):
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
        if args[0] == "rev-parse" and result.stdout.strip() != PIN:
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
    if len(refs) != 1:
        raise ValueError("original variable_object Variable reference not qualified")
    mapping = {entry["source_id"]: entry["native_id"]
               for entry in trace.get("native_identities", [])
               if entry.get("kind") == "variable"}
    expected = mapping.get(refs[0])
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

def source_literal(value, datatype):
    if datatype == "string":
        return value
    if datatype in ("int", "integer"):
        return int(value.strip(), 10)
    if datatype == "boolean":
        if value.strip().lower() not in ("true", "false", "1", "0"):
            raise ValueError("unrecognized original boolean value")
        return value.strip().lower() in ("true", "1")
    raise ValueError("unqualified original Variable datatype: " + str(datatype))

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

def compare_mapped_variables(source, native, trace, selected_tests):
    source_to_native = {}
    for row in trace.get("native_identities", []):
        if row.get("kind") != "variable":
            continue
        srcid, nativeid = row.get("source_id"), row.get("native_id")
        if not srcid or not nativeid or srcid in source_to_native:
            raise ValueError("duplicate/invalid source Variable mapping")
        source_to_native[srcid] = nativeid
    native_vars = native.get("variables", {})
    missing = required_variable_declarations(source, selected_tests) - set(source_to_native)
    if missing:
        raise ValueError("required original Variable declarations omitted: " + str(sorted(missing)))
    if not set(source_to_native).issubset(source["variables"]):
        raise ValueError("fabricated original Variable declaration mapping")
    if set(native_vars) != set(source_to_native.values()):
        raise ValueError("native Variable declarations do not match source trace")
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
        expected_type = {"int": "integer"}.get(dtype, dtype)
        if dst.get("datatype") != expected_type:
            raise ValueError("source/native Variable datatype mismatch: " + srcid)
        expression = dst.get("expression")
        if not isinstance(expression, dict) or len(expression) != 1:
            raise ValueError("invalid native Variable expression: " + srcid)
        if kind == "constant_variable":
            values = [source_literal(child.text or "", dtype)
                      for child in src if tag(child) == "value"]
            native_values = expression.get("literal")
            if not isinstance(native_values, list) or values != native_values:
                raise ValueError("source/native constant values, order or duplicates differ: " + srcid)
        else:
            parts = [child for child in src if isinstance(child.tag, str)]
            if len(parts) != 1:
                raise ValueError("local Variable graph has unqualified component count: " + srcid)
            child = parts[0]
            if tag(child) == "variable_component":
                reference = source_to_native.get(child.get("var_ref"))
                if not reference or expression.get("variable") != reference:
                    raise ValueError("original Variable alias is not preserved: " + srcid)
            elif tag(child) == "literal_component":
                native_values = expression.get("literal")
                expected = source_literal(child.text or "", child.get("datatype"))
                if native_values != expected and native_values != [expected]:
                    raise ValueError("original local literal differs: " + srcid)
            else:
                # Full recursive function comparison is a separate gate; do
                # not mark complex conversion as semantically proved here.
                raise ValueError("unqualified original Variable expression: " + tag(child))
        checked += 1
    return checked

def audit(source_root, pack, *, require_full=False, expected_xml=144,
          expected_definitions=168, expected_tests=803,
          verify_pin=False):
    pin_verified = verify_source_checkout(source_root) if verify_pin else False
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
        if status in ("excluded", "intentionally_excluded"):
            if not row.get("diagnostic") or not row.get("owner_decision"):
                problems.append({"type": "exclusion_without_owner_approval",
                                 "source": path, "definition": ident})
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
            selected_tests = reachable_source_tests(source, ident)
            if set(source_to_native) != selected_tests:
                raise ValueError("missing or extra source Test mapping")
            if set(native.get("tests", {})) != set(source_to_native.values()):
                raise ValueError("native Test map differs from source trace")
            for source_id, native_id in source_to_native.items():
                source_test = source["tests"].get(source_id)
                if source_test is None:
                    raise ValueError("source Test reference undefined in source XML")
                native_test = native["tests"][native_id]
                compare_variable_test_binding(source, source_test, native_test, trace)
                if tag(source_test) == "unknown_test":
                    # OVAL unknown_test has a fixed unknown result. Its legacy
                    # cardinality attributes are ignored by specification.
                    if native_test.get("capability") != "independent.unknown":
                        raise ValueError("fixed unknown Test has wrong native capability")
                    continue
                original_existence = source_test.get("check_existence", "at_least_one_exists")
                expected_existence = EXISTENCE.get(original_existence)
                if expected_existence is None:
                    raise ValueError("unqualified original existence: " + str(original_existence))
                if (native_test.get("require", {}).get("item_requirement", {})
                              .get("items_found") != expected_existence):
                    raise ValueError("OVAL existence cardinality differs at " + source_id)
                has_states = any(tag(child) == "state" for child in source_test)
                # OVAL has no State match to evaluate for a presence-only Test
                # or when the existence boundary itself is none_exist.
                if has_states and original_existence != "none_exist":
                    original_check = source_test.get("check", "all")
                    expected_check = CHECK.get(original_check)
                    if expected_check is None:
                        raise ValueError("unqualified original check: " + str(original_check))
                    if (native_test.get("require", {}).get("item_requirement", {})
                                  .get("items_satisfying") != expected_check):
                        raise ValueError("OVAL check cardinality differs at " + source_id)
            compare_mapped_variables(source, native, trace, selected_tests)
            native_to_source = {v: k for k, v in source_to_native.items()}
            oval_tree = normalize_source_evaluate(source, ident)
            native_tree = normalize_native_evaluate(native.get("evaluate"), native_to_source)
            if oval_tree != native_tree:
                raise ValueError("source/native Evaluate logic mismatch")
            tested += len(selected_tests)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            problems.append({"type": "converted_parity_failure", "source": path,
                             "definition": ident, "reason": str(exc)[:300]})
            continue
        # Structural parity, NOT independently executed semantic equivalence.
        unqualified += 1
    absent = sorted(key for key in definition_paths if key not in seen)
    for path, ident in absent:
        problems.append({"type": "source_definition_without_converter_disposition",
                         "source": path, "definition": ident})
    coverage = {"original": original, "source_git_pin_verified": pin_verified,
                "pack": {
        "source_commit": manifest.get("source_commit"),
        "schema_family_sha256": manifest.get("schema", {}).get("aggregate_sha256"),
        "definitions_in_pack": len(rows),
        "status_counts": dict(sorted(statuses.items())),
        "parity_checked_definitions": unqualified,
        "source_mapped_tests_checked": tested,
        "converted_definitions": converted,
        "source_definitions_without_disposition": len(absent),
    }}
    accounting_errors = {"duplicate_source_definition", "duplicate_test_id",
                         "duplicate_converter_row", "source_sha256_mismatch",
                         "invented_or_unpinned_source_definition",
                         "source_test_references_mismatch",
                         "blocker_without_diagnostic",
                         "exclusion_without_owner_approval",
                         "unreviewed_converter_status",
                         "source_definition_without_converter_disposition",
                         "original_xml_file_count_mismatch",
                         "original_definition_count_mismatch",
                         "original_test_count_mismatch",
                         "unclassified_embedded_content"}
    accounted = not any(problem["type"] in accounting_errors for problem in problems)
    complete = not problems and converted == original["definitions"]
    scope_complete = (not problems and
                      converted + statuses["excluded"] +
                      statuses["intentionally_excluded"] == original["definitions"])
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
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-xml", type=int, default=144)
    parser.add_argument("--expected-definitions", type=int, default=168)
    parser.add_argument("--expected-tests", type=int, default=803)
    parser.add_argument("--allow-unverified-fixture-source", action="store_true",
                        help="TEST FIXTURES ONLY: skip exact Git commit verification")
    parser.add_argument("--require-full", action="store_true",
                        help="exit nonzero unless every original Definition is converted")
    parser.add_argument("--require-scope", action="store_true",
                        help="allow excluded Definitions ONLY with explicit owner decision")
    args = parser.parse_args()
    try:
        report = audit(args.source_root, args.pack,
                       require_full=args.require_full, expected_xml=args.expected_xml,
                       expected_definitions=args.expected_definitions,
                       expected_tests=args.expected_tests,
                       verify_pin=not args.allow_unverified_fixture_source)
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
                      "problems": len(report["problems"])}, sort_keys=True))
    if ((args.require_full and not report["complete"]) or
            (args.require_scope and not report["scope_complete"])):
        raise SystemExit(1)

if __name__ == "__main__":
    main()
