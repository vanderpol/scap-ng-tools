#!/usr/bin/env python3
"""Build the source-ID-preserving Issue #59 datatype recovery ledger.

This is an evidence inventory, not a converter proof.  It reads the signed
source ZIPs and the exact rebuild receipt, records the collected Item field
contract separately from the OVAL State comparator contract, and only marks a
case recoverable when a reviewed source boundary supplies a single native
input type (or OVAL ``unique`` supplies an explicit lexical conversion).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"


def local(element):
    return element.tag.rsplit("}", 1)[-1]


def refs(element):
    result = set()
    for node in element.iter():
        for key in ("test_ref", "object_ref", "state_ref", "var_ref", "variable_ref", "definition_ref"):
            if node.get(key):
                result.add(node.get(key))
        if local(node) in {"filter", "object_reference", "var_ref"} and (node.text or "").strip():
            result.add(node.text.strip())
    return result


def source_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_zip(path):
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".xml")]
        if not names:
            raise ValueError("source ZIP has no XML: " + path.name)
        root = ET.fromstring(archive.read(names[0]))
    by_id = {node.get("id"): node for node in root.iter() if node.get("id")}
    return root, by_id


def mappings(schema_root):
    result = {}
    for path in sorted((schema_root / "capability-mappings" / "supported").glob("*.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        source = item.get("source", {})
        result[(source.get("namespace"), source.get("object"))] = item
    return result


def choose_variable(by_id, definition_id, blocker):
    seen = set()
    queue = [definition_id] if definition_id else []
    while queue:
        identity = queue.pop()
        if identity in seen:
            continue
        seen.add(identity)
        node = by_id.get(identity)
        if node is not None:
            queue.extend(refs(node) - seen)
    variables = [by_id[i] for i in seen if i in by_id and local(by_id[i]) == "local_variable"]
    match = re.search(r"Variable ([^:]+):", blocker)
    words = {word for word in re.split(r"[-_ ]+", (match.group(1) if match else "").lower())
             if len(word) > 2 and word not in {"variable", "the", "from", "and"}}
    scored = sorted(((sum(word in (node.get("comment") or "").lower() for word in words), node)
                     for node in variables), key=lambda pair: (-pair[0], pair[1].get("id", "")))
    if "unique requires" in blocker:
        unique = [node for node in variables if any(local(child) == "unique" for child in node)]
        if unique:
            return sorted(unique, key=lambda node: node.get("id", ""))[0]
    if scored and (scored[0][0] > 0 or len(variables) == 1):
        return scored[0][1]
    return scored[0][1] if scored else None


def definition_for_rule(by_id, rule_id):
    rule = by_id.get(rule_id)
    if rule is None:
        raise ValueError("source Rule is missing: " + rule_id)
    for node in rule.iter():
        if local(node) == "check-content-ref" and node.get("name"):
            return node.get("name")
    raise ValueError("Rule has no OVAL Definition reference: " + rule_id)


def object_mapping(by_id, component, mapping_index):
    object_id = component.get("object_ref")
    obj = by_id.get(object_id)
    if obj is None:
        return None, None
    namespace = obj.tag[1:].split("}", 1)[0] if obj.tag.startswith("{") else ""
    item = mapping_index.get((namespace, local(obj)))
    if item is None:
        item = next((value for (ns, name), value in mapping_index.items() if name == local(obj)), None)
    return obj, item


def consumers(root, variable_id):
    parent = {child: node for node in root.iter() for child in node}
    rows = []
    for node in root.iter():
        if node.get("var_ref") != variable_id:
            continue
        owner = parent.get(node)
        rows.append({
            "element": local(node),
            "parent": local(owner) if owner is not None else None,
            "operation": node.get("operation", "equals"),
            "datatype": node.get("datatype"),
            "var_check": node.get("var_check"),
        })
    return rows


def classify(row, source_root, mapping_index):
    path = next(source_root.rglob(row["benchmark"]))
    root, by_id = load_zip(path)
    definition_id = definition_for_rule(by_id, row["source_rule"])
    variable = choose_variable(by_id, definition_id, row["primary_blocker"])
    if variable is None:
        raise ValueError("unable to identify local Variable: " + row["source_rule"])
    expression = variable[0] if len(variable) else None
    components = [node for node in variable.iter() if local(node) == "object_component"]
    field_rows = []
    for component in components:
        obj, mapping = object_mapping(by_id, component, mapping_index)
        field = component.get("item_field")
        native = mapping.get("native", {}) if mapping else {}
        item_types = native.get("field_datatypes", {}).get(native.get("state_field_map", {}).get(field, field))
        state_types = native.get("state_field_datatypes", {}).get(native.get("state_field_map", {}).get(field, field))
        field_rows.append({
            "capability": mapping.get("capability") if mapping else None,
            "source_object": local(obj) if obj is not None else None,
            "source_object_id": component.get("object_ref"),
            "source_field": field,
            "native_field": native.get("state_field_map", {}).get(field, field),
            "collected_item_datatypes": item_types or [],
            "state_comparator_datatypes": state_types or [],
        })
    unique = local(expression) == "unique" if expression is not None else False
    singletons = [field for field in field_rows if len(field["collected_item_datatypes"]) == 1]
    if unique:
        decision, reason = "recover", "OVAL 5.12.3 unique has an explicit lexical-string result"
    elif field_rows and len(field_rows) == len(singletons) and len(field_rows) == 1:
        decision, reason = "recover", "collected Item field contract is a singleton datatype"
    else:
        decision, reason = "blocked", "collected Item field permits multiple datatypes; source declaration is not a native cast"
    return {
        "benchmark": row["benchmark"],
        "source_rule": row["source_rule"],
        "source_rule_sha256": row.get("source_rule_sha256", ""),
        "source_variable_id": variable.get("id"),
        "source_variable_xml_sha256": hashlib.sha256(ET.tostring(variable, encoding="utf-8")).hexdigest(),
        "source_variable_datatype": variable.get("datatype"),
        "source_variable_comment": variable.get("comment"),
        "source_expression": local(expression) if expression is not None else None,
        "consumer_operations": consumers(root, variable.get("id")),
        "fields": field_rows,
        "decision": decision,
        "decision_reason": reason,
        "proof_status": "authoring_only_unverified",
        "scanner_equivalent": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--original-receipt", type=Path, required=True,
                        help="pre-fix receipt containing all 118 original regressions")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--crosswalk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    original = json.loads(args.original_receipt.read_text(encoding="utf-8"))
    crosswalk = json.loads(args.crosswalk.read_text(encoding="utf-8"))
    if receipt.get("canonical_schema_commit") != "aece827964c785be77b088c3c61255a2d07fd9a9":
        raise SystemExit("canonical schema commit is not the reviewed 0.4.1 pin")
    if receipt.get("schema_aggregate_sha256") != crosswalk.get("new_schema_sha256"):
        raise SystemExit("schema digest mismatch")
    pins = {row["filename"]: row["source_sha256"] for row in crosswalk["benchmarks"]}
    index = mappings(args.schema_root)
    latest_keys = {(item["benchmark"], item["source_rule"]) for item in receipt["regression_ids"]}
    rows = []
    for item in original["regression_ids"]:
        path = next(args.source_root.rglob(item["benchmark"]))
        if source_hash(path) != pins[item["benchmark"]]:
            raise SystemExit("source ZIP hash mismatch: " + item["benchmark"])
        classified = classify(item, args.source_root, index)
        key = (item["benchmark"], item["source_rule"])
        classified["latest_status"] = "blocked" if key in latest_keys else "converted"
        if classified["latest_status"] == "converted":
            classified["decision"] = "recovered"
        rows.append(classified)
    rows.sort(key=lambda row: (row["decision"], row["benchmark"], row["source_rule"]))
    counts = Counter(row["decision"] for row in rows)
    families = Counter("unique" if row["source_expression"] == "unique" else "collected_field" for row in rows)
    result = {
        "format": "scap-ng-0.4.1-issue59-datatype-recovery/1",
        "canonical_schema_commit": "aece827964c785be77b088c3c61255a2d07fd9a9",
        "schema_aggregate_sha256": receipt["schema_aggregate_sha256"],
        "source_repository": receipt["source_repository"],
        "source_commit": receipt["source_commit"],
        "source_benchmarks": receipt["source_benchmarks"],
        "input_receipt_sha256": source_hash(args.receipt),
        "original_regression_receipt_sha256": source_hash(args.original_receipt),
        "source_zip_hashes_verified": True,
        "counts": dict(sorted(counts.items())),
        "family_counts": dict(sorted(families.items())),
        "proof_status": "UNVERIFIED",
        "scanner_equivalent": False,
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"counts": result["counts"], "family_counts": result["family_counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
