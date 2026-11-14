#!/usr/bin/env python3
"""Audit the remaining 23 non-textfilecontent collected-field holds.

This report is deliberately non-converting: it preserves the source Rule
identities and records the pinned OVAL Item/State contracts and missing
runtime evidence needed before a typed consumer-boundary implementation.
"""
from __future__ import annotations
import argparse, hashlib, json, zipfile
from collections import Counter, defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET

SCHEMA_COMMIT = "aece827964c785be77b088c3c61255a2d07fd9a9"
SCHEMA_DIGEST = "578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829"
OVAL_COMMIT = "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706"

def local(node): return node.tag.rsplit("}", 1)[-1]

def load(source_root, benchmark):
    path = next(source_root.rglob(benchmark))
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read(next(n for n in archive.namelist() if n.endswith(".xml"))))
    return root, {n.get("id"): n for n in root.iter() if n.get("id")}

def graph_signature(by_id, object_id, seen=None):
    seen = set() if seen is None else seen
    if object_id in seen: return {"objects": [], "patterns": [], "selectors": []}
    seen.add(object_id)
    node = by_id[object_id]
    patterns = [{"text": n.text or "", "attributes": dict(sorted(n.attrib.items()))}
                for n in node if local(n) == "pattern"]
    selectors = [{"element": local(n), "text": (n.text or "").strip(),
                  "attributes": dict(sorted(n.attrib.items()))}
                 for n in node if local(n) not in {"set", "object_reference", "filter"}]
    result = {"objects": [object_id], "patterns": patterns, "selectors": selectors}
    for ref in node.iter():
        if local(ref) == "object_reference" and (ref.text or "").strip():
            child = graph_signature(by_id, ref.text.strip(), seen)
            result["objects"].extend(child["objects"])
            result["patterns"].extend(child["patterns"])
            result["selectors"].extend(child["selectors"])
    return result

def item_state_evidence(capability, field):
    if capability == "independent.shellcommand":
        return {
            "item": "EntityItemAnySimpleType",
            "state": "EntityStateAnySimpleType",
            "source_pointer": "OVAL 5.12.3 independent-system-characteristics-schema.xsd:383-387; independent-definitions-schema.xsd:1140-1142",
            "interpretation": "Regex capture is lexical; no source operation types the captured subexpression.",
        }
    if capability == "windows.registry":
        return {
            "item": "EntityItemAnySimpleType with runtime datatype attribute",
            "state": "EntityStateAnySimpleType",
            "source_pointer": "OVAL 5.12.3 windows-system-characteristics-schema.xsd:2410-2413; windows-definitions-schema.xsd:5589-5594",
            "interpretation": "Item datatype depends on registry value kind; source Object/Variable does not provide the runtime Item datatype.",
        }
    return {
        "item": "EntityItemAnySimpleType",
        "state": "EntityStateAnySimpleType",
        "source_pointer": "OVAL 5.12.3 independent-system-characteristics-schema.xsd:190-194/221-225; independent-definitions-schema.xsd:562-566/668-672",
        "interpretation": "Environment Object selectors do not establish the runtime value datatype.",
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ledger", type=Path, required=True)
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--original-receipt", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    ledger = json.loads(args.ledger.read_text())
    original = json.loads(args.original_receipt.read_text())
    original_rows = {(r["benchmark"], r["source_rule"]): r for r in original["regression_ids"]}
    rows = [r for r in ledger["rows"] if r.get("decision") == "blocked" and r.get("fields")
            and r["fields"][0].get("capability") != "independent.textfilecontent"]
    records = []
    for row in rows:
        root, by_id = load(args.source_root, row["benchmark"])
        field = row["fields"][0]
        variable = by_id[row["source_variable_id"]]
        component = next(n for n in variable.iter() if local(n) == "object_component")
        signature = graph_signature(by_id, component.get("object_ref"))
        consumers = []
        for node in root.iter():
            if node.get("var_ref") == row["source_variable_id"]:
                consumers.append({"element": local(node), "operation": node.get("operation", "equals"),
                                  "datatype": node.get("datatype"), "var_check": node.get("var_check")})
        capability = field["capability"]
        source_record = original_rows.get((row["benchmark"], row["source_rule"]))
        if source_record is None or source_record.get("from") != "converted" or source_record.get("to") != "blocked":
            raise SystemExit("missing original converted-to-blocked Rule receipt: " + row["source_rule"])
        records.append({
            "benchmark": row["benchmark"], "source_rule": row["source_rule"],
            "original_status": {"from": source_record["from"], "to": source_record["to"]},
            "original_blocker_category": source_record.get("blocker_category"),
            "original_blocker": source_record.get("primary_blocker"),
            "original_proof_level": source_record.get("original_proof_level"),
            "source_rule_sha256": row["source_rule_sha256"],
            "source_variable_id": row["source_variable_id"],
            "source_variable_datatype": row["source_variable_datatype"],
            "source_expression": row["source_expression"], "source_field": field["native_field"],
            "capability": capability, "source_object_id": field["source_object_id"],
            "object_graph": signature, "consumer_operations": consumers,
            "item_state_evidence": item_state_evidence(capability, field["native_field"]),
            "explicit_source_conversion": False,
            "decision": "retain_blocker",
            "owner_decision_required": {
                "independent.shellcommand": "Approve operation-directed interpretation of raw capture values with exact invalid lexical/status/multiplicity/var_check semantics, or provide OVAL/RI truth vectors.",
                "windows.registry": "Provide runtime Item datatype/type/status vectors for this registry value and define comparison interpretation; the source Object does not pin REG_* kind.",
                "independent.environmentvariable": "Provide runtime Item datatype/status vectors and operation-directed comparison semantics; the source Object only selects name/pid.",
            }[capability],
        })
    records.sort(key=lambda r: (r["capability"], r["benchmark"], r["source_rule"]))
    shapes = defaultdict(list)
    for record in records:
        shape = json.dumps({"capability": record["capability"], "object_graph": record["object_graph"]}, sort_keys=True)
        shapes[shape].append(record["source_rule"])
    result = {
        "format": "scap-ng-0.4.1-issue59-remaining-collected-field-audit/1",
        "canonical_schema_commit": SCHEMA_COMMIT, "schema_aggregate_sha256": SCHEMA_DIGEST,
        "oval_community_commit": OVAL_COMMIT, "source_regressions": len(records),
        "distinct_source_shapes": len(shapes), "recovered": 0, "retained_blocked": len(records),
        "scanner_equivalent": False, "source_statuses_preserved": True,
        "family_counts": dict(sorted(Counter(r["capability"] for r in records).items())),
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("source_regressions", "distinct_source_shapes", "family_counts")}, sort_keys=True))

if __name__ == "__main__": main()
