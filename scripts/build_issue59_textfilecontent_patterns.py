#!/usr/bin/env python3
"""Classify the blocked Issue #59 textfilecontent subexpression patterns.

The pinned OVAL 5.12.3 schemas deliberately distinguish a collected
textfilecontent Item subexpression (EntityItemAnySimpleType) from the State
subexpression (EntityStateAnySimpleType).  A regex pattern is lexical
matching, not a typed conversion.  This report therefore fails closed for
all patterns unless a reviewed source operation supplies a conversion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_COMMIT = "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706"
SCHEMA_COMMIT = "aece827964c785be77b088c3c61255a2d07fd9a9"
SCHEMA_DIGEST = "578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829"


def local(node):
    return node.tag.rsplit("}", 1)[-1]


def capture_count(pattern):
    # Evidence-only count: identify capturing parentheses without attempting
    # to interpret the complete OVAL regular-expression dialect.
    count = 0
    escaped = False
    for index, char in enumerate(pattern or ""):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "(":
            # OVAL/Perl-style (?i), (?:...), (?=...), (?!...) and
            # (?<=...) are assertions or groups without a captured value;
            # named (?P<name>...) is a capture.
            prefix = pattern[index:index + 3]
            if not prefix.startswith("(?") or prefix.startswith("(?P<"):
                count += 1
    return count


def source_index(source_root, benchmark):
    path = next(source_root.rglob(benchmark))
    with zipfile.ZipFile(path) as archive:
        xml_name = next(name for name in archive.namelist() if name.endswith(".xml"))
        root = ET.fromstring(archive.read(xml_name))
    return {node.get("id"): node for node in root.iter() if node.get("id")}, root


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    rows = [row for row in ledger["rows"]
            if row.get("fields") and row["fields"][0].get("capability") == "independent.textfilecontent"
            and row.get("decision") == "blocked"]
    groups = defaultdict(list)
    for row in rows:
        by_id, root = source_index(args.source_root, row["benchmark"])
        variable = by_id[row["source_variable_id"]]
        component = next(node for node in variable.iter() if local(node) == "object_component")
        def pattern_nodes(object_id, seen=None):
            seen = set() if seen is None else seen
            if object_id in seen:
                return []
            seen.add(object_id)
            obj = by_id[object_id]
            direct = [node for node in obj if local(node) == "pattern"]
            refs = [node.text.strip() for node in obj.iter()
                    if local(node) == "object_reference" and (node.text or "").strip()]
            return direct + [pattern for ref in refs for pattern in pattern_nodes(ref, seen)]
        patterns = pattern_nodes(component.get("object_ref"))
        if not patterns:
            raise SystemExit("textfilecontent Object graph has no pattern: " + row["source_rule"])
        consumers = []
        for node in root.iter():
            if node.get("var_ref") == row["source_variable_id"]:
                consumers.append({"element": local(node), "operation": node.get("operation", "equals"),
                                  "datatype": node.get("datatype")})
        for pattern in patterns:
            key = (pattern.text or "", tuple(sorted(pattern.attrib.items())))
            groups[key].append({
                "benchmark": row["benchmark"],
                "source_rule": row["source_rule"],
                "source_rule_sha256": row["source_rule_sha256"],
                "source_variable_id": row["source_variable_id"],
                "source_variable_datatype": row["source_variable_datatype"],
                "source_object_id": component.get("object_ref"),
                "consumers": consumers,
            })
    patterns = []
    for number, ((text, attrs), members) in enumerate(sorted(groups.items(), key=lambda item: (item[0][0], item[0][1])), 1):
        patterns.append({
            "pattern_number": number,
            "pattern": text,
            "pattern_attributes": dict(attrs),
            "capture_group_count_observed": capture_count(text),
            "source_variable_datatypes": sorted({m["source_variable_datatype"] for m in members}),
            "rules": sorted(members, key=lambda m: (m["benchmark"], m["source_rule"])),
            "decision": "retain_blocker",
            "owner_decision_required": "Approve a typed collected Item/result boundary and RI behavior for textfilecontent.subexpression, or provide a reviewed source operation that performs lexical conversion before the Variable expression. The source Variable datatype is a compliance constraint, not a converter cast.",
        })
    result = {
        "format": "scap-ng-0.4.1-issue59-textfilecontent-patterns/1",
        "canonical_schema_commit": SCHEMA_COMMIT,
        "schema_aggregate_sha256": SCHEMA_DIGEST,
        "oval_community_commit": OVAL_COMMIT,
        "source_regressions": len(rows),
        "distinct_source_patterns": len(patterns),
        "recovered": 0,
        "retained_blocked": len(rows),
        "scanner_equivalent": False,
        "evidence": {
            "item_subexpression": "oval-schemas/independent-system-characteristics-schema.xsd:383-387 EntityItemAnySimpleType",
            "state_subexpression": "oval-schemas/independent-definitions-schema.xsd:1910-1914 EntityStateAnySimpleType",
            "pattern_entity": "oval-schemas/independent-definitions-schema.xsd: pattern is EntityStateStringType and operation is pattern match",
            "variable_datatype": "oval-schemas/oval-definitions-schema.xsd:533-534; value set must comply with datatype and error otherwise; no conversion is specified",
            "variable_guidance": "guidelines/oval-schema-documentation/oval-definitions-schema.rst:721",
        },
        "patterns": patterns,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("source_regressions", "distinct_source_patterns", "recovered", "retained_blocked")}, sort_keys=True))


if __name__ == "__main__":
    main()
