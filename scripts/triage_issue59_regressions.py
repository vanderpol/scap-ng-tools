#!/usr/bin/env python3
"""Produce a fail-closed, source-ID-preserving triage ledger from Issue #59 rebuild.

Input is the existing signed-source Rule-ID rebuild JSON, not fabricated source
types or scanner observations. This script NEVER promotes conversion proof.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

FIELDNAMES = (
    "benchmark", "source_rule", "source_rule_sha256",
    "blocker_category", "primary_blocker", "type_family",
    "original_proof_level", "new_proof_level",
    "source_value_domain", "explicit_native_mapping", "oracle_status",
)
TYPE_FAMILIES = (
    ("collected_field", ("ambiguous allowed datatype", "collected field")),
    ("unique", ("unique requires", "unique input")),
    ("split", ("split requires", "split input")),
    ("substring", ("substring requires", "substring input")),
)


def family_for(message: str) -> str:
    value = message.lower()
    for family, tokens in TYPE_FAMILIES:
        if any(token in value for token in tokens):
            return family
    return "unclassified"


def build_inventory(receipt: dict) -> tuple[list[dict], dict]:
    if receipt.get("format") != "scap-ng-0.4.1-source-rule-identity-rebuild/1":
        raise ValueError("unsupported or absent signed-source receipt format")
    if receipt.get("scanner_equivalent") is not False:
        raise ValueError("receipt must explicitly disclaim scanner equivalence")
    if receipt.get("owner_scope") != {
        "active": 7990, "owner_excluded_sql": 209,
        "historical_windows_2012": 693,
    }:
        raise ValueError("unexpected or incomplete original owner scope")
    if not isinstance(receipt.get("regression_ids"), list):
        raise ValueError("missing original Rule-ID regression list")
    if receipt.get("newly_blocked_from_converted") != len(receipt["regression_ids"]):
        raise ValueError("regression count does not match source Rule-ID ledger")

    seen = set()
    rows = []
    for item in receipt["regression_ids"]:
        if item.get("from") != "converted" or item.get("to") != "blocked":
            raise ValueError("unexpected regression transition; triage manually")
        benchmark = item.get("benchmark")
        source_rule = item.get("source_rule")
        message = item.get("primary_blocker")
        if not all(isinstance(v, str) and v for v in (benchmark, source_rule, message)):
            raise ValueError("missing original source ID or blocker diagnostic")
        key = (benchmark, source_rule)
        if key in seen:
            raise ValueError("duplicate source Rule identity: " + str(key))
        seen.add(key)
        rows.append({
            "benchmark": benchmark,
            "source_rule": source_rule,
            "source_rule_sha256": item.get("source_rule_sha256") or "",
            "blocker_category": item.get("blocker_category") or "",
            "primary_blocker": message,
            "type_family": family_for(message),
            "original_proof_level": item.get("original_proof_level") or "none",
            "new_proof_level": item.get("new_proof_level") or "none",
            "source_value_domain": "UNDETERMINED",
            "explicit_native_mapping": "UNDETERMINED",
            "oracle_status": "NOT_RUN",
        })
    rows.sort(key=lambda r: (r["type_family"], r["benchmark"], r["source_rule"]))
    counts = dict(sorted(Counter(r["type_family"] for r in rows).items()))
    return rows, {
        "format": "scap-ng-0.4.1-regression-triage/1",
        "input_schema_aggregate_sha256": receipt.get("schema_aggregate_sha256"),
        "input_source_commit": receipt.get("source_commit"),
        "regressions": len(rows),
        "family_counts": counts,
        "scanner_equivalent": False,
        "proof_status": "UNVERIFIED",
        "all_values_and_mappings_require_independent_source_evidence": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Issue #59 rebuild JSON")
    parser.add_argument("--csv", type=Path, required=True, help="New triage CSV")
    parser.add_argument("--summary", type=Path, required=True, help="New JSON receipt")
    args = parser.parse_args()
    if args.csv == args.summary or args.csv.exists() or args.summary.exists():
        parser.error("outputs must be distinct and must not already exist")
    rows, summary = build_inventory(json.loads(args.input.read_text(encoding="utf-8")))
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    args.summary.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
