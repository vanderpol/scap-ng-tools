#!/usr/bin/env python3
"""Fail-closed Definition-level gate for the pinned agnostic OVAL corpus.

Consumes a REAL newly generated RI definition-results.csv (46 complete rows).
It does NOT run conversion, invoke RI, or treat a stale receipt as execution.
Expected outcomes are a separate original-source-backed manifest, never
injected into the scanner or derived from scanner results at gate time.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path
import sys


def sha_file(path):
    return sha256(path.read_bytes()).hexdigest()


def compare(manifest, rows):
    expected = {entry["source_definition_id"]: entry for entry in manifest["definitions"]}
    if len(expected) != manifest["expected_total"] or len(expected) != 46:
        raise ValueError("invalid expected-Definition manifest: 46 unique Definitions required")
    if {k: sum(e["expected_outcome"] == k for e in expected.values())
        for k in ("true", "false", "unknown")} != manifest["expected_counts"]:
        raise ValueError("invalid source expected-outcome counts")
    observed, problems = {}, []
    for row in rows:
        if row.get("family") != "agnostic":
            continue
        identifier = row.get("source_id", "")
        if identifier in observed:
            problems.append({"source_id": identifier, "code": "duplicate_actual_definition"})
            continue
        observed[identifier] = row
        if identifier not in expected:
            problems.append({"source_id": identifier, "code": "unexpected_source_definition"})
            continue
        case = expected[identifier]
        if row.get("source_xml") != case["source_path"]:
            problems.append({"source_id": identifier, "code": "source_path_mismatch"})
        if row.get("source_xml_sha256") != case["source_sha256"]:
            problems.append({"source_id": identifier, "code": "source_xml_sha256_mismatch"})
        if row.get("execution_status") != "executed":
            problems.append({"source_id": identifier, "code": "not_executed",
                             "actual_status": row.get("execution_status", "")})
        elif row.get("actual_outcome") != case["expected_outcome"]:
            problems.append({"source_id": identifier, "code": "outcome_mismatch",
                             "expected": case["expected_outcome"],
                             "actual": row.get("actual_outcome", "")})
    for identifier in expected.keys() - observed.keys():
        problems.append({"source_id": identifier, "code": "missing_definition"})
    problems.sort(key=lambda x: (x["source_id"], x["code"]))
    return {
        "status": "PASS" if not problems else "FAIL",
        "expected_definitions": len(expected),
        "observed_agnostic_definitions": len(observed),
        "verified_expected_outcomes": len(expected) -
            len({p["source_id"] for p in problems if p["source_id"] in expected}),
        "source_expected_counts": manifest["expected_counts"],
        "problems": problems,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definition-results", type=Path, required=True)
    parser.add_argument("--expectations", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "docs/qualification/agnostic-self-assertion/expected-definitions.json")
    parser.add_argument("--receipt", type=Path,
                        help="Optional output JSON receipt; must not overwrite input")
    args = parser.parse_args()
    if args.receipt and args.receipt.resolve() in {
        args.definition_results.resolve(), args.expectations.resolve()}:
        parser.error("receipt path must not overwrite an input")
    manifest = json.loads(args.expectations.read_text())
    if manifest.get("source_commit") != "d91e6ba33841e3202dc27d3e0d469a7abd939b16":
        parser.error("source pin differs from independently reviewed expected results")
    with args.definition_results.open(newline="") as f:
        rows = list(csv.DictReader(f))
    result = compare(manifest, rows)
    result["source_commit"] = manifest["source_commit"]
    result["qualification_policy"] = manifest["qualifications"]
    result["expectations_sha256"] = sha_file(args.expectations)
    result["definition_results_sha256"] = sha_file(args.definition_results)
    result["execution_proof"] = "NOT_ESTABLISHED_BY_COMPARISON_ONLY"
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.receipt:
        if args.receipt.exists():
            parser.error("receipt already exists (immutable qualification receipt policy)")
        args.receipt.write_text(rendered)
    print(rendered, end="")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
