#!/usr/bin/env python3
"""Export immutable original 0.3 OVAL source-semantics vectors for 0.4 qualification.

This is a *source oracle*, not a claim that a native converter, RI, or SCC
currently produces matching outcomes. The 0.3 reference is copied verbatim
from vanderpol/scap-ng-research/tools/oval_result_truth_tables.py.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "tests/reference_v003/oval_result_truth_tables.py"
PINNED_GIT_BLOB = "dcd513cb3c5d75a2ecab4fc2575a0adc3bf75915"
VERSION = "oval-source-truth-v003.1"


def original_oracle():
    raw = REFERENCE.read_bytes()
    digest = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    if digest != PINNED_GIT_BLOB:
        raise ValueError("original 0.3 OVAL semantic oracle has changed")
    return runpy.run_path(str(REFERENCE))


def build_vectors():
    o = original_oracle()
    flags = o["SET_FLAGS"]
    result_values = ("true", "false", "error", "unknown",
                     "not evaluated", "not applicable")
    set_cases = [
        {"source_operator": operator,
         "native_operator": {"UNION": "union", "INTERSECTION": "intersection",
                             "COMPLEMENT": "difference"}[operator],
         "first_flag": first, "second_flag": second,
         "expected_flag": o["combine_set_flags"](operator, first, second)}
        for operator, first, second in itertools.product(
            ("UNION", "INTERSECTION", "COMPLEMENT"), flags, flags)
    ]
    filter_cases = [
        {"action": action, "state_result": outcome,
         "expected": o["apply_filter_state_result"](action, outcome)}
        for action, outcome in itertools.product(
            ("include", "exclude"), result_values)
    ]
    populations = (
        {"exists": 0, "does_not_exist": 0, "error": 0, "not_collected": 0},
        {"exists": 1, "does_not_exist": 0, "error": 0, "not_collected": 0},
        {"exists": 2, "does_not_exist": 0, "error": 0, "not_collected": 0},
        {"exists": 0, "does_not_exist": 1, "error": 0, "not_collected": 0},
        {"exists": 0, "does_not_exist": 0, "error": 1, "not_collected": 0},
        {"exists": 0, "does_not_exist": 0, "error": 0, "not_collected": 1},
        {"exists": 1, "does_not_exist": 0, "error": 1, "not_collected": 0},
        {"exists": 1, "does_not_exist": 1, "error": 0, "not_collected": 0},
    )
    existence_cases = [
        {"source_mode": mode, "population": population,
         "expected": o["aggregate_existence"](mode, **population)}
        for mode, population in itertools.product(
            ("all_exist", "any_exist", "at_least_one_exists",
             "none_exist", "only_one_exists"), populations)
    ]
    operator_cases = [
        {"operator": operator, "operands": [first, second],
         "expected": o["aggregate_operator"](operator, [first, second])}
        for operator, first, second in itertools.product(
            ("AND", "OR", "XOR", "ONE"), result_values, result_values)
    ]
    return {
        "schema": VERSION,
        "source": {
            "repository": "vanderpol/scap-ng-research",
            "file": "tools/oval_result_truth_tables.py",
            "git_blob_sha1": PINNED_GIT_BLOB,
            "provenance": "original 0.3 result truth-table contract",
        },
        "qualification": "OVAL_SOURCE_ONLY_NOT_NATIVE_OR_SCANNER_EQUIVALENCE",
        "set_flag_cases": set_cases,
        "filter_cases": filter_cases,
        "existence_cases": existence_cases,
        "boolean_operator_cases": operator_cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    data = build_vectors()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "schema": VERSION,
        "set_flags": len(data["set_flag_cases"]),
        "filters": len(data["filter_cases"]),
        "existence": len(data["existence_cases"]),
        "boolean": len(data["boolean_operator_cases"]),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
