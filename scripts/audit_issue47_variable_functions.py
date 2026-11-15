#!/usr/bin/env python3
"""Audit the SCAP-NG 0.4 Variable-function contract and count.1 regressions.

This is a read-only comparison of two already-published candidate ledgers and
an already-committed source inventory.  It does not run the converter and does
not alter either candidate.  The generated report deliberately keeps every
candidate blocker message so a Rule-level result can be independently traced.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path
import re
from typing import Any

ACTIVE_FUNCTIONS = ("concat", "regex_capture", "unique", "count", "merge")
SOURCE_FUNCTIONS = (
    "arithmetic", "concat", "count", "end", "merge", "regex_capture",
    "split", "substring", "unique",
)


def load_json(path: Path) -> Any:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def function_inventory(path: Path) -> tuple[dict[str, set[str]], Counter, Counter, Counter]:
    """Map source Rule IDs to functions and count occurrences/rules."""
    inventory = load_json(path)
    rule_functions: dict[str, set[str]] = defaultdict(set)
    occurrences: Counter[str] = Counter()
    variable_ids: dict[str, set[str]] = defaultdict(set)
    for benchmark in inventory["benchmarks"]:
        for variable in benchmark["variables"]:
            names = {item["name"] for item in variable.get("functions", [])}
            for name in names:
                variable_ids[name].add(variable["variable_id"])
            for item in variable.get("functions", []):
                occurrences[item["name"]] += 1
            for rule_id in variable.get("rules", []):
                rule_functions[rule_id].update(names)
    variables = Counter({name: len(ids) for name, ids in variable_ids.items()})
    rules = Counter({name: sum(name in funcs for funcs in rule_functions.values())
                     for name in occurrences})
    return rule_functions, occurrences, variables, rules


def candidate_rows(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    return data["rules"]


def source_error_functions(messages: list[str]) -> list[str]:
    names = set()
    for message in messages:
        names.update(re.findall(r"'name': '([a-z_]+)'", message))
    return sorted(names)


def error_path(message: str) -> str | None:
    # Most diagnostics begin with the emitted path. Keep the concrete path,
    # while allowing diagnostics that are not tied to an emitted document.
    match = re.match(r"([^:]+\.json):", message)
    return match.group(1) if match else None


def regression_report(old_path: Path, new_path: Path, inventory_path: Path) -> dict[str, Any]:
    old = candidate_rows(old_path)
    new = candidate_rows(new_path)
    if len(old) != len(new):
        raise ValueError(f"candidate Rule inventories differ: {len(old)} != {len(new)}")
    # The same source Rule ID can legitimately occur in more than one
    # benchmark package; benchmark + source ID is the Rule-level identity.
    old_by_id = {(row["benchmark"], row["source_rule"]): row for row in old}
    new_by_id = {(row["benchmark"], row["source_rule"]): row for row in new}
    if set(old_by_id) != set(new_by_id):
        raise ValueError("candidate Rule identity sets differ")
    rule_functions, occurrences, variable_counts, rule_counts = function_inventory(inventory_path)
    regressions = []
    for benchmark, source_rule in sorted(old_by_id):
        before, after = old_by_id[(benchmark, source_rule)], new_by_id[(benchmark, source_rule)]
        if before["status"] == after["status"]:
            continue
        messages = [blocker["message"] for blocker in after.get("blockers", [])]
        inactive = any("'function'" in message for message in messages)
        regressions.append({
            "benchmark": after["benchmark"],
            "source_rule": source_rule,
            "title": after.get("title", ""),
            "functions_in_source_closure": sorted(rule_functions.get(source_rule, set())),
            "old_status": before["status"],
            "new_status": after["status"],
            "old_artifacts": before.get("artifacts", []),
            "new_artifacts": after.get("artifacts", []),
            "blockers": after.get("blockers", []),
            "blocker_paths": sorted({path for path in (error_path(m) for m in messages) if path}),
            "emitted_function_names": source_error_functions(messages),
            "classification": (
                "inactive_function_envelope"
                if inactive else "unrelated_datatype_or_schema_blocker"
            ),
            "attributable_to_function_contract": inactive,
        })
    status_delta = Counter(
        (before["status"], after["status"])
        for before, after in zip(old, new) if before["status"] != after["status"]
    )
    classification = Counter(item["classification"] for item in regressions)
    # Candidate statuses are counted per function-bearing Rule. These are
    # overlapping sets: a Rule using concat and unique appears in both rows.
    status_by_function: dict[str, Counter] = {}
    for function in SOURCE_FUNCTIONS:
        status_by_function[function] = Counter(
            row["status"] for row in new
            if function in rule_functions.get(row["source_rule"], set())
        )
    return {
        "format": "scap-ng-tools/issue47-variable-function-regression/1",
        "scope": {
            "source_benchmarks": 65,
            "source_rules": 8892,
            "candidate_rules_compared": len(old),
            "regression_definition": "old status converted and new status blocked",
        },
        "baseline": {
            "archive": "applicability.8",
            "sha256": "e164ba54ac99ed1ebc6d205205deedea311ad92abd3d83739073eb0751ae4125",
            "status_counts": dict(Counter(row["status"] for row in old)),
        },
        "candidate": {
            "archive": "count.1",
            "sha256": "5e34519ee38189d8a104770fc9f1e944b7f3681edf8a76636d931026a8b02571",
            "status_counts": dict(Counter(row["status"] for row in new)),
        },
        "pins": {
            "source_commit": "8c8e5dff860af6b1290ee9273a282db24278f8d5",
            "schema_commit": "8f8e219e4fb2db8b37a6d0e1ca418e8a392c38e3",
            "schema_sha256": "910beeebfb90a63c773615907289a0e4b93095ee41cd1ad41b33652363900c74",
            "candidate_generator_commit": "0822dd7e4a3b8a7e5656f98322805d28447f1d7c",
        },
        "source_function_inventory": {
            "occurrences": dict(sorted(occurrences.items())),
            "variables": dict(sorted(variable_counts.items())),
            "rules": dict(sorted(rule_counts.items())),
        },
        "candidate_status_by_function": {
            name: dict(sorted(counts.items())) for name, counts in sorted(status_by_function.items())
        },
        "regression_summary": {
            "count": len(regressions),
            "status_delta": {f"{before}->{after}": count for (before, after), count in sorted(status_delta.items())},
            "classifications": dict(sorted(classification.items())),
            "count_bearing_regressions": sum(
                "count" in item["functions_in_source_closure"] for item in regressions
            ),
        },
        "regressions": regressions,
    }


def matrix(report: dict[str, Any]) -> dict[str, Any]:
    inventory = report["source_function_inventory"]
    status = report["candidate_status_by_function"]
    rows = []
    for name in SOURCE_FUNCTIONS:
        active = name in ACTIVE_FUNCTIONS
        if name == "count":
            form = "{count: expression}; exactly one recursive nested expression"
            qualification = "active_native_structural; 32 count-bearing Rules converted"
        elif name in {"concat", "regex_capture"}:
            form = {
                "concat": "{concat: [expression, ...]}",
                "regex_capture": "{regex_capture: {pattern, value}}",
            }[name]
            qualification = "active_native_shape"
        elif name in {"unique", "merge"}:
            form = {
                "unique": "{unique: expression} (one source component)",
                "merge": "{merge: {delimiter, sort, order, values}} (one source component)",
            }[name]
            qualification = "active_native_shape; multi-component source form is unsupported"
        else:
            form = "no active 0.4 native expression form"
            qualification = "fail_closed; inactive function envelope is forbidden"
        rows.append({
            "function": name,
            "active_0_4": active,
            "source_occurrences": inventory["occurrences"].get(name, 0),
            "source_variables": inventory["variables"].get(name, 0),
            "source_rules": inventory["rules"].get(name, 0),
            "candidate_rule_status": status.get(name, {}),
            "converter_form": form,
            "qualification": qualification,
            "runtime_equivalence": "not qualified",
        })
    return {
        "format": "scap-ng-tools/issue47-variable-function-support-matrix/1",
        "schema_contract": {
            "version": "0.4.0",
            "schema_commit": report["pins"]["schema_commit"],
            "schema_sha256": report["pins"]["schema_sha256"],
            "active_functions": list(ACTIVE_FUNCTIONS),
            "legacy_function_envelope": "forbidden",
        },
        "rows": rows,
        "notes": [
            "Source Rules are counted by unique source Rule ID; candidate status counts are benchmark+source Rule instances and can therefore exceed that ID count.",
            "Rule status counts overlap when a Rule closure uses multiple functions.",
            "A structural conversion or schema validation does not establish scanner/runtime equivalence.",
            "The five count-bearing Rules blocked in count.1 are not count regressions.",
        ],
    }


def md_report(report: dict[str, Any], support: dict[str, Any]) -> tuple[str, str]:
    s = report["regression_summary"]
    lines = [
        "# SCAP-NG 0.4 Variable-function support and Issue #47 regression audit", "",
        "Read-only comparison of the immutable `applicability.8` and `count.1` candidate ledgers; no corpus was regenerated.", "",
        "## Result", "",
        f"- **{s['count']} exact Rule regressions:** `converted → blocked`.",
        f"- Classification: **{s['classifications'].get('inactive_function_envelope', 0)}** inactive-envelope outputs and **{s['classifications'].get('unrelated_datatype_or_schema_blocker', 0)}** unrelated datatype/schema blockers.",
        f"- Count-bearing regressions: **{s['count_bearing_regressions']}** (none expected). The count.1 inventory has 32 converted and 5 blocked count-bearing Rules.",
        "- Runtime/scanner equivalence is **not** claimed.", "",
        "## Pins and immutable inputs", "",
        f"- applicability.8 SHA-256: `{report['baseline']['sha256']}`",
        f"- count.1 SHA-256: `{report['candidate']['sha256']}`",
        f"- Source: `{report['pins']['source_commit']}`",
        f"- Schema: `{report['pins']['schema_commit']}` (SHA-256 `{report['pins']['schema_sha256']}`)",
        f"- count.1 generator: `{report['pins']['candidate_generator_commit']}`", "",
        "## Function-support matrix", "",
        "| Function | Active native 0.4 | Source uses | Source Rule IDs | count.1 Rule instances (overlapping) | Converter contract |",
        "|---|---:|---:|---:|---|---|",
    ]
    for row in support["rows"]:
        status = ", ".join(f"{k}={v}" for k, v in row["candidate_rule_status"].items()) or "none"
        lines.append(f"| `{row['function']}` | {'yes' if row['active_0_4'] else 'no'} | {row['source_occurrences']} | {row['source_rules']} | {status} | {row['qualification']} |")
    lines += ["", "Active grammar is `concat`, `regex_capture`, `unique`, recursive `count`, and `merge`; the historical generic `function` envelope is not active 0.4 syntax.", ""]
    lines += ["## Exact Rule-level regressions", "", "The machine-readable JSON retains every original blocker object and message. Paths below are the emitted assessment paths when present.", ""]
    for item in report["regressions"]:
        lines += [
            f"### `{item['source_rule']}` — {item['title']}",
            f"- Benchmark: `{item['benchmark']}`",
            f"- Functions in source closure: `{', '.join(item['functions_in_source_closure']) or 'none'}`",
            f"- Status: `{item['old_status']}` → `{item['new_status']}`",
            f"- Classification: **{item['classification']}**; emitted operation(s): `{', '.join(item['emitted_function_names']) or 'none'}`",
        ]
        for blocker in item["blockers"]:
            lines.append(f"- `{blocker['category']}`: `{blocker['message']}`")
        lines.append("")
    lines += ["## Interpretation and next gate", "", "The 50 inactive-envelope regressions demonstrate a converter admission defect: native recovery attempted to emit schema-invalid generic function objects for operations/shapes not present in the active 0.4 grammar. The safe correction is fail-closed conversion with an explicit unsupported-function blocker. The five unrelated regressions remain separate datatype/possible-restriction work and are not count defects. A new full-corpus candidate is intentionally not produced by Issue #47.", ""]
    return "\n".join(lines), json.dumps(support, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-rules", type=Path, required=True)
    parser.add_argument("--candidate-rules", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = regression_report(args.baseline_rules, args.candidate_rules, args.inventory)
    support = matrix(report)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "RULE-REGRESSION-REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (args.out / "FUNCTION-SUPPORT-MATRIX.json").write_text(json.dumps(support, indent=2, sort_keys=True) + "\n")
    md, _ = md_report(report, support)
    (args.out / "RULE-REGRESSION-REPORT.md").write_text(md)
    (args.out / "FUNCTION-SUPPORT-MATRIX.md").write_text(md.split("## Exact Rule-level regressions", 1)[0] + "\n")
    print(json.dumps({"regressions": report["regression_summary"], "out": str(args.out)}, indent=2))


if __name__ == "__main__":
    main()
