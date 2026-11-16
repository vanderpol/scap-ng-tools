#!/usr/bin/env python3
"""Read-only, same-source 0.4.0 -> 0.4.1 65-benchmark regression audit.

Restore owner's SQL and Windows 2012 exclusions before comparing admission.
Benchmark counts are *not* Rule-ID parity and do not establish RI/SCC results.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CROSSWALK = ROOT / "docs/evidence/issue59/full65-crosswalk.json"
NEW = ROOT / "docs/evidence/issue59/full65-conversion-v041.json"
SQL = ROOT / "docs/evidence/issue28/SQL-EXCLUSIONS.json"
FIELDS = ("converted", "blocked", "manual_only")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def totals(rows, key):
    result = Counter()
    for row in rows:
        result["source_rules"] += row["source_rules"]
        for field in FIELDS:
            result[field] += row[key].get(field, 0)
        result["intentionally_excluded"] += row[key].get("intentionally_excluded", 0)
    return dict(result)


def audit(crosswalk_path=CROSSWALK, new_path=NEW, sql_path=SQL):
    crosswalk, fresh, excluded = map(load, (crosswalk_path, new_path, sql_path))
    old_rows, new_rows = crosswalk["benchmarks"], fresh["benchmarks"]
    by_new = {row["file"]: row for row in new_rows}
    if len(old_rows) != 65 or len(new_rows) != 65 or len(by_new) != 65:
        raise ValueError("expected 65 unique original benchmark source ZIPs")
    by_old = {row["filename"]: row for row in old_rows}
    if len(by_old) != 65 or set(by_old) != set(by_new):
        raise ValueError("0.4.1 benchmark set differs from old same-source ledger")
    sql_names = {row["filename"] for row in excluded["benchmarks"]}
    if len(sql_names) != 4 or not sql_names <= set(by_old):
        raise ValueError("owner SQL exclusion inventory missing or changed")
    server2012_names = {name for name in by_old if "Windows_2012_and_2012_R2" in name}
    if len(server2012_names) != 2 or sql_names & server2012_names:
        raise ValueError("historically excluded Windows 2012 source set changed")

    categories = {"active": [], "excluded_sql": [], "historical_windows_2012": []}
    for name, old in by_old.items():
        current = by_new[name]
        if (old["source_rules"] != current["source_rules"] or
                old["source_sha256"] != current["sha256"]):
            raise ValueError("pinned same-source identity drift: " + name)
        actual = current["summary"]["statuses"]
        if any(old["new_0_4_1"].get(k, 0) != actual.get(k, 0) for k in FIELDS):
            raise ValueError("new admission evidence differs from crosswalk: " + name)
        for version in ("old_0_4_0", "new_0_4_1"):
            count = sum(old[version].get(k, 0) for k in FIELDS)
            count += old[version].get("intentionally_excluded", 0)
            if count != old["source_rules"]:
                raise ValueError("unaccounted original Rules: " + name)
        group = ("excluded_sql" if name in sql_names else
                 "historical_windows_2012" if name in server2012_names else "active")
        categories[group].append(old)

    result = {"format": "scap-ng-issue59-owner-scoped-admission-regression/1",
              "source_identity": "original ZIP filename + SHA-256",
              "rule_id_equivalence": "NOT_PROVED_BY_BENCHMARK_COUNTS",
              "scanner_equivalence": "NOT_PROVED",
              "scope": {}}
    for group, rows in categories.items():
        before, after = totals(rows, "old_0_4_0"), totals(rows, "new_0_4_1")
        result["scope"][group] = {
            "benchmarks": len(rows), "old": before, "new": after,
            "delta": {key: after.get(key, 0) - before.get(key, 0)
                      for key in (*FIELDS, "intentionally_excluded")}}

    sql = result["scope"]["excluded_sql"]
    if (sql["old"]["source_rules"] != excluded["excluded_rules"] or
            sql["old"]["intentionally_excluded"] != excluded["excluded_rules"]):
        raise ValueError("SQL owner exclusions do not reconcile")
    if (result["scope"]["historical_windows_2012"]["old"]["source_rules"] != 693 or
            result["scope"]["active"]["old"]["source_rules"] != 7990):
        raise ValueError("historical owner-scope denominator changed")

    active = categories["active"]
    losses = [row for row in active if row["delta"]["converted"] < 0]
    gains = [row for row in active if row["delta"]["converted"] > 0]
    result["regression"] = {
        "benchmarks_with_lost_conversions": len(losses),
        "benchmarks_with_gained_conversions": len(gains),
        "gross_lost_converted": -sum(row["delta"]["converted"] for row in losses),
        "gross_gained_converted": sum(row["delta"]["converted"] for row in gains),
        "net_lost_converted": -result["scope"]["active"]["delta"]["converted"],
        "lost_by_benchmark": [
            {"benchmark": row["filename"],
             "old_converted": row["old_0_4_0"]["converted"],
             "new_converted": row["new_0_4_1"]["converted"],
             "lost": -row["delta"]["converted"]}
            for row in sorted(losses, key=lambda row: row["delta"]["converted"])],
    }
    result["nonregression_gate"] = {
        "pass": not losses and not result["scope"]["active"]["delta"]["blocked"] > 0,
        "limit": "benchmark-level admission only; requires separate per-Rule-ID proof"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enforce-nonregression", action="store_true",
                        help="fail on any active benchmark loss; does not prove Rule-ID parity")
    args = parser.parse_args()
    try:
        result = audit()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("Admission evidence integrity ERROR: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    if args.enforce_nonregression and not result["nonregression_gate"]["pass"]:
        print("HOLD: active 0.4.1 automated conversion coverage regressed",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
