#!/usr/bin/env python3
"""Rebuild all 65 pinned STIG ZIPs and independently compare original Rule IDs.

Read-only qualification: pinned source/checksums, one active 0.4.1 schema,
per-Rule dispositions and blocker reasons. This is not RI/SCC equivalence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "8c8e5dff860af6b1290ee9273a282db24278f8d5"
CROSSWALK = ROOT / "docs/evidence/issue59/full65-crosswalk.json"
HISTORICAL_RULES = ROOT / "docs/evidence/issue28/ACTIVE-CANDIDATE-RULES.json.gz"
SQL_POLICY = ROOT / "docs/evidence/issue28/SQL-EXCLUSIONS.json"
OLD = {"converted": 6479, "blocked": 108, "manual_only": 1403}
RECORD_TYPES = ("converted", "blocked", "manual_only")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def hash_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as reader:
        for block in iter(lambda: reader.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git_revision(root):
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def expected_scope(crosswalk, sql_policy):
    rows = crosswalk["benchmarks"]
    if len(rows) != 65 or len({r["filename"] for r in rows}) != 65:
        raise ValueError("source crosswalk must contain 65 distinct filenames")
    sql = {entry["filename"] for entry in sql_policy["benchmarks"]}
    old_windows = {r["filename"] for r in rows if "Windows_2012_and_2012_R2" in r["filename"]}
    if len(sql) != 4 or len(old_windows) != 2 or sql & old_windows:
        raise ValueError("owner-excluded source benchmark inventory changed")
    if sql_policy["excluded_rules"] != 209:
        raise ValueError("owner's 209 SQLEXT exclusions changed")
    categories = {r["filename"]: "owner_excluded_sql" if r["filename"] in sql else
                  "historical_windows_2012" if r["filename"] in old_windows else "active"
                  for r in rows}
    if Counter(categories.values()) != {"active": 59, "owner_excluded_sql": 4,
                                         "historical_windows_2012": 2}:
        raise ValueError("active 59/4/2 source scope changed")
    if sum(r["source_rules"] for r in rows if categories[r["filename"]] == "active") != 7990:
        raise ValueError("active source denominator changed")
    return categories


def source_paths(source_root, crosswalk):
    by_name = defaultdict(list)
    for file in source_root.rglob("*.zip"):
        by_name[file.name].append(file)
    found = {}
    for row in crosswalk["benchmarks"]:
        name, expected = row["filename"], row["source_sha256"]
        candidates = by_name.get(name, [])
        if not candidates:
            raise ValueError("source ZIP is missing: " + name)
        matching = [p for p in candidates if hash_file(p) == expected]
        if not matching:
            raise ValueError("source ZIP SHA-256 mismatch: " + name)
        found[name] = sorted(matching)[0]
    return found


def rule_map(rows, *, label):
    result = {}
    for row in rows:
        key = (row["benchmark"], row["source_rule"])
        if key in result:
            raise ValueError(label + " has duplicated source Rule identity " + str(key))
        result[key] = row
    return result


def compare_rule_ids(old_rows, new_rows, categories):
    """Compare exact original Rule identity and prevent scope/status laundering."""
    old_map, new_map = rule_map(old_rows, label="historical"), rule_map(new_rows, label="new")
    expected_keys = {key for key in new_map if categories[key[0]] != "historical_windows_2012"}
    if set(old_map) != expected_keys:
        missing = sorted(set(old_map) - expected_keys)[:5]
        extra = sorted(expected_keys - set(old_map))[:5]
        raise ValueError("old/new Rule IDs differ (missing: %s; extra: %s)" % (missing, extra))
    transitions, blocked_cases = [], []
    old_counts, new_counts = Counter(), Counter()
    for key in sorted(expected_keys):
        old, new = old_map[key], new_map[key]
        category = categories[key[0]]
        earlier, latest = old["status"], new["status"]
        if (old.get("source_rule_sha256") and new.get("source_rule_sha256") and
                old["source_rule_sha256"] != new["source_rule_sha256"]):
            raise ValueError("source Rule XML identity drift: " + str(key))
        if category == "owner_excluded_sql":
            if earlier != "intentionally_excluded":
                raise ValueError("SQL Rule was not historically owner-excluded: " + str(key))
            continue
        if earlier not in RECORD_TYPES or latest not in RECORD_TYPES:
            raise ValueError("invalid active Rule disposition: " + str(key))
        old_counts[earlier] += 1
        new_counts[latest] += 1
        if latest == "blocked":
            cause = new.get("primary_blocker") or {}
            blocked_cases.append({"benchmark": key[0], "source_rule": key[1],
                                  "original_status": earlier,
                                  "category": cause.get("category", "unclassified"),
                                  "message": cause.get("message", "unclassified")})
        if earlier != latest:
            transitions.append({
                "benchmark": key[0], "source_rule": key[1], "from": earlier,
                "to": latest,
                "primary_blocker": ((new.get("primary_blocker") or {}).get("message")
                                     if latest == "blocked" else None),
                "blocker_category": ((new.get("primary_blocker") or {}).get("category")
                                     if latest == "blocked" else None),
                "source_rule_sha256": new.get("source_rule_sha256"),
                "original_proof_level": old.get("proof_level", "none"),
                "new_proof_level": new.get("proof_level", "none"),
            })
    if dict(old_counts) != OLD:
        raise ValueError("previous 59-benchmark active corpus disposition changed: " + str(dict(old_counts)))
    if sum(new_counts.values()) != 7990:
        raise ValueError("new 59-benchmark active Rule IDs incomplete")
    regressions = [r for r in transitions if r["from"] == "converted" and r["to"] != "converted"]
    return {"original": dict(sorted(old_counts.items())),
            "candidate": dict(sorted(new_counts.items())),
            "transitions": transitions,
            "blocked_rule_ids": blocked_cases,
            "blocker_category_counts": dict(sorted(Counter(row["category"] for row in blocked_cases).items())),
            "newly_blocked_from_converted": len(regressions),
            "regression_ids": regressions,
            "newly_converted_from_blocked": sum(r["to"] == "converted" and r["from"] == "blocked"
                                                for r in transitions),
            "nonregression_pass": not regressions,
            "scanner_equivalent": False}


def run_build(schema_root, source_root, crosswalk, categories, *, native_recovery):
    from scap_ng_tools.converter.direct04 import convert_benchmark
    zip_paths = source_paths(source_root, crosswalk)
    rows, totals = [], Counter()
    for index, item in enumerate(crosswalk["benchmarks"], 1):
        name = item["filename"]
        print(f"[{index:02d}/65] {name}", file=sys.stderr, flush=True)
        docs, trace, coverage = convert_benchmark(
            schema_root=schema_root, source=zip_paths[name],
            sha256_pin=item["source_sha256"], native_recovery=native_recovery)
        if coverage["summary"]["source_rules"] != item["source_rules"] or len(coverage["rules"]) != item["source_rules"]:
            raise ValueError("original Rule count drift: " + name)
        if coverage.get("scanner_evaluated") or coverage.get("coverage_promoted"):
            raise ValueError("forbidden scanner/proof promotion: " + name)
        for rule in coverage["rules"]:
            if rule.get("status") not in RECORD_TYPES or rule.get("proof_level") not in ("none", "authoring_validated"):
                raise ValueError("unexpected authoring qualification: " + name)
            rows.append({"benchmark": name, **rule})
        totals[categories[name]] += len(coverage["rules"])
        if coverage["summary"]["statuses"].get("converted", 0) and not docs:
            raise ValueError("converted Rules yielded no native authoring: " + name)
    if dict(totals) != {"active": 7990, "owner_excluded_sql": 209,
                         "historical_windows_2012": 693}:
        raise ValueError("owner-scoped source totals no longer reconcile")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enforce-nonregression", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; no overwrite is permitted")
    if git_revision(args.source_root) != SOURCE_COMMIT:
        parser.error("source library commit does not match pinned source")
    crosswalk, sql = read_json(CROSSWALK), read_json(SQL_POLICY)
    categories = expected_scope(crosswalk, sql)
    from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot
    snap = Pinned041SchemaSnapshot(args.schema_root)
    schema_digest = snap.manifest()["aggregate_sha256"]
    if schema_digest != crosswalk["new_schema_sha256"]:
        parser.error("canonical 0.4.1 aggregate digest differs from source receipt")
    with gzip.open(HISTORICAL_RULES, "rt", encoding="utf-8") as reader:
        historical = json.load(reader)
    new_rows = run_build(args.schema_root, args.source_root, crosswalk, categories, native_recovery=True)
    output = compare_rule_ids(historical["rules"], new_rows, categories)
    output.update({"format": "scap-ng-0.4.1-source-rule-identity-rebuild/1",
                   "source_repository": "niwc-atlantic/scap-content-library",
                   "source_commit": SOURCE_COMMIT,
                   "schema_version": "0.4.1", "schema_aggregate_sha256": schema_digest,
                   "source_benchmarks": 65,
                   "owner_scope": {"active": 7990, "owner_excluded_sql": 209,
                                   "historical_windows_2012": 693},
                   "qualification": "CONVERTED_UNVERIFIED; no scanner runtime evidence"})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: output[key] for key in ("original", "candidate", "newly_blocked_from_converted",
                                                      "newly_converted_from_blocked", "nonregression_pass")}, sort_keys=True))
    if args.enforce_nonregression and not output["nonregression_pass"]:
        print("HOLD: previously converted source Rule IDs now blocked/manual", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
