#!/usr/bin/env python3
"""Build a same-scope crosswalk between the 8,199-rule and 8,892-rule ledgers.

This is an accounting report, not a conversion claim.  It compares the active
rule universe against the historical 65-benchmark universe and reports native
artifact bytes only when both explicitly supplied artifact roots exist.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path


def load(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def rows(document, label):
    values = document.get("rules") if isinstance(document, dict) else document
    if not isinstance(values, list):
        raise ValueError(f"{label}: expected a rules array")
    result = {}
    for row in values:
        ident = row.get("source_rule")
        benchmark = row.get("benchmark")
        if not ident or not benchmark:
            raise ValueError(f"{label}: missing benchmark or source_rule")
        key = (benchmark, ident)
        if key in result:
            raise ValueError(f"{label}: duplicate benchmark/source_rule")
        result[key] = row
    return result


def sha256_file(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_sha(root: Path | None, relative: str):
    if root is None:
        return None
    path = root / relative
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_crosswalk(active, historical, active_root, historical_root):
    if active_root is None or historical_root is None:
        return {"native_bytes_comparison": "not_available",
                "reason": "both --active-artifact-root and --historical-artifact-root are required",
                "identical": 0, "changed": 0, "missing": 0}
    identical = changed = missing = 0
    details = []
    for key in sorted(active):
        old = historical.get(key)
        if old is None:
            continue
        active_artifacts = active[ident].get("artifacts") or []
        old_artifacts = old.get("artifacts") or []
        paths = sorted(set(active_artifacts) | set(old_artifacts))
        pairs = []
        for relative in paths:
            new_sha = file_sha(active_root, relative)
            old_sha = file_sha(historical_root, relative)
            if new_sha is None or old_sha is None:
                missing += 1
            elif new_sha == old_sha:
                identical += 1
            else:
                changed += 1
            pairs.append({"path": relative, "active_sha256": new_sha,
                          "historical_sha256": old_sha})
        details.append({"benchmark": active[key].get("benchmark"),
                        "source_rule": active[key].get("source_rule"), "artifacts": pairs})
    return {"native_bytes_comparison": "available", "identical": identical,
            "changed": changed, "missing": missing, "rules": details}


def build(active_doc, historical_doc, active_root=None, historical_root=None):
    active = rows(active_doc, "active")
    historical = rows(historical_doc, "historical")
    active_ids, historical_ids = set(active), set(historical)
    common = active_ids & historical_ids
    historical_only = sorted(historical_ids - active_ids)
    active_only = sorted(active_ids - historical_ids)
    transitions = Counter()
    source_sha_drift = []
    per_rule = []
    for key in sorted(active_ids):
        new = active[key]
        old = historical.get(key)
        ident = new.get("source_rule")
        old_status = old.get("status", old.get("conversion_status")) if old else None
        new_status = new.get("status", new.get("conversion_status"))
        transitions[f"{old_status or 'missing'}->{new_status or 'missing'}"] += 1
        if old and new.get("source_rule_sha256") != old.get("source_rule_sha256"):
            source_sha_drift.append({"source_rule": ident,
                                     "active": new.get("source_rule_sha256"),
                                     "historical": old.get("source_rule_sha256")})
        per_rule.append({"source_rule": ident,
                         "benchmark": new.get("benchmark"),
                         "active": {"source_rule_sha256": new.get("source_rule_sha256"),
                                    "status": new_status},
                         "historical": ({"source_rule_sha256": old.get("source_rule_sha256"),
                                         "status": old_status} if old else None)})
    benchmarks = defaultdict(lambda: {"active": 0, "historical": 0,
                                      "common": 0, "historical_only": 0})
    for key, row in active.items():
        benchmarks[row.get("benchmark")]["active"] += 1
    for key, row in historical.items():
        benchmarks[row.get("benchmark")]["historical"] += 1
    for key in common:
        benchmarks[active[key].get("benchmark")]["common"] += 1
    for key in historical_only:
        benchmarks[historical[key].get("benchmark")]["historical_only"] += 1
    return {
        "format": "scap-ng-issue28-same-scope-crosswalk/1",
        "scope": {
            "active_rules": len(active), "historical_rules": len(historical),
            "common_rules": len(common), "active_only_rules": len(active_only),
            "historical_only_rules": len(historical_only),
            "active_benchmarks": len({r.get("benchmark") for r in active.values()}),
            "historical_benchmarks": len({r.get("benchmark") for r in historical.values()}),
            "same_scope": "active rule universe crosswalked against historical ledger; no denominator substitution",
        },
        "status_transition_counts": dict(sorted(transitions.items())),
        "source_rule_sha256_drift_count": len(source_sha_drift),
        "source_rule_sha256_drift": source_sha_drift,
        "historical_only_source_rules": [{"benchmark": historical[key].get("benchmark"),
                                             "source_rule": historical[key].get("source_rule")}
                                            for key in historical_only],
        "active_only_source_rules": [{"benchmark": active[key].get("benchmark"),
                                       "source_rule": active[key].get("source_rule")}
                                      for key in active_only],
        "benchmarks": dict(sorted(benchmarks.items())),
        "native_artifacts": artifact_crosswalk(active, historical, active_root, historical_root),
        "rules": per_rule,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active", type=Path, required=True)
    parser.add_argument("--historical", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--active-artifact-root", type=Path)
    parser.add_argument("--historical-artifact-root", type=Path)
    args = parser.parse_args()
    report = build(load(args.active), load(args.historical),
                   args.active_artifact_root, args.historical_artifact_root)
    report["inputs"] = {
        "active": {"path": str(args.active), "sha256": sha256_file(args.active)},
        "historical": {"path": str(args.historical), "sha256": sha256_file(args.historical)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"active": report["scope"]["active_rules"],
                      "historical": report["scope"]["historical_rules"],
                      "common": report["scope"]["common_rules"],
                      "historical_only": report["scope"]["historical_only_rules"],
                      "sha_drift": report["source_rule_sha256_drift_count"],
                      "native_bytes_comparison": report["native_artifacts"]["native_bytes_comparison"]}, sort_keys=True))


if __name__ == "__main__":
    main()
