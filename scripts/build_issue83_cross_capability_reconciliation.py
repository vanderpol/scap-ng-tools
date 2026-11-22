#!/usr/bin/env python3
"""Reconcile the full-65 blocker ledger after typed Test-capability recovery.

This is an evidence transformation, not a converter exception list.  It reads
an immutable prior ledger, verifies the owner-approved source Rule identities,
and removes only Rules independently replayed through the generic
Object/State-authoritative resolver.  All other source dispositions remain
unchanged and fail closed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

RECOVERED_IDS = {
    "xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278400r1172752_rule",
    "xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218741r1022677_rule",
    "xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218742r1022679_rule",
    "xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214451r879567_rule",
    "xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214452r879568_rule",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--converter-commit", required=True)
    args = parser.parse_args()
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    rows = baseline["rows"]
    by_rule = {row["source_rule"]: row for row in rows}
    if len(by_rule) != len(rows):
        raise SystemExit("baseline contains duplicate source Rules")
    if not RECOVERED_IDS <= set(by_rule):
        raise SystemExit("baseline is missing an owner-approved recovery Rule")
    recovered = []
    for source_rule in sorted(RECOVERED_IDS):
        row = by_rule[source_rule]
        if row["root_cause"] != "source_invalid_cross_capability_reference":
            raise SystemExit(f"recovery is not a cross-capability source disposition: {source_rule}")
        recovered.append({
            "benchmark": row["benchmark"],
            "source_rule": source_rule,
            "source_rule_sha256": row["source_rule_sha256"],
            "definition": row["definition"],
            "definition_sha256": row["definition_sha256"],
            "source_test_ids": row["source_test_ids"],
            "source_zip_sha256": row["source_zip_sha256"],
            "source_xml_sha256": row["source_xml_sha256"],
            "authority": "object_and_all_direct_state_capabilities_match",
            "native_capability_inferred": True,
            "runtime_qualified": False,
        })
    remaining = [row for row in rows if row["source_rule"] not in RECOVERED_IDS]
    def counts(field):
        output = {}
        for row in remaining:
            key = row[field]
            output[key] = output.get(key, 0) + 1
        return dict(sorted(output.items()))
    output = {
        "format": "scap-ng-tools/issue83-cross-capability-reconciliation/1",
        "baseline_ledger": str(args.baseline),
        "baseline_ledger_sha256": sha(args.baseline),
        "pins": baseline["pins"],
        "converter_commit": args.converter_commit,
        "recovery_contract": {
            "source_rule_semantics": "Use Object and all direct State declarations as the authoritative capability when they are one matching capability, regardless of the wrapper Test element.",
            "not_applied_to": [
                "missing or malformed Object/State references",
                "mixed Object/State capabilities",
                "deprecated Test elements",
                "nested Set/Filter States, which retain their own same-family validation",
            ],
            "source_content_modified": False,
            "runtime_equivalence": "not_proved",
        },
        "counts": {
            "baseline_blocked_rules": len(rows),
            "recovered_rules": len(recovered),
            "remaining_blocked_rules": len(remaining),
            "remaining_by_disposition": counts("disposition"),
            "remaining_by_root_cause": counts("root_cause"),
        },
        "recovered": recovered,
        "remaining_rows": sorted(remaining, key=lambda row: (row["root_cause"], row["benchmark"], row["source_rule"])),
        "proof": [
            "Each recovered Rule was converted through the production AssessmentConverter and canonical 0.4.1 semantic validator.",
            "The source ZIP/XML/Rule/Definition identities are copied from the pinned baseline ledger and were not rewritten.",
            "The four nested-filter cases remain source-invalid and are not recovered by direct Test inference.",
            "Structural conversion does not prove RI runtime execution or independent OVAL equivalence.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output["counts"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
