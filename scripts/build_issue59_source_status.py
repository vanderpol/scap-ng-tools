#!/usr/bin/env python3
"""Build a two-axis OVAL-source vs native-conversion crosswalk from a historic receipt.

This does not rerun the converter, alter its original receipt, or infer
deprecation from absence of a native capability. Only exact Test QNames
with documented OVAL 5.12.3 deprecation annotations are classified.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

WINDOWS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}"
OVAL_VERSION = "5.12.3"
OVAL_REFERENCE = ("https://oval-community-guidelines.readthedocs.io/en/latest/"
                  "oval-schema-documentation/windows-definitions-schema.html")
DEPRECATED = {
    WINDOWS + "accesstoken_test": {
        "deprecated_as_of": "5.11",
        "replacement": "userright_test",
        "reason": "Domain-controller scalability; replaced by userright_test",
    },
    WINDOWS + "user_test": {
        "deprecated_as_of": "5.11",
        "replacement": "user_sid55_test",
        "reason": "Trustee names are not unique; replaced by SID-based user_sid55_test",
    },
}
PREFIX = "unsupported test capability: "


def classify(row: dict) -> dict:
    diagnostic = row["diagnostic"]
    qname = diagnostic[len(PREFIX):] if diagnostic.startswith(PREFIX) else None
    annotation = DEPRECATED.get(qname)
    return {
        "benchmark": row["benchmark"],
        "source_rule": row["source_id"],
        "original_diagnostic": diagnostic,
        "native_conversion_disposition": row["disposition_class"],
        "native_conversion_blocker_group": row["blocker_group"],
        "source_normative_status": (
            "deprecated_by_pinned_oval" if annotation else "needs_source_verification"
        ),
        "source_test_qname": qname,
        "deprecation_evidence": ({
            "normative_version": OVAL_VERSION,
            "specification": OVAL_REFERENCE,
            **annotation,
        } if annotation else None),
    }


def build(ledger: dict) -> dict:
    old = ledger["benchmark"]
    original = old["rows"]
    if len(original) != old["source_rules_blocked"]:
        raise ValueError("historical blocked Rule count mismatch")
    if any(row.get("entity") != "benchmark_rule" for row in original):
        raise ValueError("unexpected source entity kind")
    identities = [(r["benchmark"], r["source_id"]) for r in original]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate original benchmark Rule")
    rows = sorted((classify(row) for row in original),
                  key=lambda row: (row["benchmark"], row["source_rule"]))
    by_status = Counter(r["source_normative_status"] for r in rows)
    by_test = Counter(r["source_test_qname"] for r in rows if r["deprecation_evidence"])
    return {
        "format": "scap-ng-tools-oval-source-status-crosswalk/1",
        "as_of": "2026-11-18",
        "basis": "historical pinned blocked-Rule receipt; not current main",
        "original_conversion_ledger_schema_commit": ledger["canonical_schema_commit"],
        "original_benchmark_source_commit": ledger["benchmark_source_commit"],
        "normative_reference_version": OVAL_VERSION,
        "normative_reference": OVAL_REFERENCE,
        "source_document_version_qualification": "pending_original_xml_by_rule",
        "summary": {
            "historical_blocked_rules": len(rows),
            "deprecated_by_pinned_oval": by_status["deprecated_by_pinned_oval"],
            "needs_source_verification": by_status["needs_source_verification"],
            "deprecated_qname_counts": dict(sorted(by_test.items())),
            "native_converted": 0,
            "claim_of_nondeprecated_lossless_completion": False,
        },
        "rows": rows,
    }


def markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# Source support versus conversion - historic 98-Rule blocker audit",
        "",
        "This is a new normative-source crosswalk, not a converter rerun. "
        "The original 98-Rule receipt remains unchanged.",
        "",
        "Original benchmark source commit: " + report["original_benchmark_source_commit"],
        "Original canonical schema commit: " + report["original_conversion_ledger_schema_commit"],
        "Normative reference: [OVAL 5.12.3 Windows Definitions](" + OVAL_REFERENCE + ")",
        "",
        "| Independent OVAL source-status axis | Rules |",
        "|---|---:|",
        "| Verified deprecated by pinned OVAL 5.12.3 | "
            + str(s["deprecated_by_pinned_oval"]) + " |",
        "| Normative status requires original-source/XSD review | "
            + str(s["needs_source_verification"]) + " |",
        "| **Total historical blocked native Rules** | **"
            + str(s["historical_blocked_rules"]) + "** |",
        "",
        "The 66 Windows accesstoken_test and five Windows user_test entries were "
        "deprecated in OVAL 5.11. All 98 remain historically unconverted. "
        "Replacements are NOT asserted behaviorally equivalent.",
        "",
        "The other 27 are NOT yet proven nondeprecated; check original OVAL "
        "source versions, exact QNames, referenced Object/State and behaviors. "
        "Never infer deprecation from lack of a native mapping.",
        "",
        "## Remaining source-status verification queue",
        "",
        "| Original source Rule | Native blocker group |",
        "|---|---|",
    ]
    for row in report["rows"]:
        if row["source_normative_status"] == "needs_source_verification":
            lines.append("| " + row["source_rule"] + " | "
                         + row["native_conversion_blocker_group"] + " |")
    lines += [
        "",
        "The machine-readable source-status-crosswalk.json retains the original "
        "Rule identities, native conversion dispositions, diagnostic text and "
        "deprecation authority. Per-Rule original XML hashes and a current-main "
        "source rebuild remain to be qualified.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ledger", type=Path, required=True)
    ap.add_argument("--json-output", type=Path, required=True)
    ap.add_argument("--markdown-output", type=Path, required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    report = build(json.loads(args.ledger.read_text(encoding="utf-8")))
    md = markdown(report)
    if args.check:
        if (not args.json_output.is_file()
                or json.loads(args.json_output.read_text(encoding="utf-8")) != report):
            raise SystemExit("source status JSON crosswalk stale")
        if (not args.markdown_output.is_file()
                or args.markdown_output.read_text(encoding="utf-8") != md):
            raise SystemExit("source status Markdown crosswalk stale")
    else:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                    encoding="utf-8")
        args.markdown_output.write_text(md, encoding="utf-8")
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
