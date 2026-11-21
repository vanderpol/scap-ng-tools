#!/usr/bin/env python3
"""Audit the Windows OVAL accesstoken blocker family as one source status.

This is a read-only source audit. It does not map deprecated accesstoken
content to userright, alter benchmark XML, or execute a Windows collector.
The historical conversion ledger supplies exact Rule identities; the pinned
benchmark archive supplies source Rule titles/check references and hashes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

SOURCE_COMMIT = "8c8e5dff860af6b1290ee9273a282db24278f8d5"
OVAL_COMMIT = "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706"
XSD_NAME = "windows-definitions-schema.xsd"
XSD_SHA256 = "b66f1547bfd0bb8ea6cf58a0eec9f8de417aad6642f741d0ed0ad7b6462314ff"
QNAME = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test"
XCCDF = "http://checklists.nist.gov/xccdf/1.2"

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]

def source_rule(root: ET.Element, identifier: str) -> ET.Element | None:
    return next((node for node in root.iter()
                 if local(node.tag) == "Rule" and node.get("id") == identifier), None)

def archive_details(path: Path, rule_id: str) -> dict:
    raw = path.read_bytes()
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        if len(names) != 1:
            raise ValueError(f"expected one datastream XML in {path.name}, found {names}")
        member = names[0]
        member_raw = archive.read(member)
    root = ET.fromstring(member_raw)
    rule = source_rule(root, rule_id)
    if rule is None:
        raise ValueError(f"source Rule {rule_id} not found in {path.name}")
    refs = [{"href": child.get("href"), "name": child.get("name")}
            for child in rule.iter()
            if local(child.tag) == "check-content-ref"]
    return {
        "benchmark_zip": path.name,
        "benchmark_zip_sha256": sha(raw),
        "datastream_member": member,
        "datastream_member_sha256": sha(member_raw),
        "source_rule_sha256": sha(ET.tostring(rule, encoding="utf-8")),
        "source_rule_title": next(" ".join((child.text or "").split())
                                   for child in rule
                                   if local(child.tag) == "title"),
        "check_content_refs": refs,
    }

def build(ledger_path: Path, source_root: Path, xsd_path: Path) -> dict:
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    rows = ledger["benchmark"]["rows"]
    selected = [row for row in rows
                if row.get("diagnostic") == "unsupported test capability: " + QNAME]
    if len(selected) != 66:
        raise ValueError(f"expected 66 accesstoken Rules, found {len(selected)}")
    xsd_raw = xsd_path.read_bytes()
    if sha(xsd_raw) != XSD_SHA256:
        raise ValueError("Windows XSD is not the pinned OVAL 5.12.3 file")
    output_rows = []
    for row in sorted(selected, key=lambda item: (item["benchmark"], item["source_id"])):
        archive = source_root / row["benchmark"]
        if not archive.is_file():
            raise FileNotFoundError(archive)
        output_rows.append({
            "benchmark": row["benchmark"],
            "source_rule_id": row["source_id"],
            "historical_conversion_disposition": row["disposition_class"],
            "source_rule": archive_details(archive, row["source_id"]),
        })
    return {
        "format": "scap-ng-tools/accesstoken-family-audit/1",
        "scope": "one deprecated OVAL capability family; source status, not replacement equivalence",
        "source": {
            "benchmark_source_commit": SOURCE_COMMIT,
            "historical_ledger_sha256": sha(ledger_path.read_bytes()),
            "oval_schema_commit": OVAL_COMMIT,
            "xsd": XSD_NAME,
            "xsd_sha256": XSD_SHA256,
            "source_test_qname": QNAME,
            "deprecated_since": "5.11",
            "replacement": "userright_test/userright_object/userright_state",
            "reason": "The accesstoken_test suffers from scalability issues when run on a domain controller and should not be used.",
        },
        "canonical_status": {
            "classification": "deprecated_source_construct",
            "converter_action": "retain explicit hold; do not add canonical support solely for these Rules",
            "replacement_equivalence": "not_proved",
            "runtime_execution": "not_run; no Windows target",
        },
        "summary": {
            "rules": len(output_rows),
            "unique_rules": len({row["source_rule_id"] for row in output_rows}),
            "benchmarks": len({row["benchmark"] for row in output_rows}),
            "check_references": sum(len(row["source_rule"]["check_content_refs"])
                                    for row in output_rows),
            "historical_native_disposition": dict(Counter(
                row["historical_conversion_disposition"] for row in output_rows)),
        },
        "rows": output_rows,
    }

def markdown(report: dict) -> str:
    s = report["summary"]
    source = report["source"]
    lines = [
        "# Windows `accesstoken_test` family audit",
        "",
        "This audit treats the 66 blocked Rules as one source capability family. "
        "It does not claim that `userright` is behaviorally equivalent and does not "
        "modify source or canonical schemas.",
        "",
        f"- Rules: **{s['rules']}** ({s['unique_rules']} unique)",
        f"- Benchmarks: **{s['benchmarks']}**",
        f"- OVAL source commit: `{source['benchmark_source_commit']}`",
        f"- OVAL 5.12.3 schema commit: `{source['oval_schema_commit']}`",
        f"- Windows XSD SHA-256: `{source['xsd_sha256']}`",
        f"- Deprecated since: **{source['deprecated_since']}**",
        f"- Replacement named by XSD: **{source['replacement']}**",
        "",
        "## Normative classification",
        "",
        "The pinned `windows-definitions-schema.xsd` attaches `deprecated_info` directly "
        "to `accesstoken_test`, `accesstoken_object`, `accesstoken_state`, and "
        "`AccesstokenBehaviors`. The reason explicitly cites domain-controller scalability "
        "and directs authors to `userright`. These are deprecated source constructs, not "
        "66 independent converter defects. The source check references and Rule hashes "
        "remain in the JSON receipt.",
        "",
        "## Per-Rule source crosswalk",
        "",
        "| Benchmark | Source Rule | Source title | OVAL Definition refs |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        refs = ", ".join(str(ref.get("name")) for ref in row["source_rule"]["check_content_refs"])
        lines.append(f"| `{row['benchmark']}` | `{row['source_rule_id']}` | "
                     f"{row['source_rule']['source_rule_title']} | `{refs}` |")
    lines += [
        "",
        "## Holds",
        "",
        "- `accesstoken` source execution remains **not run**; no Windows target was available.",
        "- `userright` replacement conversion/runtime equivalence is **not proved**.",
        "- No deprecated OVAL behavior is introduced into SCAP-NG 0.4.1.",
    ]
    return "\n".join(lines) + "\n"

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--xsd", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.json_output.exists() or args.markdown_output.exists():
        raise SystemExit("refusing to overwrite existing audit output")
    report = build(args.ledger, args.source_root, args.xsd)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_output.write_text(markdown(report), encoding="utf-8")
    print(json.dumps(report["summary"], sort_keys=True))

if __name__ == "__main__":
    main()
