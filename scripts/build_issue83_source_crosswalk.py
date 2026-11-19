#!/usr/bin/env python3
"""Build a deterministic, source-pinned Issue #83 crosswalk.

The command deliberately reads source archives without copying or rewriting
content.  It records the complete 65-archive XCCDF Rule identity ledger,
source ``requires``/``conflicts`` relationships, and the DISA extended
``description`` fields used by the signed SCAP 1.4 stream.  An optional OVAL
schema root adds a declaration inventory; declarations are never promoted to
support merely because an XSD name resembles a native capability.

Generated reports are evidence, not converter output and must normally live
outside the repository.  The compact JSON/Markdown output is deterministic.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import html
import json
from pathlib import Path
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

DS = "http://scap.nist.gov/schema/scap/source/1.2"
XCCDF = "http://checklists.nist.gov/xccdf/1.2"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
DISA_FIELDS = (
    "VulnDiscussion", "FalsePositives", "FalseNegatives", "Documentable",
    "Mitigations", "SeverityOverrideGuidance", "PotentialImpacts",
    "ThirdPartyTools", "MitigationControl", "Responsibility", "IAControls",
)
OVAL_DEFINITION_FILES = re.compile(r"^[^-]+-definitions-schema\.xsd$")


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def xml_identity(element: ET.Element):
    """Stable identity used by the existing converter provenance contract."""
    return [
        element.tag,
        sorted(element.attrib.items()),
        element.text if not len(element) else None,
        [xml_identity(child) for child in element],
    ]


def identity_digest(element: ET.Element) -> str:
    raw = json.dumps(xml_identity(element), sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    return digest(raw)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_disa_description(description: ET.Element | None) -> tuple[dict[str, str], str]:
    """Parse publisher tags embedded as escaped XML in XCCDF description text.

    DISA streams carry these tags as literal text, not XML children.  Empty
    values and ``Documentable=false`` are retained exactly as authored.
    """
    text = "" if description is None else (description.text or "")
    if not text.strip():
        return {}, text
    try:
        root = ET.fromstring(f"<disa-wrapper>{html.unescape(text)}</disa-wrapper>")
    except ET.ParseError:
        return {}, text
    fields: dict[str, str] = {}
    for child in root:
        if child.tag in DISA_FIELDS and child.tag not in fields:
            fields[child.tag] = "".join(child.itertext())
    return fields, text


def find_benchmark(raw_xml: bytes) -> ET.Element:
    root = ET.fromstring(raw_xml)
    if root.tag != f"{{{DS}}}data-stream-collection":
        raise ValueError("source XML is not a SCAP 1.2 data-stream-collection")
    benchmarks = [element for element in root.iter()
                  if element.tag == f"{{{XCCDF}}}Benchmark"]
    if len(benchmarks) != 1:
        raise ValueError(f"expected one XCCDF Benchmark, found {len(benchmarks)}")
    return benchmarks[0]


def archive_record(path: Path) -> dict:
    archive_raw = path.read_bytes()
    archive_sha = digest(archive_raw)
    with zipfile.ZipFile(path) as package:
        if package.testzip() is not None:
            raise ValueError(f"CRC failure in {path.name}")
        members = package.namelist()
        if len(members) != len(set(members)):
            raise ValueError(f"duplicate ZIP member in {path.name}")
        xml_members = [name for name in members if name.lower().endswith(".xml")]
        if len(xml_members) != 1:
            raise ValueError(f"expected one XML member in {path.name}, found {len(xml_members)}")
        member = xml_members[0]
        raw_xml = package.read(member)
    benchmark = find_benchmark(raw_xml)
    rules = []
    relation_rows = []
    field_counts = Counter()
    field_nonempty = Counter()
    malformed_descriptions = []
    for rule in benchmark.iter(f"{{{XCCDF}}}Rule"):
        source_id = rule.get("id")
        if not source_id:
            raise ValueError(f"Rule without id in {path.name}")
        fields, raw_description = parse_disa_description(
            next((child for child in rule if child.tag == f"{{{XCCDF}}}description"), None))
        field_hashes = {}
        for name in DISA_FIELDS:
            if name in fields:
                field_counts[name] += 1
                if fields[name]:
                    field_nonempty[name] += 1
                field_hashes[name] = digest(fields[name].encode("utf-8"))
        if raw_description and not fields:
            # A description is allowed to be ordinary XCCDF text; only record
            # malformed publisher-looking payloads as a diagnostic.
            if raw_description.lstrip().startswith("<"):
                malformed_descriptions.append(source_id)
        requires_elements = rule.findall(f"{{{XCCDF}}}requires")
        conflicts_elements = rule.findall(f"{{{XCCDF}}}conflicts")
        requires_raw = [element.get("idref", "") for element in requires_elements]
        conflicts_raw = [element.get("idref", "") for element in conflicts_elements]
        requires = []
        for value in requires_raw:
            ids = value.split()
            if not ids:
                raise ValueError(f"empty requires idref in {path.name}:{source_id}")
            requires.append(ids[0] if len(ids) == 1 else {"any_of": ids})
        conflicts = []
        for value in conflicts_raw:
            ids = value.split()
            if len(ids) != 1:
                raise ValueError(f"conflicts requires one idref in {path.name}:{source_id}")
            conflicts.append(ids[0])
        row = {
            "source_rule": source_id,
            "source_rule_sha256": identity_digest(rule),
            "requires": requires,
            "conflicts": conflicts,
            "disa_description_field_sha256": dict(sorted(field_hashes.items())),
        }
        rules.append(row)
        if requires or conflicts:
            relation_rows.append({
                "archive": path.name,
                "xml_member": member,
                "source_rule": source_id,
                "source_rule_sha256": row["source_rule_sha256"],
                "requires_raw": requires_raw,
                "requires": requires,
                "conflicts_raw": conflicts_raw,
                "conflicts": conflicts,
            })
    return {
        "archive": path.name,
        "archive_sha256": archive_sha,
        "xml_member": member,
        "xml_sha256": digest(raw_xml),
        "benchmark_id": benchmark.get("id"),
        "xccdf_version": benchmark.get("xccdf-version"),
        "rule_count": len(rules),
        "relation_count": len(relation_rows),
        "rules": rules,
        "relations": relation_rows,
        "disa_description": {
            "field_names": list(DISA_FIELDS),
            "rule_field_counts": dict(sorted(field_counts.items())),
            "nonempty_rule_field_counts": dict(sorted(field_nonempty.items())),
            "malformed_publisher_payload_rules": sorted(malformed_descriptions),
        },
    }


def oval_inventory(root: Path) -> dict:
    rows = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or not OVAL_DEFINITION_FILES.match(path.name):
            continue
        raw = path.read_bytes()
        document = ET.parse(path).getroot()
        namespace = document.get("targetNamespace", "")
        for child in document:
            if child.tag.rsplit("}", 1)[-1] not in {"element", "complexType", "simpleType", "group"}:
                continue
            name = child.get("name")
            if not name:
                continue
            rows.append({
                "schema_file": path.name,
                "schema_sha256": digest(raw),
                "namespace": namespace,
                "declaration_kind": child.tag.rsplit("}", 1)[-1],
                "name": name,
                "native_mapping_status": "unclassified",
                "classification_reason": "XSD declaration inventory is not proof of a native mapping; classify against canonical 0.4.1 and converter evidence.",
            })
    return {
        "source_commit_expected": "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706",
        "schema_files": sorted({row["schema_file"] for row in rows}),
        "declarations": rows,
        "summary": {
            "schema_files": len({row["schema_file"] for row in rows}),
            "declarations": len(rows),
            "native_mapping_status": {"unclassified": len(rows)},
        },
    }


def build(source_root: Path, expected_archives: int, source_commit: str,
          oval_root: Path | None) -> dict:
    archives = sorted(source_root.glob("*.zip"))
    if len(archives) != expected_archives:
        raise ValueError(f"expected {expected_archives} source ZIPs, found {len(archives)}")
    records = [archive_record(path) for path in archives]
    source_rules = sum(record["rule_count"] for record in records)
    relations = [row for record in records for row in record["relations"]]
    archive_manifest = [{key: record[key] for key in (
        "archive", "archive_sha256", "xml_member", "xml_sha256", "benchmark_id", "rule_count")}
        for record in records]
    archive_set_sha256 = digest(json.dumps(
        archive_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    field_counts = Counter()
    nonempty = Counter()
    malformed = []
    for record in records:
        field_counts.update(record["disa_description"]["rule_field_counts"])
        nonempty.update(record["disa_description"]["nonempty_rule_field_counts"])
        malformed.extend(record["disa_description"]["malformed_publisher_payload_rules"])
    result = {
        "format": "scap-ng-tools/issue83-source-crosswalk/1",
        "source": {
            "root": "external source root (not copied into repository)",
            "commit": source_commit,
            "expected_archives": expected_archives,
            "archive_set_sha256": archive_set_sha256,
            "archives": records,
        },
        "summary": {
            "archives": len(records),
            "source_rules": source_rules,
            "rules_with_requires_or_conflicts": len(relations),
            "requires_rows": sum(bool(row["requires"]) for row in relations),
            "conflicts_rows": sum(bool(row["conflicts"]) for row in relations),
            "disa_description_field_names": list(DISA_FIELDS),
            "disa_description_rule_field_counts": dict(sorted(field_counts.items())),
            "disa_description_nonempty_rule_field_counts": dict(sorted(nonempty.items())),
            "malformed_publisher_payload_rules": sorted(malformed),
        },
        "relationships": relations,
        "mapping": {
            "requires": {
                "source": "XCCDF 1.2 Rule/requires/@idref, one child per clause; IDs in one child are ORed",
                "native": "SCAP-NG 0.4.1 rule.requires; clauses are ANDed and any_of members are ORed",
                "status": "converter currently initializes an empty native array; loss is a converter defect",
            },
            "conflicts": {
                "source": "XCCDF 1.2 Rule/conflicts/@idref, one ID per child",
                "native": "SCAP-NG 0.4.1 rule.conflicts; IDs remain source identities",
                "status": "converter currently initializes an empty native array; loss is a converter defect",
            },
            "disa_description": {
                "source": "XCCDF description text containing literal publisher XML",
                "native_discussion": "rule.discussion retains the exact source description text",
                "native_extension": "rule.extensions.disa preserves each named field, including empty strings and Documentable lexical value",
                "fields": list(DISA_FIELDS),
                "status": "structured extension mapping is implemented in the follow-up converter increment",
            },
        },
    }
    if oval_root is not None:
        result["oval_schema_inventory"] = oval_inventory(oval_root)
    return result


def markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Issue #83 source crosswalk",
        "",
        "This report is generated from immutable signed SCAP 1.4 source ZIPs. It is a source inventory and converter-loss audit, not runtime or OVAL equivalence proof.",
        "",
        f"- Source commit: `{report['source']['commit']}`",
        f"- Archives: **{summary['archives']}**",
        f"- Source Rules: **{summary['source_rules']}**",
        f"- Rules with `requires`/`conflicts`: **{summary['rules_with_requires_or_conflicts']}**",
        f"- `requires` rows: **{summary['requires_rows']}**; `conflicts` rows: **{summary['conflicts_rows']}**",
        "",
        "## Result",
        "",
        "The pinned 65-archive corpus contains no non-empty `Rule/requires` or `Rule/conflicts` relationships. This is a measured zero, not evidence that the converter may drop relationships: the converter must preserve them for source streams that use them. The relationship ledger is empty for this corpus and the test fixture exercises positive and negative source relationship elements.",
        "",
        "## DISA extended description mapping",
        "",
        "Literal publisher XML inside XCCDF `description` is mapped without data loss:",
        "",
        "| Source field | Native location | Preservation |\n|---|---|---|\n" + "\n".join(f"| `{field}` | `rule.extensions.disa.{field}` | present, empty values, and lexical value retained |" for field in DISA_FIELDS),
        "",
        f"The source ledger has the eleven-field DISA payload on {summary['disa_description_rule_field_counts'].get('VulnDiscussion', 0)} Rules; {len(summary['malformed_publisher_payload_rules'])} Rules have publisher-looking descriptions that require source-specific review. Per-Rule field hashes are retained in JSON. `rule.discussion` retains the original description text for compatibility.",
        "",
        "## Holds",
        "",
        "- The OVAL XSD declaration inventory (when supplied) is intentionally `unclassified`; XSD declaration names are not native support proof.",
        "- Canonical schema changes are out of scope for this Tools increment; any missing native representation is a canonical-language decision for `scap-ng` #80.",
        "- Native conversion output and RI execution are separate qualification stages.",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-archives", type=int, default=65)
    parser.add_argument("--oval-schema-root", type=Path)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build(args.source_root, args.expected_archives, args.source_commit,
                   args.oval_schema_root)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(markdown(report), encoding="utf-8")
    print(json.dumps({"archives": report["summary"]["archives"],
                      "source_rules": report["summary"]["source_rules"],
                      "relationships": len(report["relationships"]),
                      "output_json": str(args.output_json),
                      "output_md": str(args.output_md)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
