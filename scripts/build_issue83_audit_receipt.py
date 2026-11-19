#!/usr/bin/env python3
"""Build a compact, deterministic Issue #83 source audit receipt.

The full crosswalk is intentionally generated outside Git because it contains
all 65 archive Rule rows and the OVAL grammar witness.  This command keeps the
reviewable summary, exact input hashes, measured XCCDF metadata counts and
source-linked candidate holds in the repository without copying source data.
It never infers converter or runtime support from schema inventory counts.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _hold_rows(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for record_type in ("definitions", "tests"):
        for row in receipt.get("blocked_by_source", {}).get(record_type, []):
            rows.append({
                "record_type": record_type[:-1],
                "failure_class": row.get("failure_class", "unclassified"),
                "diagnostic": row.get("diagnostic", ""),
                "source_path": row.get("source_path", ""),
                "source_sha256": row.get("source_sha256", ""),
                "source_ids": sorted(row.get("ids", [])),
            })
    return sorted(rows, key=lambda row: (
        row["record_type"], row["source_path"], row["source_ids"], row["failure_class"]))


def _platform_hold_summary(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    families = receipt.get("families", {})
    rows = []
    for record_type in ("definitions", "tests"):
        for platform, data in sorted(families.get(record_type, {}).items()):
            blocked = sum(
                count for outcome, count in data.get("outcomes", {}).items()
                if outcome == "blocked"
            )
            excluded = sum(
                count for outcome, count in data.get("outcomes", {}).items()
                if outcome == "intentionally_excluded"
            )
            if blocked or excluded:
                rows.append({
                    "record_type": record_type[:-1],
                    "platform": platform,
                    "blocked": blocked,
                    "intentionally_excluded": excluded,
                    "failure_classes": data.get("failure_classes", {}),
                })
    return rows


def build(crosswalk_path: Path, candidate_path: Path | None, *,
          converter_commit: str, canonical_commit: str,
          canonical_schema_sha256: str, oval_commit: str) -> dict[str, Any]:
    crosswalk = json.loads(crosswalk_path.read_text(encoding="utf-8"))
    if crosswalk.get("format") != "scap-ng-tools/issue83-source-crosswalk/1":
        raise ValueError("unexpected source crosswalk format")
    summary = crosswalk["summary"]
    source = crosswalk["source"]
    oval = crosswalk.get("oval_schema_inventory")
    if oval is None:
        raise ValueError("crosswalk must include the pinned OVAL schema inventory")
    oval_summary = oval["summary"]
    candidate = None
    if candidate_path is not None:
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))

    source_identity = {
        "repository": "vanderpol/scap-content-library",
        "commit": source["commit"],
        "archive_count": source["expected_archives"],
        "source_rule_count": summary["source_rules"],
        "archive_set_sha256": source["archive_set_sha256"],
        "xccdf_schema": source["xccdf_schema"],
        "full_crosswalk_sha256": file_sha256(crosswalk_path),
        "full_crosswalk_bytes": crosswalk_path.stat().st_size,
    }
    xccdf = {
        "relationship_source_semantics": {
            "requires": "one child is one OR clause; separate children are ANDed",
            "conflicts": "one source ID per child",
        },
        "rules_with_requires_or_conflicts": summary["rules_with_requires_or_conflicts"],
        "requires_rows": summary["requires_rows"],
        "conflicts_rows": summary["conflicts_rows"],
        "groups_with_requires_or_conflicts": summary["groups_with_requires_or_conflicts"],
        "group_requires_rows": summary["group_requires_rows"],
        "group_conflicts_rows": summary["group_conflicts_rows"],
        "metadata_rule_field_counts": summary.get("xccdf_metadata_rule_field_counts", {}),
        "metadata_element_counts": summary.get("xccdf_metadata_element_counts", {}),
        "disa_description_rule_field_counts": summary["disa_description_rule_field_counts"],
        "disa_description_nonempty_rule_field_counts": summary["disa_description_nonempty_rule_field_counts"],
        "malformed_publisher_payload_rule_count": len(summary["malformed_publisher_payload_rules"]),
        "native_disposition": {
            "discussion": "source description text is retained by source_description_text",
            "identifiers_references_remediation": "converter emits no populated native fields in this increment",
            "fix_fixtext": "source elements are inventoried; no owner-approved native remediation mapping is emitted",
            "disa_structured_extension": "held pending canonical 0.4.1 extension contract",
        },
        "relationship_disposition": {
            "rule": "native Rule mapping is covered by focused source-valid production tests",
            "group": "fail-closed canonical mapping hold; do not flatten Group relationships into Rule prerequisites",
        },
    }
    oval_inventory = {
        key: oval_summary[key] for key in (
            "schema_files", "schema_manifest_files", "definition_schema_files",
            "system_characteristics_schema_files", "declarations", "grammar_rows",
            "canonical_mapping_rows", "grammar_rows_with_mapping",
            "native_mapping_status", "official_deprecation_annotations",
            "declarations_with_deprecated_members", "schema_dependencies",
            "unresolved_schema_dependencies", "schema_references",
            "resolved_schema_references", "unresolved_schema_references",
            "schematron_rows", "schematron_assertions", "schematron_reports",
            "prose_rows", "evaluation_documentation_rows", "evaluation_chart_rows",
            "schematron_test_feature_counts",
        ) if key in oval_summary
    }
    receipt = {
        "format": "scap-ng-tools/issue83-compact-audit/1",
        "generated_by": {
            "script": "scripts/build_issue83_audit_receipt.py",
            "script_sha256": file_sha256(Path(__file__).resolve()),
            "source_crosswalk_script": "scripts/build_issue83_source_crosswalk.py",
            "source_crosswalk_script_sha256": file_sha256(Path(__file__).with_name("build_issue83_source_crosswalk.py")),
        },
        "source": source_identity,
        "pins": {
            "oval_schema_commit": oval.get("source_commit_expected", oval_commit),
            "oval_schema_commit_verified": oval_commit,
            "canonical_commit": canonical_commit,
            "canonical_schema_family_sha256": canonical_schema_sha256,
            "converter_commit": converter_commit,
        },
        "xccdf": xccdf,
        "oval_schema_inventory": oval_inventory,
        "candidate_qualification": None,
        "ranked_gap_inventory": [],
        "proof_limits": [
            "Source schema and archive inventories do not prove native representability, conversion fidelity, or runtime equivalence.",
            "Measured zero relationships in this 65-archive denominator does not authorize dropping source relationships.",
            "Candidate Self-Assertion counts are schema-valid conversion diagnostics; execution and independent equivalence remain unproved.",
        ],
    }
    if candidate is not None:
        candidate_summary = candidate.get("summary", {})
        qualification = candidate.get("qualification", "not_run")
        execution = (qualification.get("execution", "not_run")
                     if isinstance(qualification, dict) else qualification)
        receipt["candidate_qualification"] = {
            "source_commit": candidate.get("source", {}).get("commit"),
            "converter_commit": candidate.get("converter_commit", candidate.get("converter", {}).get("commit")),
            "canonical_schema": candidate.get("canonical_schema"),
            "summary": candidate_summary,
            "platform_holds": _platform_hold_summary(candidate),
            "source_linked_holds": _hold_rows(candidate),
            "execution": execution,
            "independent_equivalence": "not_proved",
        }
    # This is a review queue, not a support claim.  Each row points to a
    # source/schema fact and names the owning follow-up rather than inventing
    # a per-platform workaround.
    receipt["ranked_gap_inventory"] = [
        {
            "rank": 1,
            "class": "shared_source_semantics",
            "priority": "P0",
            "measured": {
                "schematron_assertions": oval_summary.get("schematron_assertions", 0),
                "schematron_reports": oval_summary.get("schematron_reports", 0),
                "evaluation_prose_rows": oval_summary.get("prose_rows", 0),
            },
            "disposition": "inventory_only",
            "action": "Build generic source-valid semantic witnesses and review converter/RI obligations before claiming parity.",
            "owner": "scap-ng canonical language + Tools + RI",
        },
        {
            "rank": 2,
            "class": "xccdf_rule_metadata",
            "priority": "P0",
            "measured": xccdf["metadata_element_counts"],
            "disposition": "canonical_contract_hold",
            "action": "Coordinate a lossless native mapping for ident/reference/fix/fixtext and DISA publisher fields; do not overload discussion or invent extensions.",
            "owner": "scap-ng canonical language + Tools",
        },
        {
            "rank": 3,
            "class": "oval_shared_grammar",
            "priority": "P1",
            "measured": {
                "declarations": oval_summary.get("declarations", 0),
                "grammar_rows": oval_summary.get("grammar_rows", 0),
                "canonical_mapping_rows": oval_summary.get("canonical_mapping_rows", 0),
                "grammar_rows_with_mapping": oval_summary.get("grammar_rows_with_mapping", 0),
                "unproven_declarations": oval_summary.get("native_mapping_status", {}).get("unproven", 0),
            },
            "disposition": "source_crosswalk_incomplete",
            "action": "Complete field/attribute/default/cardinality/function dispositions from pinned XSD, Schematron and prose; mapping-file presence is not proof.",
            "owner": "scap-ng canonical language + Tools",
        },
        {
            "rank": 4,
            "class": "platform_specific_schema_or_source_holds",
            "priority": "P1",
            "measured": {
                "candidate_hold_rows": len(receipt["candidate_qualification"]["source_linked_holds"]) if candidate else 0,
                "candidate_execution": receipt["candidate_qualification"]["execution"] if candidate else "not_run",
            },
            "disposition": "source_linked_holds",
            "action": "Resolve only through shared canonical/converter contracts: external Variable/Input constraints, valid Windows traversal, and remaining iOS/Junos capabilities; preserve deprecated/source-invalid cases separately.",
            "owner": "Tools + canonical language; RI for runtime after admission",
        },
        {
            "rank": 5,
            "class": "group_relationships",
            "priority": "P2",
            "measured": {
                "source_groups_with_relationships": summary["groups_with_requires_or_conflicts"],
                "source_group_requires": summary["group_requires_rows"],
                "source_group_conflicts": summary["group_conflicts_rows"],
            },
            "disposition": "canonical_non_flattening_mapping_hold",
            "action": "Retain fail-closed behavior and add a source-valid group witness when canonical mapping is approved.",
            "owner": "scap-ng canonical language",
        },
    ]
    return receipt


def markdown(receipt: dict[str, Any]) -> str:
    source = receipt["source"]
    xccdf = receipt["xccdf"]
    oval = receipt["oval_schema_inventory"]
    lines = [
        "# Issue #83 compact source audit",
        "",
        "This compact receipt is derived from an external full source crosswalk. It is a source-language and conversion-gap audit, not runtime or independent equivalence proof.",
        "",
        f"- Source archives/Rules: **{source['archive_count']} / {source['source_rule_count']}**",
        f"- Source archive-set SHA-256: `{source['archive_set_sha256']}`",
        f"- Full crosswalk SHA-256: `{source['full_crosswalk_sha256']}` ({source['full_crosswalk_bytes']} bytes)",
        f"- OVAL schema: `{receipt['pins']['oval_schema_commit']}`",
        f"- Canonical 0.4.1: `{receipt['pins']['canonical_commit']}`; schema family `{receipt['pins']['canonical_schema_family_sha256']}`",
        f"- Converter audit head: `{receipt['pins']['converter_commit']}`",
        "",
        "## Reproduction",
        "",
        "Use the exact pinned 65-archive source directory without copying it into the repository. The full crosswalk is intentionally external; its byte hash is recorded above.",
        "",
        "```sh",
        "python3 scripts/build_issue83_source_crosswalk.py \\",
        "  --source-root \"$SCAP_NG_FULL65_SOURCE_ROOT\" \\",
        "  --source-commit 8c8e5dff860af6b1290ee9273a282db24278f8d5 \\",
        "  --oval-schema-root \"$OVAL_5_12_3_SCHEMA_ROOT\" \\",
        "  --canonical-mapping-root \"$SCAP_NG_041_ROOT/schema/capability-mappings\" \\",
        "  --canonical-mapping-commit 5ee55288b369da26f308f40813e545b78dff2753 \\",
        "  --output-json /tmp/issue83-crosswalk.json --output-md /tmp/issue83-crosswalk.md",
        "python3 scripts/build_issue83_audit_receipt.py \\",
        "  --crosswalk-json /tmp/issue83-crosswalk.json \\",
        "  --candidate-receipt docs/evidence/issue83/full-self-assertion-conversion-20261119-candidate-all-fixes.json \\",
        "  --converter-commit 1add34c \\",
        "  --canonical-commit 5ee55288b369da26f308f40813e545b78dff2753 \\",
        "  --canonical-schema-sha256 88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f \\",
        "  --oval-commit 2f140ee5c5dd1ed9606fcd5afc301f6baeb48706 \\",
        "  --output-json docs/evidence/issue83/source-audit-20261119.json \\",
        "  --output-md docs/evidence/issue83/source-audit-20261119.md",
        "```",
        "",
        "## Measured XCCDF source coverage",
        "",
        f"- Rule requires/conflicts: **{xccdf['rules_with_requires_or_conflicts']}** (requires {xccdf['requires_rows']}, conflicts {xccdf['conflicts_rows']})",
        f"- Group relationships: **{xccdf['groups_with_requires_or_conflicts']}** (requires {xccdf['group_requires_rows']}, conflicts {xccdf['group_conflicts_rows']})",
        f"- Standard metadata elements: `{json.dumps(xccdf['metadata_element_counts'], sort_keys=True)}`",
        f"- DISA extended fields are present on `{xccdf['disa_description_rule_field_counts'].get('VulnDiscussion', 0)}` Rules; only `VulnDiscussion` text is currently retained in the native Rule mapping.",
        "",
        "## OVAL schema inventory",
        "",
        f"- Declarations/grammar rows: **{oval.get('declarations', 0)} / {oval.get('grammar_rows', 0)}**; canonical mapping rows **{oval.get('canonical_mapping_rows', 0)}**.",
        f"- Official deprecation annotations: **{oval.get('official_deprecation_annotations', 0)}**; unproven declarations: **{oval.get('native_mapping_status', {}).get('unproven', 0)}**.",
        f"- Schematron assertions/reports and prose rows: **{oval.get('schematron_assertions', 0)} / {oval.get('schematron_reports', 0)} / {oval.get('prose_rows', 0)}**.",
        "",
        "## Ranked reusable gap inventory",
        "",
    ]
    for row in receipt["ranked_gap_inventory"]:
        lines.extend([
            f"{row['rank']}. **{row['priority']} — {row['class']}** ({row['disposition']})",
            f"   - Measured: `{json.dumps(row['measured'], sort_keys=True)}`",
            f"   - Action: {row['action']}",
        ])
    candidate = receipt.get("candidate_qualification")
    if candidate:
        lines.extend([
            "",
            "## Candidate Self-Assertion qualification",
            "",
            f"- Summary: `{json.dumps(candidate['summary'], sort_keys=True)}`",
            f"- Execution: **{candidate['execution']}**; independent equivalence: **{candidate['independent_equivalence']}**.",
            f"- Source-linked hold records: **{len(candidate['source_linked_holds'])}**.",
        ])
    lines.extend([
        "",
        "## Holds",
        "",
        "- The native contract for standard XCCDF remediation/identification metadata and structured DISA publisher metadata is not changed by this audit; canonical coordination is required.",
        "- Valid Windows downward traversal is a canonical schema hold, not a converter workaround. Deprecated source constructs stay separate and are not reintroduced.",
        "- No schema-valid conversion count in this receipt is a claim of scanner execution or source-equivalence.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crosswalk-json", type=Path, required=True)
    parser.add_argument("--candidate-receipt", type=Path)
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--canonical-commit", required=True)
    parser.add_argument("--canonical-schema-sha256", required=True)
    parser.add_argument("--oval-commit", required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = build(args.crosswalk_json, args.candidate_receipt,
                    converter_commit=args.converter_commit,
                    canonical_commit=args.canonical_commit,
                    canonical_schema_sha256=args.canonical_schema_sha256,
                    oval_commit=args.oval_commit)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(markdown(receipt), encoding="utf-8")
    print(json.dumps({
        "format": receipt["format"],
        "source_rules": receipt["source"]["source_rule_count"],
        "metadata_elements": receipt["xccdf"]["metadata_element_counts"],
        "candidate_holds": len(receipt.get("candidate_qualification", {}).get("source_linked_holds", [])) if receipt.get("candidate_qualification") else 0,
        "output_json": str(args.output_json),
        "output_md": str(args.output_md),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
