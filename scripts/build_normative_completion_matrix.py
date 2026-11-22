#!/usr/bin/env python3
"""Build a conservative feature-level OVAL 5.12.3 completion matrix.

The source crosswalk is authoritative for structural grammar evidence. This
normalizer collapses structural child rows into distinct top-level source
feature declarations, preserves exact QName/schema identity, and deliberately
keeps mapped features ``mapped_unproven`` until converter and runtime evidence
exists. It never treats an XSD name or a mapping file as proof of semantics.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

FORMAT = "scap-ng-tools/normative-completion-matrix/1"
TOP_LEVEL_PATH = "/element[0]"


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _platform(schema_file: str) -> str:
    name = schema_file.removesuffix("-definitions-schema.xsd").removesuffix(
        "-system-characteristics-schema.xsd")
    return name or "unknown"


def _candidate_summary(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for candidate in candidates:
        rows.append({key: candidate.get(key) for key in (
            "capability", "mapping_file", "source_role", "source_language",
            "source_schema", "source_namespace", "source_name",
            "converter_entrypoint", "mapping_status", "field_mapping_status",
            "converter_proof", "runtime_equivalence",
        )})
    return sorted(rows, key=lambda row: (
        row.get("capability") or "", row.get("source_role") or "",
        row.get("mapping_file") or ""))


def _classify(row: dict[str, Any]) -> str:
    if row.get("deprecation") or row.get("disposition") == "deprecated_migration":
        return "deprecated"
    if row.get("canonical_mapping_candidates"):
        return "mapped_unproven"
    return "unmapped_source_feature"


# These rows are evidence needed to reconstruct the source grammar, not
# independently authored source features. They must not inflate an
# ``unmapped_source_feature`` count.
_SUPPORTING_ROWS = frozenset({
    "annotation", "appinfo", "comment", "documentation",
    "deprecated_info", "evaluation_chart", "evaluation_documentation",
    "element_mapping", "field", "item", "name", "object", "reason",
    "selector", "state", "test", "version",
})
_SCHEMATRON_ROWS = frozenset({"assert", "let", "report", "rule", "value-of"})


def _grammar_classify(row: dict[str, Any]) -> str:
    direct = _classify(row)
    if direct != "unmapped_source_feature":
        return direct
    kind = row.get("source_kind")
    if kind in _SUPPORTING_ROWS:
        return "structural_supporting_evidence"
    if kind in _SCHEMATRON_ROWS:
        return "semantic_constraint_unproven"
    return direct


def _grammar_inventory(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize every structural row without treating grammar as proof.

    The feature matrix intentionally has one row per top-level source
    declaration. ``rows`` also contains inherited members, particles,
    Schematron expressions and documentation records. Keeping their
    dispositions as counts prevents the compact report from implying that
    the top-level table is an exhaustive field/attribute crosswalk.
    """
    by_kind: dict[str, Counter[str]] = defaultdict(Counter)
    by_schema: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        classification = _grammar_classify(row)
        by_kind[row.get("source_kind", "unknown")][classification] += 1
        by_schema[row.get("schema_file", "unknown")][classification] += 1
    return {
        "rows": len(rows),
        "by_source_kind": {
            kind: dict(sorted(counts.items()))
            for kind, counts in sorted(by_kind.items())
        },
        "by_schema": {
            schema: dict(sorted(counts.items()))
            for schema, counts in sorted(by_schema.items())
        },
        "policy": (
            "Supporting rows are source-grammar evidence rather than distinct "
            "features; Schematron rows are semantic constraints. Neither "
            "classification establishes native representability, converter parity "
            "or runtime semantics. Direct source declaration rows are the "
            "separate top-level feature table."
        ),
    }


def build(crosswalk: dict[str, Any], *, source_sha256: str,
          source_path: str) -> dict[str, Any]:
    if crosswalk.get("format") != "scap-ng-tools/issue83-source-crosswalk/1":
        raise ValueError("unexpected source crosswalk format")
    inventory = crosswalk.get("oval_schema_inventory")
    if not isinstance(inventory, dict):
        raise ValueError("crosswalk has no OVAL schema inventory")
    rows = inventory.get("grammar_rows", [])
    features = []
    identities: set[tuple[str, str]] = set()
    for row in rows:
        if (row.get("source_kind") != "element"
                or row.get("source_path") != TOP_LEVEL_PATH):
            continue
        schema_file = row.get("schema_file")
        source_qname = row.get("source_qname")
        if not schema_file or not source_qname:
            raise ValueError("top-level source element is missing schema/QName identity")
        identity = (schema_file, source_qname)
        if identity in identities:
            raise ValueError("duplicate top-level source identity: "
                             + schema_file + "::" + source_qname)
        identities.add(identity)
        classification = _classify(row)
        candidates = row.get("canonical_mapping_candidates") or []
        roles = sorted({candidate.get("source_role") for candidate in candidates
                         if candidate.get("source_role")})
        features.append({
            "source_schema": row.get("schema_file"),
            "platform": _platform(row.get("schema_file", "")),
            "source_qname": row.get("source_qname"),
            "source_name": row.get("source_name"),
            "source_kind": row.get("source_kind"),
            "classification": classification,
            "source_deprecation": row.get("deprecation", []),
            "source_shape": {
                "attributes": row.get("attributes", {}),
                "member_names": row.get("source_member_names", []),
                "enumeration_values": row.get("enumeration_values", []),
            },
            "canonical_mapping_roles": roles,
            "canonical_mapping_candidates": _candidate_summary(candidates),
            "semantic_proof": "not_proved",
            "converter_qualification": "not_proved",
            "ri_runtime": "not_run",
        })
    features.sort(key=lambda row: (row["source_schema"], row["source_qname"]))
    by_status: Counter[str] = Counter(row["classification"] for row in features)
    by_platform: dict[str, Counter[str]] = defaultdict(Counter)
    for row in features:
        by_platform[row["platform"]][row["classification"]] += 1
    return {
        "format": FORMAT,
        "source": {
            "crosswalk_path": source_path,
            "crosswalk_sha256": source_sha256,
            "source_commit": crosswalk["source"]["commit"],
            "oval_schema_commit": inventory["source_commit_expected"],
            "canonical_mapping_commit": inventory["summary"].get("canonical_mapping_commit"),
        },
        "policy": {
            "top_level_feature_selector": "source_kind=element and source_path=/element[0]",
            "mapped_meaning": "A canonical mapping candidate is representability evidence only; it is not converter or runtime proof.",
            "unmapped_meaning": "No exact canonical mapping candidate was found in the supplied pinned mapping inventory; this is a review hold, not automatically a canonical gap.",
            "deprecated_meaning": "The pinned XSD/Schematron marks the declaration deprecated; source replacement and migration policy remain separate evidence.",
        },
        "counts": {
            "distinct_top_level_features": len(features),
            "by_classification": dict(sorted(by_status.items())),
            "by_platform": {
                platform: dict(sorted(counts.items()))
                for platform, counts in sorted(by_platform.items())
            },
            "structural_grammar_rows": len(rows),
            "structural_declarations": inventory["summary"].get("declarations"),
            "canonical_mapping_rows": inventory["summary"].get("canonical_mapping_rows"),
        },
        "grammar_inventory": _grammar_inventory(rows),
        "features": features,
        "qualification": {
            "source_structure": "pinned and structurally inventoried",
            "converter_source_parity": "not_run",
            "ri_runtime": "not_run",
            "independent_equivalence": "not_proved",
        },
    }


def compact(matrix: dict[str, Any]) -> dict[str, Any]:
    """Return a versioned summary while retaining a hash of external rows."""
    result = dict(matrix)
    features = result.pop("features")
    result["features_external"] = {
        "count": len(features),
        "sha256": sha256(json.dumps(
            features, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
    }
    return result


def markdown(matrix: dict[str, Any]) -> str:
    counts = matrix["counts"]
    lines = [
        "# Normative SCAP 1.4 completion matrix",
        "",
        "This matrix is generated from the pinned OVAL 5.12.3 source crosswalk.",
        "It normalizes top-level source declarations and deliberately does not "
        "promote schema or mapping presence into converter or runtime proof.",
        "",
        f"- Source commit: `{matrix['source']['source_commit']}`",
        f"- OVAL schema commit: `{matrix['source']['oval_schema_commit']}`",
        f"- Canonical mapping commit: `{matrix['source']['canonical_mapping_commit']}`",
        f"- Input crosswalk SHA-256: `{matrix['source']['crosswalk_sha256']}`",
        f"- Distinct top-level features: **{counts['distinct_top_level_features']}**",
        f"- Structural grammar rows dispositioned: **{matrix['grammar_inventory']['rows']}**",
        "",
        "## Classification",
        "",
        "| Classification | Count | Meaning |",
        "|---|---:|---|",
        f"| deprecated | {counts['by_classification'].get('deprecated', 0)} | Official source deprecation evidence; not active support |",
        f"| mapped_unproven | {counts['by_classification'].get('mapped_unproven', 0)} | Canonical mapping candidate exists; converter/semantic/runtime proof remains separate |",
        f"| unmapped_source_feature | {counts['by_classification'].get('unmapped_source_feature', 0)} | Exact mapping absent; review hold, not automatically a canonical gap |",
        "",
        "## By platform/schema family",
        "",
        "| Platform | Deprecated | Mapped, unproven | Unmapped hold |",
        "|---|---:|---:|---:|",
    ]
    for platform, data in counts["by_platform"].items():
        lines.append(f"| `{platform}` | {data.get('deprecated', 0)} | {data.get('mapped_unproven', 0)} | {data.get('unmapped_source_feature', 0)} |")
    lines.extend([
        "",
        "## Structural grammar evidence",
        "",
        "The source crosswalk contains inherited members, particles, attributes, "
        "Schematron expressions and documentation in addition to top-level "
        "declarations. Their disposition counts are retained in the machine "
        "matrix under `grammar_inventory`; a row with no mapping is a review "
        "hold, not an automatic canonical gap.",
        "",
        "Supporting grammar rows are not distinct source features; Schematron "
        "rows remain semantic constraints requiring separate proof. The compact "
        "JSON retains these dimensions so they cannot be mistaken for 413 "
        "top-level converter blockers.",
        "",
        "## Proof boundaries",
        "",
        "Every feature row carries source QName, schema family, source shape, exact mapping candidates and independent proof fields. Current structural evidence does not prove converter source parity, RI execution, or independent OVAL equivalence.",
        "",
        "The full feature rows are intentionally generated externally when large; this compact report is reproducible from the recorded crosswalk hash.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crosswalk-json", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    parser.add_argument(
        "--source-label",
        help="stable logical label recorded instead of a local input path",
    )
    parser.add_argument("--compact", action="store_true",
                        help="omit per-feature rows from the versioned output")
    args = parser.parse_args(argv)
    source_sha = file_sha256(args.crosswalk_json)
    matrix = build(json.loads(args.crosswalk_json.read_text(encoding="utf-8")),
                   source_sha256=source_sha,
                   source_path=args.source_label or str(args.crosswalk_json))
    if args.compact:
        matrix = compact(matrix)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(markdown(matrix), encoding="utf-8")
    print(json.dumps({"format": FORMAT, **matrix["counts"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
