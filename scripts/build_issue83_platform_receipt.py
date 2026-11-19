#!/usr/bin/env python3
"""Build a compact platform receipt from one pinned converter package.

This is an accounting/reporting tool, not a converter. It reads the retained
production package, validates source identities and artifact hashes, and emits
per-platform Definition/Test dispositions. Runtime execution and equivalence
remain explicitly unproved.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from audit_self_assertion_parity import PIN, PREFIX, digest, sources

CONVERTED = {"CONVERTED_UNVERIFIED", "converted", "converted_unverified"}
HEXLEN = 64


def family(source_path: str) -> str:
    if not source_path.startswith(PREFIX):
        raise ValueError(f"source path outside pinned corpus: {source_path}")
    rest = source_path[len(PREFIX):]
    name = rest.split("/", 1)[0]
    if not name:
        raise ValueError(f"source path has no platform family: {source_path}")
    return name


def disposition(status: str) -> str:
    if status in CONVERTED:
        return "converted"
    if status == "blocked":
        return "blocked"
    if status in {"excluded", "intentionally_excluded"}:
        return "excluded"
    return "unreviewed"


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != HEXLEN:
        raise ValueError(f"{label} is not a SHA-256")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{label} is not a SHA-256") from exc
    return value


def _read_test_ledger(path: Path) -> list[dict[str, Any]]:
    rows = []
    seen = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"tests.jsonl line {line_number} is not an object")
        key = (row.get("source_path"), row.get("test_id"))
        if (not isinstance(key[0], str) or not isinstance(key[1], str) or
                key in seen):
            raise ValueError(f"invalid or duplicate Test at line {line_number}")
        seen.add(key)
        _require_sha(row.get("source_sha256"), f"Test {key} source_sha256")
        family(row["source_path"])
        rows.append(row)
    return rows


def _verify_manifest_artifacts(package: Path, manifest: dict[str, Any]) -> int:
    checked = 0
    for relative, metadata in manifest.get("artifacts", {}).items():
        if not isinstance(relative, str):
            raise ValueError("manifest artifact path is not a string")
        artifact_path = Path(relative)
        if artifact_path.is_absolute() or ".." in artifact_path.parts:
            raise ValueError(f"manifest artifact path escapes package: {relative}")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("sha256"), str):
            raise ValueError(f"manifest artifact metadata is malformed: {relative}")
        raw = (package / artifact_path).read_bytes()
        expected = _require_sha(metadata["sha256"], f"artifact {relative}")
        observed = digest(raw)
        if observed != expected:
            raise ValueError(f"artifact SHA-256 mismatch: {relative}")
        if metadata.get("bytes") is not None and metadata["bytes"] != len(raw):
            raise ValueError(f"artifact byte count mismatch: {relative}")
        checked += 1
    return checked


def _row_identity(row: dict[str, Any], key: str) -> dict[str, Any]:
    return {
        "source_path": row["source_path"],
        "source_xml_sha256": row["source_sha256"],
        key: row[key],
        "status": row.get("conversion_status", "missing"),
        "disposition": disposition(row.get("conversion_status", "missing")),
        "failure_class": row.get("failure_class"),
        "diagnostic": row.get("diagnostic"),
    }


def _summaries(rows: list[dict[str, Any]], key: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[family(row["source_path"])].append(row)
    platforms = {}
    blockers = []
    for name in sorted(grouped):
        cohort = grouped[name]
        counts = Counter(disposition(row.get("conversion_status", "missing")) for row in cohort)
        statuses = Counter(row.get("conversion_status", "missing") for row in cohort)
        platforms[name] = {
            "total": len(cohort),
            "converted": counts["converted"],
            "blocked": counts["blocked"],
            "excluded": counts["excluded"],
            "unreviewed": counts["unreviewed"],
            "status_counts": dict(sorted(statuses.items())),
        }
        blockers.extend(_row_identity(row, key) for row in cohort
                        if disposition(row.get("conversion_status", "missing")) != "converted")
    return platforms, sorted(blockers, key=lambda row: (row["source_path"], row[key]))


def build_receipt(package: Path, *, source_root: Path | None,
                  converter_commit: str, expected: dict[str, int] | None = None) -> dict[str, Any]:
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("source_commit") != PIN:
        raise ValueError("package source pin differs from approved Self-Assertion pin")
    definitions = json.loads((package / "definitions.json").read_text(encoding="utf-8"))
    if not isinstance(definitions, list):
        raise ValueError("definitions.json must be an array")
    tests = _read_test_ledger(package / "tests.jsonl")
    source_records = sources(source_root)[0] if source_root is not None else None
    seen_definitions = set()
    for row in definitions:
        if not isinstance(row, dict):
            raise ValueError("Definition ledger row is not an object")
        key = (row.get("source_path"), row.get("definition_id"))
        if key in seen_definitions or not all(isinstance(item, str) and item for item in key):
            raise ValueError(f"invalid or duplicate Definition identity: {key}")
        seen_definitions.add(key)
        _require_sha(row.get("source_sha256"), f"Definition {key} source_sha256")
        family(row["source_path"])
        if source_records is not None:
            source = source_records.get(row["source_path"])
            if source is None or source["sha256"] != row["source_sha256"] or row["definition_id"] not in source["definitions"]:
                raise ValueError(f"Definition source identity mismatch: {key}")
    if source_records is not None:
        expected_defs = {(path, ident) for path, record in source_records.items() for ident in record["definitions"]}
        if seen_definitions != expected_defs:
            raise ValueError("Definition ledger does not account for source universe")
        expected_tests = {(path, ident) for path, record in source_records.items() for ident in record["tests"]}
        observed_tests = {(row["source_path"], row["test_id"]) for row in tests}
        if observed_tests != expected_tests:
            raise ValueError("Test ledger does not account for source universe")
        for row in tests:
            source = source_records[row["source_path"]]
            if source["sha256"] != row["source_sha256"] or row["test_id"] not in source["tests"]:
                raise ValueError(f"Test source identity mismatch: {row['source_path']}, {row['test_id']}")
    def_platforms, def_blockers = _summaries(definitions, "definition_id")
    test_platforms, test_blockers = _summaries(tests, "test_id")
    artifact_count = _verify_manifest_artifacts(package, manifest)
    summary = {
        "definitions": len(definitions), "tests": len(tests),
        "converted_definitions": sum(row["converted"] for row in def_platforms.values()),
        "blocked_definitions": sum(row["blocked"] for row in def_platforms.values()),
        "excluded_definitions": sum(row["excluded"] for row in def_platforms.values()),
        "converted_tests": sum(row["converted"] for row in test_platforms.values()),
        "blocked_tests": sum(row["blocked"] for row in test_platforms.values()),
        "excluded_tests": sum(row["excluded"] for row in test_platforms.values()),
    }
    if expected:
        for key, value in expected.items():
            if summary.get(key) != value:
                raise ValueError(f"expected {key}={value}, observed {summary.get(key)}")
    return {
        "format": "scap-ng-tools/issue83/platform-receipt/1",
        "source": {"repository": manifest.get("source_repository"), "commit": PIN,
                   "root": "SCAP_1.4/OVAL_Test_Content", "identity": "source path + source ID + exact source XML SHA-256"},
        "converter": {"repository": "vanderpol/scap-ng-tools", "commit": converter_commit,
                      "entrypoint": manifest.get("converter"), "execution": "production package only"},
        "canonical_schema": {"version": manifest.get("schema", {}).get("schema_version"),
                             "commit": manifest.get("schema", {}).get("canonical_commit"),
                             "aggregate_sha256": manifest.get("schema", {}).get("aggregate_sha256")},
        "package": {"manifest_sha256": digest((package / "manifest.json").read_bytes()),
                    "definitions_ledger_sha256": digest((package / "definitions.json").read_bytes()),
                    "tests_ledger_sha256": digest((package / "tests.jsonl").read_bytes()),
                    "manifest_artifacts_verified": artifact_count},
        "summary": summary,
        "platforms": {"definitions": def_platforms, "tests": test_platforms},
        "blockers": {"definitions": def_blockers, "tests": test_blockers},
        "qualification": {"source_identity_validated": source_records is not None,
                          "runtime_execution": "not_run", "independent_oval_equivalence": "not_proved"},
    }


def markdown(receipt: dict[str, Any]) -> str:
    summary = receipt["summary"]
    lines = ["# OVAL Self-Assertion platform receipt", "", "This is source/package accounting only; runtime execution and independent OVAL equivalence are not proved.", "", f"- Source: `{receipt['source']['commit']}`", f"- Converter: `{receipt['converter']['commit']}`", f"- Canonical schema: `{receipt['canonical_schema']['commit']}` (`{receipt['canonical_schema']['aggregate_sha256']}`)", "", "| Family | Definitions converted/blocked/excluded | Tests converted/blocked/excluded |", "|---|---:|---:|"]
    families = sorted(set(receipt["platforms"]["definitions"]) | set(receipt["platforms"]["tests"]))
    for name in families:
        d, t = receipt["platforms"]["definitions"].get(name, {}), receipt["platforms"]["tests"].get(name, {})
        lines.append(f"| `{name}` | {d.get('converted', 0)}/{d.get('blocked', 0)}/{d.get('excluded', 0)} | {t.get('converted', 0)}/{t.get('blocked', 0)}/{t.get('excluded', 0)} |")
    lines += ["", f"Total: **{summary['converted_definitions']}/{summary['blocked_definitions']}/{summary['excluded_definitions']} Definitions**, **{summary['converted_tests']}/{summary['blocked_tests']}/{summary['excluded_tests']} Tests**.", "", f"Exact blocker rows: {len(receipt['blockers']['definitions'])} Definitions and {len(receipt['blockers']['tests'])} Tests.", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path)
    args = parser.parse_args()
    expected = {"definitions": 168, "tests": 803} if args.source_root else None
    receipt = build_receipt(args.package, source_root=args.source_root,
                            converter_commit=args.converter_commit, expected=expected)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.output_md:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(markdown(receipt), encoding="utf-8")
    print(json.dumps({"definitions": receipt["summary"]["definitions"], "tests": receipt["summary"]["tests"], "artifact_hashes_verified": receipt["package"]["manifest_artifacts_verified"]}))


if __name__ == "__main__":
    main()
