#!/usr/bin/env python3
"""Run the production converter against Issue #83 source witnesses.

This is intentionally a thin qualification runner: it does not derive
expected outcomes or alter source XML. Each row joins an original source Test
ID/hash to a separately generated positive witness and records the exact
converter disposition. Generated converter documents and receipts belong in
an external bounded evidence directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from scap_ng_tools.contracts.schema_snapshot_v041 import (
    CANONICAL_COMMIT, FLAT_SCHEMA_SHA256, Pinned041SchemaSnapshot,
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_schema_root(schema_root: Path, schema_commit: str) -> tuple[Path, str]:
    """Require the exact active 0.4.1 schema family before conversion."""
    if schema_commit != CANONICAL_COMMIT:
        raise ValueError(
            f"schema commit {schema_commit} is not the active canonical pin {CANONICAL_COMMIT}")
    snapshot = Pinned041SchemaSnapshot(schema_root)
    return snapshot.schema_root, FLAT_SCHEMA_SHA256


def classify(message: str) -> str:
    text = message.lower()
    # Deprecated source syntax is not a generic converter gap. Keep it
    # fail-closed, but give the qualification ledger a distinct disposition
    # so source-valid and deprecated cases cannot be conflated.
    if "deprecated" in text:
        return "deprecated_source_construct"
    if "possible_restriction" in text or "external variable" in text:
        return "canonical_input_constraint_hold"
    if "invalid int literal" in text:
        return "source_typed_literal_invalid"
    if "unsupported" in text or "held" in text:
        return "converter_unsupported_source"
    if "schema" in text or "validation" in text:
        return "converter_schema_or_validation_failure"
    return "converter_failure"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witness-root", type=Path, required=True)
    parser.add_argument("--witness-receipt", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--schema-commit", required=True)
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-prefix", default="agnostic/")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.output}")
    if args.timeout_seconds < 1:
        raise SystemExit("--timeout-seconds must be positive")
    schema_root, schema_family_sha256 = verify_schema_root(
        args.schema_root, args.schema_commit)
    receipt = json.loads(args.witness_receipt.read_text(encoding="utf-8"))
    rows = []
    selected = [row for row in receipt["tests"]
                if row["source_file"].startswith(args.source_prefix)]
    args.output.mkdir(parents=True)
    for ordinal, row in ((i, row) for i, row in enumerate(receipt["tests"], 1)
                          if row["source_file"].startswith(args.source_prefix)):
        candidates = sorted((args.witness_root / "positive").glob(
            f"{ordinal:04d}-*.xml"))
        base = {
            "ordinal": ordinal,
            "source_file": row["source_file"],
            "source_test_id": row["source_test_id"],
            "source_test_sha256": row["source_test_sha256"],
            "witness_definition_id": row["witness_definition_id"],
        }
        if len(candidates) != 1:
            rows.append({**base, "status": "harness_missing_witness",
                         "candidate_count": len(candidates)})
            continue
        witness = candidates[0]
        output = args.output / f"{ordinal:04d}"
        witness_sha = digest(witness.read_bytes())
        command = [sys.executable, "-m", "scap_ng_tools.converter.direct04",
                   "--schema-root", str(schema_root), "--source", str(witness),
                   "--sha256", witness_sha, "--oval-definition",
                   row["witness_definition_id"], "--source-commit", args.source_commit,
                   "--source-path", f"witness/{row['source_file']}!{row['source_test_id']}",
                   "--output", str(output)]
        try:
            process = subprocess.run(command, capture_output=True, text=True,
                                     timeout=args.timeout_seconds, check=False)
            diagnostic = (process.stderr.strip() or process.stdout.strip()).splitlines()
            diagnostic = diagnostic[-1] if diagnostic else ""
            status = "converted" if process.returncode == 0 else "blocked"
            result = {**base, "witness_sha256": witness_sha, "status": status,
                      "returncode": process.returncode}
            if status == "blocked":
                result["failure_class"] = classify(diagnostic)
                result["diagnostic"] = diagnostic[:500]
            else:
                result["outputs"] = {
                    name: {"bytes": (output / name).stat().st_size,
                           "sha256": digest((output / name).read_bytes())}
                    for name in ("assessment.json", "assessment.yaml",
                                 "source-trace.json", "conversion-scope.json")
                    if (output / name).is_file()}
        except subprocess.TimeoutExpired:
            result = {**base, "witness_sha256": witness_sha, "status": "timeout",
                      "failure_class": "converter_timeout"}
        rows.append(result)
    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    failure_classes = {}
    for row in rows:
        if row.get("failure_class"):
            failure_classes[row["failure_class"]] = failure_classes.get(
                row["failure_class"], 0) + 1
    result = {
        "format": "scap-ng-tools/issue83-witness-conversion/1",
        "source_commit": args.source_commit,
        "schema_commit": args.schema_commit,
        "schema_family_sha256": schema_family_sha256,
        "schema_root_verified": True,
        "converter_commit": args.converter_commit,
        "witness_receipt_sha256": digest(args.witness_receipt.read_bytes()),
        "source_prefix": args.source_prefix,
        "tests_considered": len(selected),
        "counts": counts,
        "failure_classes": failure_classes,
        "tests": rows,
        "qualification": "source-witness converter qualification only; runtime equivalence not proved",
    }
    path = args.output / "receipt.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "counts": counts,
                      "failure_classes": failure_classes,
                      "receipt_sha256": digest(path.read_bytes())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
