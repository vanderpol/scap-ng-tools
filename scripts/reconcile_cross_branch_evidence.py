#!/usr/bin/env python3
"""Reconcile source-linked qualification evidence across active Git refs.

This is intentionally an evidence join, not a new qualification run.  It
compares the same source archive and Rule identities across branches and
selects the newest available disposition receipt per ref.  Missing or older
branch evidence remains visible; it is never silently merged into the newest
result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

EVIDENCE_PATHS = (
    "docs/evidence/issue85/full65-blocker-disposition-20261122.json",
    "docs/evidence/issue85/full65-current-c428.json",
    "docs/evidence/issue85/full65-current-449.json",
)
ACCESS_PATH = "docs/evidence/issue83/accesstoken-family-audit.json"
CONCAT_PATH = "docs/evidence/issue83/oval-concat-replay-audit-20261122.json"


def _git_show(repo: Path, ref: str, path: str) -> tuple[Any, str] | None:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(repo), "show", f"{ref}:{path}"],
            stderr=subprocess.DEVNULL,
        )
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def _source_and_canonical(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if "source" in doc and isinstance(doc["source"], dict):
        source = doc["source"]
        source_norm = {
            "repository": source.get("repository", "niwc-atlantic/scap-content-library"),
            "commit": source.get("commit", source.get("signed_benchmark_commit")),
            "archive_sha256": source.get("archive_sha256", source.get("signed_archive_sha256")),
        }
    else:
        source_norm = {
            "repository": "niwc-atlantic/scap-content-library",
            "commit": doc.get("source_commit"),
            "archive_sha256": doc.get("source_archive_sha256"),
        }
    canonical = doc.get("canonical", {})
    if not isinstance(canonical, dict):
        canonical = {}
    canonical_norm = {
        "commit": canonical.get("commit", doc.get("canonical_schema_commit")),
        "flat_schema_sha256": canonical.get(
            "flat_schema_sha256", doc.get("schema_aggregate_sha256")),
    }
    return source_norm, canonical_norm


def _normalize(path: str, doc: dict[str, Any], blob_sha256: str) -> dict[str, Any]:
    source, canonical = _source_and_canonical(doc)
    if "after" in doc:
        counts = doc["after"]
        converter = doc.get("converter", {}).get("commit")
        categories = doc.get("categories", {})
        disposition = "full65-blocker-disposition/2"
        blocked_rows = doc.get("blocked_rules", [])
        gaps = doc.get("remaining_canonical_gaps", {})
        proof = doc.get("proof_boundary")
    else:
        counts = doc.get("candidate", {})
        converter = doc.get("converter", {}).get("commit") if isinstance(doc.get("converter"), dict) else doc.get("converter_commit")
        categories = doc.get("blocker_category_counts", doc.get("counts", {}).get("blocker_category_counts", {}))
        disposition = doc.get("format", "unknown")
        remaining = doc.get("remaining", {})
        blocked_rows = doc.get("blocked_rule_ids", remaining.get("blocked_rule_ids", []))
        gaps = {}
        proof = doc.get("qualification")
    blocked_ids = sorted({row.get("source_rule") for row in blocked_rows if row.get("source_rule")})
    dynamic_ids = sorted({
        row["source_rule"] for row in blocked_rows
        if "dynamic Variable Object Set" in row.get("message", "")
    })
    return {
        "path": path,
        "receipt_sha256": blob_sha256,
        "format": disposition,
        "source": source,
        "canonical": canonical,
        "converter_commit": converter,
        "counts": {key: counts.get(key) for key in ("converted", "blocked", "manual_only")},
        "categories": categories,
        "blocked_rule_count": len(blocked_ids),
        "blocked_rule_ids_sha256": hashlib.sha256(
            ("\n".join(blocked_ids) + "\n").encode()).hexdigest() if blocked_ids else None,
        "dynamic_variable_object_set_rule_ids": dynamic_ids,
        "to_integer_blocked": any("SV-221718" in item for item in blocked_ids),
        "remaining_canonical_gaps": gaps,
        "proof_boundary": proof,
    }


def reconcile_documents(documents: list[dict[str, Any]]) -> dict[str, Any]:
    if not documents:
        raise ValueError("no branch evidence was supplied")
    source_keys = {
        (json.dumps(row["source"], sort_keys=True), row["canonical"].get("flat_schema_sha256"))
        for row in documents
    }
    authoritative = [row for row in documents if row["format"] == "full65-blocker-disposition/2"]
    latest = authoritative[0] if authoritative else documents[0]
    latest_counts = latest["counts"]
    stale = [
        row["branch"] for row in documents
        if row["counts"] != latest_counts
        or row["format"] != latest["format"]
        or row["to_integer_blocked"] != latest["to_integer_blocked"]
    ]
    return {
        "format": "scap-ng-tools/cross-branch-evidence-reconciliation/1",
        "branch_count": len(documents),
        "authoritative_branch": latest["branch"],
        "source_identity_agrees": len({json.dumps(row["source"], sort_keys=True) for row in documents}) == 1,
        "canonical_pins": sorted(source_keys),
        "authoritative_counts": latest_counts,
        "authoritative_categories": latest["categories"],
        "authoritative_dynamic_variable_object_set_rule_ids": latest["dynamic_variable_object_set_rule_ids"],
        "authoritative_to_integer_blocked": latest["to_integer_blocked"],
        "stale_or_incomplete_branches": stale,
        "branches": documents,
        "limitations": [
            "This joins committed receipts; it does not regenerate content or prove runtime equivalence.",
            "A branch without the newest disposition receipt remains stale/incomplete, not successful.",
            "Canonical pin differences are preserved and are not reconciled by changing hashes.",
        ],
    }


def audit(repo: Path, refs: list[tuple[str, str]]) -> dict[str, Any]:
    rows = []
    for branch, ref in refs:
        found = []
        for path in EVIDENCE_PATHS:
            item = _git_show(repo, ref, path)
            if item:
                doc, digest = item
                found.append(_normalize(path, doc, digest))
        if not found:
            rows.append({"branch": branch, "ref": ref, "status": "no_full65_evidence"})
            continue
        preferred = next((row for row in found if row["format"] == "full65-blocker-disposition/2"), found[0])
        preferred["branch"] = branch
        preferred["ref"] = ref
        preferred["available_evidence"] = [row["path"] for row in found]
        prior = [row for row in found if row is not preferred]
        preferred["superseded_evidence"] = [
            {
                "path": row["path"],
                "counts": row["counts"],
                "to_integer_blocked": row["to_integer_blocked"],
                "blocked_rule_count": row["blocked_rule_count"],
                "converted_delta_to_preferred": (
                    preferred["counts"].get("converted", 0) - row["counts"].get("converted", 0)),
                "blocked_delta_to_preferred": (
                    preferred["counts"].get("blocked", 0) - row["counts"].get("blocked", 0)),
            }
            for row in prior
        ]
        preferred["cumulative_recovery_count"] = (
            preferred["counts"].get("converted", 0) - 6479)
        rows.append(preferred)
    usable = [row for row in rows if row.get("status") != "no_full65_evidence"]
    result = reconcile_documents(usable)
    missing = [row["branch"] for row in rows if row.get("status") == "no_full65_evidence"]
    result["stale_or_incomplete_branches"] = sorted(
        set(result["stale_or_incomplete_branches"]) | set(missing))
    result["refs"] = rows
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--branch", action="append", required=True,
                        help="label=git-ref (repeatable)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    refs = []
    for value in args.branch:
        if "=" not in value:
            parser.error("--branch must be label=git-ref")
        refs.append(tuple(value.split("=", 1)))
    result = audit(args.repo, refs)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "authoritative_branch": result["authoritative_branch"],
        "counts": result["authoritative_counts"],
        "dynamic_ids": result["authoritative_dynamic_variable_object_set_rule_ids"],
        "stale_or_incomplete": result["stale_or_incomplete_branches"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
