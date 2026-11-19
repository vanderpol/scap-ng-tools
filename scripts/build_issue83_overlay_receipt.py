#!/usr/bin/env python3
"""Build a compact receipt for a pinned Self-Assertion overlay conversion.

The converter output and source checkout remain external.  This verifier joins
all source-linked ledger rows to the exact synthetic/source commit, checks the
source bytes and hashes, and publishes only bounded summaries and blocker rows.
It never derives expected outcomes or scanner equivalence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
from io import BytesIO
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def tree_digest(root: Path) -> tuple[str, int, int]:
    h = hashlib.sha256()
    files = 0
    total = 0
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        raw = path.read_bytes()
        rel = path.relative_to(root).as_posix()
        h.update(rel.encode()); h.update(b"\0"); h.update(hashlib.sha256(raw).digest())
        files += 1; total += len(raw)
    return h.hexdigest(), files, total


def git_blob(repo: Path, commit: str, path: str) -> bytes:
    result = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"],
                            check=True, capture_output=True)
    return result.stdout


def source_verify(source_root: Path, repo: Path, commit: str) -> dict:
    corpus = source_root / "SCAP_1.4" / "OVAL_Test_Content"
    manifest, files, bytes_ = tree_digest(corpus)
    verified = 0
    for path in sorted(p for p in corpus.rglob("*") if p.is_file()):
        rel = path.relative_to(source_root).as_posix()
        if path.suffix.lower() not in {".xml", ".zip"}:
            continue
        expected = git_blob(repo, commit, rel)
        actual = path.read_bytes()
        if expected != actual:
            raise ValueError(f"source commit bytes differ: {rel}")
        verified += 1
    embedded = corpus / "agnostic" / "oval-def-ext.zip"
    member = "oval-def-ext.xml"
    with ZipFile(embedded) as archive:
        member_raw = archive.read(member)
    commit_archive = git_blob(repo, commit,
                              "SCAP_1.4/OVAL_Test_Content/agnostic/oval-def-ext.zip")
    with ZipFile(BytesIO(commit_archive)) as archive:
        if archive.read(member) != member_raw:
            raise ValueError("embedded OVAL member differs from source commit")
    return {"manifest_sha256": manifest, "files": files, "bytes": bytes_,
            "git_verified_files": verified, "embedded_member": member,
            "embedded_member_sha256": sha(member_raw)}


def platform(path: str) -> str:
    parts = path.split("/")
    try:
        return parts[parts.index("OVAL_Test_Content") + 1]
    except ValueError:
        return "unknown"


def summarize(rows: list[dict], key: str) -> dict:
    result = defaultdict(Counter)
    for row in rows:
        result[platform(row["source_path"])][row[key]] += 1
    return {name: dict(sorted(counter.items())) for name, counter in sorted(result.items())}


def compact_row(row: dict, *, test: bool = False) -> dict:
    keys = ["source_path", "source_sha256", "failure_class", "diagnostic"]
    if test:
        keys += ["test_id", "definition_ids"]
    else:
        keys += ["definition_id", "source_test_ids"]
    return {key: row.get(key) for key in keys}


def output_digest(root: Path) -> dict:
    digest, files, bytes_ = tree_digest(root)
    return {"tree_sha256": digest, "files": files, "bytes": bytes_}


def build(args: argparse.Namespace) -> tuple[dict, str]:
    root = args.output
    definitions = json.loads((root / "definitions.json").read_text())
    tests = [json.loads(line) for line in (root / "tests.jsonl").read_text().splitlines()]
    source = source_verify(args.source_root, args.source_repo, args.source_commit)
    blocked_definitions = [row for row in definitions if row["conversion_status"] == "blocked"]
    blocked_tests = [row for row in tests if row["conversion_status"] == "blocked"]
    result = {
        "format": "scap-ng-tools/issue83-self-assertion-overlay-receipt/1",
        "qualification": "schema admission/conversion only; execution and independent OVAL equivalence not proved",
        "pins": {
            "source_commit": args.source_commit,
            "source_base_commit": args.source_base_commit,
            "source_manifest_sha256": source["manifest_sha256"],
            "oval_schema_commit": args.oval_commit,
            "canonical_schema_commit": args.canonical_commit,
            "canonical_schema_family_sha256": args.schema_family_sha256,
            "converter_commit": args.converter_commit,
        },
        "source_overlay": {
            "construction": "Synthetic local commit built from the pinned base with the listed upstream correction blobs; it is not a pushed upstream merge.",
            "correction_commits": {
                "5": "cc3be23f51913561c96aacaf36f4838a78100cdf",
                "6": "33c6ad2bb254f2c60274a19891a9f9973f985e76",
                "7": "c06d4899af19147a12add8008859a29a1de579e4",
                "8_19": "0a1ee9365aff7962118f316ed9df822217bbf850",
                "9": "e4ebc8722501c9911fc1d6c8682917c4276a3e1b",
                "10": "8d8f1eb088f15aadf7d28cc6221d2808dc930a7f",
                "11": "088b6e9083eca68c45196bd3c8eb7f1ba5d6c263",
                "12": "fa62bece68f7b86bbdd71db2fa30c40fc35d7e92",
                "13": "6dbdda26e56ba23f3ba0a3a8b39b2a4a1cfcce30",
                "14": "50f801e3f4bdb5d3f6583195ad2ce29a2920546d",
                "15": "8132076d52362fe54da357da5f9a3178a1a8ff00",
                "16": "799e8d6dbc43fe68044996c9cf2628f13c17a320",
                "17": "d3c93ced3a7518e875d61079d945ade6669af442",
                "18": "8728b036c093f90ddb05b7b5d330ed4f206b4c18",
                "20": "f63e2c899ef97f93198d8b6663ead93e105d0a3f",
                "21": "9e079baea4432b3babff5429ca726c281872de1f",
            },
            "removed_paths": [
                "SCAP_1.4/OVAL_Test_Content/solaris/sol-def_package511_test.xml",
                "SCAP_1.4/OVAL_Test_Content/solaris/sol-def_package_test.xml",
                "SCAP_1.4/OVAL_Test_Content/junos/junos-def_xml_config_test.xml",
            ],
        },
        "source_verification": source,
        "output": output_digest(root),
        "summary": {
            "definitions": len(definitions),
            "tests": len(tests),
            "converted_definitions": sum(r["conversion_status"] == "CONVERTED_UNVERIFIED" for r in definitions),
            "blocked_definitions": len(blocked_definitions),
            "converted_tests": sum(r["conversion_status"] == "CONVERTED_UNVERIFIED" for r in tests),
            "blocked_tests": len(blocked_tests),
            "execution": "not_run",
            "schema_validated_documents": sum(r.get("schema_validated", False) for r in definitions),
        },
        "by_platform": {
            "definitions": summarize(definitions, "conversion_status"),
            "tests": summarize(tests, "conversion_status"),
        },
        "blocked": {
            "definitions": [compact_row(row) for row in blocked_definitions],
            "tests": [compact_row(row, test=True) for row in blocked_tests],
        },
        "reproduction": {
            "command": "PYTHONPATH=src .venv/bin/python scripts/convert_self_assertion_corpus.py --corpus <overlay-root> --schema-root <schema-root> --source-commit <source-commit> --output <external-output> --python <repo>/.venv/bin/python",
            "verifier": "PYTHONPATH=src .venv/bin/python scripts/build_issue83_overlay_receipt.py ...",
            "source_artifacts": "external; only hashes and bounded blocker rows are committed",
        },
    }
    lines = ["# Self-Assertion source-correction overlay receipt", "",
             f"Source overlay commit: `{args.source_commit}` (base `{args.source_base_commit}`).  ",
             f"Converter: `{args.converter_commit}`; canonical schema: `{args.canonical_commit}`.", "",
             "This is schema admission/conversion evidence only; execution and independent OVAL equivalence are not proved.", "",
             "## Summary", "", "| Record | Total | Converted | Blocked |", "|---|---:|---:|---:|",
             f"| Definitions | {len(definitions)} | {result['summary']['converted_definitions']} | {len(blocked_definitions)} |",
             f"| Tests | {len(tests)} | {result['summary']['converted_tests']} | {len(blocked_tests)} |", "",
             "## Platform outcomes", "", "| Platform | Definitions | Tests |", "|---|---|---|"]
    for name in sorted(set(result["by_platform"]["definitions"]) | set(result["by_platform"]["tests"])):
        lines.append(f"| {name} | `{result['by_platform']['definitions'].get(name, {})}` | `{result['by_platform']['tests'].get(name, {})}` |")
    lines += ["", "## Remaining Definition blockers", "", "| Definition | Class | Source |", "|---|---|---|"]
    for row in result["blocked"]["definitions"]:
        lines.append(f"| `{row['definition_id']}` | `{row['failure_class']}` | `{row['source_path']}` |")
    lines += ["", "## Holds", "", "- External Variable/Input cases remain a canonical input-contract hold.",
              "- iOS `version55_test` remains a canonical capability gap.",
              "- Three Windows registry traversal families remain canonical schema holds.",
              "- No runtime execution or independent OVAL equivalence is claimed.", ""]
    return result, "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-base-commit", default="e3538595c5083b9c34d937a81d319234df9bbfaa")
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--canonical-commit", required=True)
    parser.add_argument("--schema-family-sha256", required=True)
    parser.add_argument("--oval-commit", required=True)
    parser.add_argument("--report-json", type=Path, required=True)
    parser.add_argument("--report-md", type=Path, required=True)
    args = parser.parse_args()
    result, markdown = build(args)
    args.report_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    args.report_md.write_text(markdown)
    print(json.dumps(result["summary"], sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
