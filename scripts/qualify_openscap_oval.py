#!/usr/bin/env python3
"""Run pinned OVAL XML through an installed OpenSCAP engine.

This is an independent source-engine qualification harness, not an RI evaluator.
It deliberately records when validation is skipped (required for OpenSCAP 1.3.9
against OVAL 5.12.3 content), retains raw results in an external bounded output
root, and commits only a compact source/result ledger.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
import xml.etree.ElementTree as ET

FAMILIES = (
    "agnostic", "aix", "asa", "ios", "iosxe", "junos", "linux", "macos",
    "panos", "solaris", "unix", "windows",
)
OUTCOMES = {"true", "false", "unknown", "error", "not_evaluated", "not_applicable"}
_HEX = re.compile(r"^[0-9a-f]{64}$")


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_name(relative: Path) -> str:
    """Create a deterministic filename without allowing path traversal."""
    relative_text = relative.as_posix()
    return f"{hashlib.sha256(relative_text.encode()).hexdigest()[:16]}-{relative.name}"


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_results(path: Path) -> list[dict[str, str]]:
    """Extract only Definition IDs/results; never retain collected Item values."""
    root = ET.parse(path).getroot()
    rows = []
    for element in root.iter():
        if local_name(element.tag) != "definition" or "result" not in element.attrib:
            continue
        definition_id = element.attrib.get("definition_id") or element.attrib.get("id")
        result = element.attrib["result"].lower()
        if not definition_id:
            continue
        rows.append({"definition_id": definition_id, "result": result})
    return rows


def summarize_outcomes(definitions: list[dict[str, str]]) -> dict[str, int]:
    counts = {outcome: 0 for outcome in sorted(OUTCOMES)}
    for row in definitions:
        result = row["result"]
        counts[result] = counts.get(result, 0) + 1
    return {key: value for key, value in counts.items() if value}


def sanitize_diagnostic(text: str, replacements: tuple[tuple[str, str], ...]) -> str:
    for old, new in replacements:
        if old:
            text = text.replace(old, new)
    # Do not commit host identifiers, usernames or collected paths in a
    # machine-readable receipt. Raw logs stay in the caller-owned external
    # evidence directory when needed for diagnosis.
    text = re.sub(r"/proc/[^\s]+", "<proc-entry>", text)
    text = re.sub(r"/run/user/\d+", "/run/user/<uid>", text)
    text = re.sub(r"/home/[^\s]+", "/home/<user>", text)
    text = re.sub(r"/tmp/[^\s]+", "/tmp/<run>", text)
    text = re.sub(r"/var/lib/rpm/[^\s]+", "/var/lib/rpm/<database>", text)
    # Keep the receipt safe and bounded even when a probe emits a long error.
    text = re.sub(r"\s+", " ", text).strip()
    return text[-1000:]


def engine_version(executable: str) -> str:
    process = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, check=False,
        timeout=15,
    )
    text = (process.stdout or process.stderr).strip()
    first_line = text.splitlines()[0] if text else ""
    return sanitize_diagnostic(first_line, ())


def terminate(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def run_one(
    source: Path,
    corpus: Path,
    output: Path,
    executable: str,
    timeout_seconds: int,
    max_result_bytes: int,
    source_commit: str,
) -> dict[str, Any]:
    relative = source.relative_to(corpus)
    stem = safe_name(relative)
    result_path = output / "results" / f"{stem}.xml"
    stdout_path = output / "logs" / f"{stem}.stdout.log"
    stderr_path = output / "logs" / f"{stem}.stderr.log"
    source_sha256 = digest_file(source)
    command = [executable, "oval", "eval", "--skip-valid", "--results", str(result_path), str(source)]
    started = time.monotonic()
    status = "execution_error"
    returncode: int | None = None
    limit_reason = None
    (output / "results").mkdir(parents=True, exist_ok=True)
    (output / "logs").mkdir(parents=True, exist_ok=True)
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            while process.poll() is None:
                if result_path.exists() and result_path.stat().st_size > max_result_bytes:
                    limit_reason = "result_size_limit"
                    terminate(process)
                    break
                if time.monotonic() - started > timeout_seconds:
                    limit_reason = "timeout"
                    terminate(process)
                    break
                time.sleep(0.05)
            returncode = process.poll()
            if returncode is None:
                returncode = process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired) as exc:
            limit_reason = "process_failure"
            returncode = None
            stderr.write(str(exc).encode("utf-8", "replace"))
    elapsed = round(time.monotonic() - started, 3)
    replacements = ((str(corpus), "<corpus>"), (str(output), "<output>"))
    stderr_tail = sanitize_diagnostic(stderr_path.read_text(errors="replace"), replacements)
    stdout_tail = sanitize_diagnostic(stdout_path.read_text(errors="replace"), replacements)
    definitions: list[dict[str, str]] = []
    parse_error = None
    result_sha256 = None
    result_bytes = result_path.stat().st_size if result_path.exists() else 0
    if limit_reason:
        status = limit_reason
    elif result_path.exists():
        result_sha256 = digest_file(result_path)
        try:
            definitions = parse_results(result_path)
            status = "completed" if returncode == 0 else "completed_with_engine_error"
        except (ET.ParseError, OSError) as exc:
            parse_error = sanitize_diagnostic(str(exc), replacements)
            status = "result_parse_error"
    elif returncode == 0:
        status = "missing_results"
    diagnostic = stderr_tail or stdout_tail or parse_error or ""
    return {
        "family": relative.parts[0] if relative.parts else "",
        "source_path": relative.as_posix(),
        "source_commit": source_commit,
        "source_sha256": source_sha256,
        "status": status,
        "returncode": returncode,
        "duration_seconds": elapsed,
        "result_bytes": result_bytes,
        "result_sha256": result_sha256,
        "definitions": definitions,
        "definition_count": len(definitions),
        "outcomes": summarize_outcomes(definitions),
        "diagnostic": diagnostic,
        "command": [executable, "oval", "eval", "--skip-valid", "--results", "<external-result>", "<source>"],
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = ["family", "source_path", "source_sha256", "status", "returncode",
              "duration_seconds", "result_bytes", "result_sha256", "definition_count",
              "outcomes", "diagnostic"]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            values = dict(row)
            values["outcomes"] = json.dumps(row["outcomes"], sort_keys=True)
            values.pop("definitions", None)
            values.pop("command", None)
            writer.writerow({field: values.get(field) for field in fields})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True,
                        help="OVAL_Test_Content root containing platform directories")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="new external bounded output directory; never overwritten")
    parser.add_argument("--family", action="append", choices=FAMILIES,
                        help="restrict to one or more families (default: all present families)")
    parser.add_argument("--oscap", default="oscap")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--max-result-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.output}")
    if not args.corpus.is_dir():
        raise SystemExit(f"corpus is not a directory: {args.corpus}")
    if args.timeout_seconds < 1 or args.max_result_bytes < 1024:
        raise SystemExit("timeout and result limit must be positive (result limit >= 1024)")
    selected = set(args.family or FAMILIES)
    sources = sorted(
        source for family in selected if (args.corpus / family).is_dir()
        for source in (args.corpus / family).rglob("*.xml") if source.is_file()
    )
    if not sources:
        raise SystemExit("no XML source files selected")
    args.output.mkdir(parents=True)
    rows = [run_one(source, args.corpus, args.output, args.oscap,
                    args.timeout_seconds, args.max_result_bytes, args.source_commit)
            for source in sources]
    summary: dict[str, Any] = {"files": len(rows), "statuses": {}, "outcomes": {}, "families": {}}
    for row in rows:
        summary["statuses"][row["status"]] = summary["statuses"].get(row["status"], 0) + 1
        for outcome, count in row["outcomes"].items():
            summary["outcomes"][outcome] = summary["outcomes"].get(outcome, 0) + count
        family = summary["families"].setdefault(row["family"], {"files": 0, "statuses": {}, "outcomes": {}})
        family["files"] += 1
        family["statuses"][row["status"]] = family["statuses"].get(row["status"], 0) + 1
        for outcome, count in row["outcomes"].items():
            family["outcomes"][outcome] = family["outcomes"].get(outcome, 0) + count
    receipt = {
        "format": "scap-ng-tools/openscap-oval-ledger/1",
        "source_commit": args.source_commit,
        "corpus": "OVAL_Test_Content",
        "engine": {"executable": args.oscap, "version": engine_version(args.oscap),
                   "validation": "skipped (--skip-valid)", "reported_oval_version": "engine-dependent"},
        "limits": {"timeout_seconds": args.timeout_seconds, "max_result_bytes": args.max_result_bytes},
        "qualification": "independent legacy OpenSCAP source execution; not SCAP-NG/OVAL 5.12.3 equivalence",
        "summary": summary,
        "files": rows,
    }
    (args.output / "ledger.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_csv(args.output / "ledger.csv", rows)
    print(json.dumps({"output": str(args.output), "summary": summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
