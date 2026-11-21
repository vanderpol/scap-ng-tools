#!/usr/bin/env python3
"""Compare two immutable Self-Assertion source pins without rewriting either.

The output is a source-fidelity receipt: file/member SHA-256 values, XML
Definition/Test IDs and explicit removed/changed classifications. It never
uses the converter and never treats source removal as converter recovery.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile

PREFIX = "SCAP_1.4/OVAL_Test_Content/"
XML_SUFFIX = ".xml"
ARCHIVE_SUFFIXES = {".zip", ".tarz"}


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def xml_inventory(raw: bytes) -> dict:
    root = ET.fromstring(raw)
    definitions = sorted(
        e.get("id") for e in root.iter()
        if local(e.tag) == "definition" and e.get("id"))
    tests = sorted(
        e.get("id") for e in root.iter()
        if local(e.tag).endswith("_test") and e.get("id"))
    return {"definitions": definitions, "tests": tests}


def file_inventory(root: Path) -> dict[str, dict]:
    base = root / "SCAP_1.4/OVAL_Test_Content"
    if not base.is_dir():
        raise ValueError(f"missing source content: {base}")
    output = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {XML_SUFFIX, *ARCHIVE_SUFFIXES}:
            continue
        relative = PREFIX + path.relative_to(base).as_posix()
        raw = path.read_bytes()
        record = {"sha256": digest(raw), "bytes": len(raw)}
        if path.suffix.lower() == XML_SUFFIX:
            record["xml"] = xml_inventory(raw)
        elif path.suffix.lower() == ".zip":
            members = {}
            with ZipFile(path) as archive:
                for info in sorted(archive.infolist(), key=lambda item: item.filename):
                    if info.is_dir():
                        continue
                    member_raw = archive.read(info)
                    member = {"sha256": digest(member_raw), "bytes": len(member_raw)}
                    if info.filename.lower().endswith(XML_SUFFIX):
                        try:
                            member["xml"] = xml_inventory(member_raw)
                        except ET.ParseError:
                            member["xml_error"] = True
                    members[info.filename] = member
            record["members"] = members
        output[relative] = record
    return output


def ids(records: dict[str, dict], kind: str) -> dict[str, list[str]]:
    result = {}
    for path, record in records.items():
        if "xml" in record:
            result[path] = record["xml"].get(kind, [])
        for member, child in record.get("members", {}).items():
            if "xml" in child:
                result[f"{path}!{member}"] = child["xml"].get(kind, [])
    return result


def build(old_root: Path, new_root: Path, old_commit: str, new_commit: str) -> dict:
    old = file_inventory(old_root)
    new = file_inventory(new_root)
    paths = sorted(set(old) | set(new))
    files = []
    for path in paths:
        before, after = old.get(path), new.get(path)
        if before is None:
            status = "added"
        elif after is None:
            status = "removed"
        elif before["sha256"] != after["sha256"]:
            status = "changed"
        else:
            status = "unchanged"
        files.append({"path": path, "status": status, "old": before, "new": after})
    old_defs, new_defs = ids(old, "definitions"), ids(new, "definitions")
    old_tests, new_tests = ids(old, "tests"), ids(new, "tests")
    def flatten(index):
        return sorted((path, ident) for path, values in index.items() for ident in values)
    old_def_ids, new_def_ids = set(flatten(old_defs)), set(flatten(new_defs))
    old_test_ids, new_test_ids = set(flatten(old_tests)), set(flatten(new_tests))
    return {
        "format": "scap-ng-tools/issue88-source-delta/1",
        "source": {
            "repository": "OVAL-Community/SCAP-Self-Assertion",
            "old_commit": old_commit,
            "new_commit": new_commit,
            "scope": PREFIX,
        },
        "files": files,
        "summary": {
            "old_files": len(old), "new_files": len(new),
            "old_xml_files": sum(path.lower().endswith(".xml") for path in old),
            "new_xml_files": sum(path.lower().endswith(".xml") for path in new),
            "added_files": sum(row["status"] == "added" for row in files),
            "removed_files": sum(row["status"] == "removed" for row in files),
            "changed_files": sum(row["status"] == "changed" for row in files),
            "unchanged_files": sum(row["status"] == "unchanged" for row in files),
            "old_definitions": len(old_def_ids), "new_definitions": len(new_def_ids),
            "old_tests": len(old_test_ids), "new_tests": len(new_test_ids),
            "removed_definition_identities": sorted(old_def_ids - new_def_ids),
            "added_definition_identities": sorted(new_def_ids - old_def_ids),
            "removed_test_identities": sorted(old_test_ids - new_test_ids),
            "added_test_identities": sorted(new_test_ids - old_test_ids),
            "classification": {
                "source_fixed_or_updated": sum(row["status"] == "changed" for row in files),
                "deprecated_or_invalid_content_removed": [
                    [path, ident] for path, ident in sorted(old_test_ids - new_test_ids)
                ],
                "converter_recovery": 0,
                "runtime_equivalence": "not_run",
            },
        },
    }


def write_markdown(receipt: dict, output_path: Path) -> None:
    summary = receipt["summary"]
    source = receipt["source"]
    lines = [
        "# Self-Assertion source pin delta",
        "",
        f"- Old source: `{source['old_commit']}`",
        f"- Corrected source: `{source['new_commit']}`",
        f"- Scope: `{source['scope']}`",
        "",
        "This is source accounting only. Removed or corrected content is not converter recovery.",
        "",
        "| Measure | Old | New | Delta |",
        "|---|---:|---:|---:|",
        f"| content files (XML/archives) | {summary['old_files']} | {summary['new_files']} | {summary['new_files'] - summary['old_files']} |",
        f"| direct XML files | {summary['old_xml_files']} | {summary['new_xml_files']} | {summary['new_xml_files'] - summary['old_xml_files']} |",
        f"| Definitions | {summary['old_definitions']} | {summary['new_definitions']} | {summary['new_definitions'] - summary['old_definitions']} |",
        f"| Tests | {summary['old_tests']} | {summary['new_tests']} | {summary['new_tests'] - summary['old_tests']} |",
        f"| changed files | — | {summary['changed_files']} | — |",
        "",
        "## Removed source identities",
        "",
    ]
    for path, ident in summary["removed_definition_identities"]:
        lines.append(f"- Definition `{ident}` in `{path}`")
    for path, ident in summary["removed_test_identities"]:
        lines.append(f"- Test `{ident}` in `{path}`")
    if not summary["removed_definition_identities"] and not summary["removed_test_identities"]:
        lines.append("- None")
    lines += [
        "",
        "## Disposition",
        "",
        "- `source_fixed_or_updated`: changed source bytes require a separate corrected-source qualification.",
        "- `deprecated_or_invalid_content_removed`: removed source identities remain excluded from the new denominator.",
        "- `converter_recovery`: 0; no converter result is inferred from the delta.",
        "- RI execution and independent OVAL equivalence: not run by this receipt.",
    ]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-root", type=Path, required=True)
    parser.add_argument("--new-root", type=Path, required=True)
    parser.add_argument("--old-commit", required=True)
    parser.add_argument("--new-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    result = build(args.old_root, args.new_root, args.old_commit, args.new_commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        write_markdown(result, Path(args.markdown))
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
