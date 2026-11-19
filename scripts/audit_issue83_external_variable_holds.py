#!/usr/bin/env python3
"""Join canonical-input converter holds to exact OVAL Variable source evidence."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

from build_issue83_source_crosswalk import digest, identity_digest, local_name


REF_ATTRIBUTES = {"object_ref", "state_ref", "var_ref", "variable_ref",
                  "definition_ref", "test_ref"}


def source_documents(root: Path) -> dict[str, tuple[ET.Element, str, str | None]]:
    """Return source XML roots keyed exactly like witness receipts."""
    documents = {}
    for path in sorted(root.rglob("*.xml")):
        raw = path.read_bytes()
        documents[path.relative_to(root).as_posix()] = (ET.fromstring(raw), digest(raw), None)
    for path in sorted(root.rglob("*.zip")):
        archive_raw = path.read_bytes()
        with zipfile.ZipFile(path) as package:
            for member in sorted(name for name in package.namelist()
                                 if name.lower().endswith(".xml")):
                raw = package.read(member)
                documents[f"{path.relative_to(root).as_posix()}!{member}"] = (
                    ET.fromstring(raw), digest(archive_raw), digest(raw))
    return documents


def id_index(root: ET.Element) -> dict[str, ET.Element]:
    return {node.get("id"): node for node in root.iter() if node.get("id")}


def referenced_ids(node: ET.Element):
    for child in node.iter():
        for attribute, value in child.attrib.items():
            if attribute.rsplit("}", 1)[-1] in REF_ATTRIBUTES and value:
                yield value
        if local_name(child.tag) == "filter" and (child.text or "").strip():
            yield (child.text or "").strip()
        if local_name(child.tag) == "var_ref" and (child.text or "").strip():
            yield (child.text or "").strip()


def closure_variables(test: ET.Element, by_id: dict[str, ET.Element]) -> set[str]:
    variables = set()
    seen = set()
    pending = [test]
    while pending:
        node = pending.pop()
        marker = id(node)
        if marker in seen:
            continue
        seen.add(marker)
        if node.get("id") and node.get("id").split(":")[-2:-1] == ["var"]:
            variables.add(node.get("id"))
        for ref in referenced_ids(node):
            target = by_id.get(ref)
            if target is not None:
                if local_name(target.tag).endswith("_variable"):
                    variables.add(ref)
                else:
                    pending.append(target)
    return variables


def audit(source_root: Path, conversion_receipt: Path) -> dict:
    receipt = json.loads(conversion_receipt.read_text(encoding="utf-8"))
    documents = source_documents(source_root)
    rows = []
    for blocked in receipt["tests"]:
        if blocked.get("failure_class") != "canonical_input_constraint_hold":
            continue
        source_file = blocked["source_file"]
        document, file_sha, member_sha = documents[source_file]
        by_id = id_index(document)
        test = by_id[blocked["source_test_id"]]
        variable_ids = closure_variables(test, by_id)
        variables = []
        for variable_id in sorted(variable_ids):
            variable = by_id.get(variable_id)
            if variable is None or local_name(variable.tag) != "external_variable":
                continue
            restrictions = []
            for possible in variable.findall(".//{*}possible_restriction"):
                restriction = next((child for child in possible
                                    if local_name(child.tag) == "restriction"), None)
                restrictions.append({
                    "hint": possible.get("hint", ""),
                    "operation": restriction.get("operation", "") if restriction is not None else "",
                    "value": (restriction.text or "").strip() if restriction is not None else "",
                })
            variables.append({
                "source_id": variable_id,
                "datatype": variable.get("datatype", ""),
                "source_element_sha256": identity_digest(variable),
                "possible_restrictions": restrictions,
            })
        rows.append({
            "source_file": source_file,
            "source_file_sha256": file_sha,
            "source_member_sha256": member_sha,
            "source_test_id": blocked["source_test_id"],
            "source_test_sha256": identity_digest(test),
            "witness_source_test_sha256": blocked["source_test_sha256"],
            "diagnostic": blocked.get("diagnostic", ""),
            "variables": variables,
        })
    restriction_count = sum(len(variable["possible_restrictions"])
                            for row in rows for variable in row["variables"])
    return {
        "format": "scap-ng-tools/issue83-external-variable-holds/1",
        "source": {"root": "external pinned source", "commit": "e3538595c5083b9c34d937a81d319234df9bbfaa"},
        "converter_receipt_sha256": digest(conversion_receipt.read_bytes()),
        "summary": {
            "blocked_tests": len(rows),
            "unique_external_variables": len({variable["source_id"] for row in rows for variable in row["variables"]}),
            "possible_restrictions": restriction_count,
            "failure_class": "canonical_input_constraint_hold",
        },
        "rows": rows,
        "disposition": {
            "canonical_input_contract": "hold",
            "converter_runtime": "not_run",
            "independent_equivalence": "not_proved",
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--conversion-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.output}")
    report = audit(args.source_root, args.conversion_receipt)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
