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
from audit_self_assertion_parity import HISTORICAL_PIN


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


def _fixture_key(source_file: str) -> str | None:
    """Return the companion OVAL Variables member for a zipped source.

    The companion document is qualification evidence only. OVAL external
    Variables are supplied by the caller; these values must never become
    authored native Input defaults.
    """
    if "!" not in source_file:
        return None
    archive, member = source_file.split("!", 1)
    if member != "oval-def-ext.xml":
        return None
    return archive + "!oval-def-ext_external-variables.xml"


def _fixture_values(source_file: str, variable_id: str, documents) -> dict | None:
    key = _fixture_key(source_file)
    if key is None or key not in documents:
        return None
    root, archive_sha, member_sha = documents[key]
    variable = id_index(root).get(variable_id)
    if variable is None or local_name(variable.tag) != "variable":
        return {
            "source_file": key, "member_sha256": member_sha,
            "variable_id": variable_id, "values": [],
            "authoritative": False, "role": "qualification_fixture",
        }
    return {
        "source_file": key, "member_sha256": member_sha,
        "variable_id": variable_id,
        "variable_sha256": identity_digest(variable),
        "values": [(child.text or "").strip()
                   for child in variable
                   if local_name(child.tag) == "value"],
        "authoritative": False,
        "role": "qualification_fixture",
    }


def _variable_crosswalk(source_file: str, variable, documents) -> dict:
    """Project only source-authored constraints; never bind fixture values."""
    possible_values = [{
        "value": (child.text or "").strip(),
        "source_sha256": identity_digest(child),
    } for child in variable if local_name(child.tag) == "possible_value"]
    restrictions = []
    for possible in variable:
        if local_name(possible.tag) != "possible_restriction":
            continue
        restrictions.append({
            "hint": possible.get("hint", ""),
            "source_sha256": identity_digest(possible),
            "constraints": [{
                "operation": child.get("operation", ""),
                "value": (child.text or "").strip(),
                "source_sha256": identity_digest(child),
            } for child in possible
              if local_name(child.tag) == "restriction"],
        })
    datatype = variable.get("datatype", "")
    if restrictions:
        disposition = "held_source_input_constraint"
    elif possible_values:
        disposition = "candidate_allowed_values_nonexecutable"
    else:
        disposition = "held_standalone_external_binding"
    return {
        "source_id": variable.get("id"),
        "datatype": datatype,
        "comment": variable.get("comment", ""),
        "source_element_sha256": identity_digest(variable),
        "possible_values": possible_values,
        "possible_restrictions": restrictions,
        "candidate_native_input_id": variable.get("id", "") + "-input",
        "candidate_native_input_executable": False,
        "disposition": disposition,
        "fixture": _fixture_values(source_file, variable.get("id"), documents),
    }


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
            variables.append(_variable_crosswalk(source_file, variable, documents))
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
    possible_value_count = sum(len(variable["possible_values"])
                               for row in rows for variable in row["variables"])
    variables = [variable for row in rows for variable in row["variables"]]
    # Historical focused fixtures predate the manifest field; retain their
    # original e353 identity rather than relabeling them as corrected-source.
    source_commit = receipt.get("source_commit", HISTORICAL_PIN)
    if not isinstance(source_commit, str) or len(source_commit) != 40:
        raise ValueError("conversion receipt must carry the exact source commit")
    return {
        "format": "scap-ng-tools/issue83-external-variable-holds/2",
        "source": {"root": "external pinned source", "commit": source_commit},
        "converter_receipt_sha256": digest(conversion_receipt.read_bytes()),
        "summary": {
            "blocked_tests": len(rows),
            "unique_external_variables": len({variable["source_id"] for row in rows for variable in row["variables"]}),
            "possible_restrictions": restriction_count,
            "possible_values": possible_value_count,
            "datatypes": dict(sorted(Counter(variable["datatype"] for variable in variables).items())),
            "dispositions": dict(sorted(Counter(variable["disposition"] for variable in variables).items())),
            "fixture_values_non_authoritative": sum(
                1 for variable in variables if variable.get("fixture") is not None),
            "failure_class": "canonical_input_constraint_hold",
        },
        "rows": rows,
        "disposition": {
            "canonical_input_contract": "hold",
            "candidate_allowed_values": "source-preserved-only",
            "fixture_values": "qualification-only/non-authoritative",
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
