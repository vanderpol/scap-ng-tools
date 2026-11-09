"""Qualification gates for the six Issue #27 streams.

This validates the recovered source-preserving pipeline without treating
schema validation as semantic proof.  It is intentionally parameterized so
that the public fixtures and generated outputs remain outside the repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import validate_native_documents

XCCDF = "http://checklists.nist.gov/xccdf/1.2"
OCIL = "http://scap.nist.gov/schema/ocil/2"
METADATA = {"coverage.json", "source-trace.json", "conversion-scope.json"}
FUNCTION_RE = re.compile(r"unsupported function:\s*([A-Za-z0-9_]+)")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> tuple[str, dict[str, str]]:
    rows = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rows[path.relative_to(root).as_posix()] = digest(path)
    h = hashlib.sha256()
    for name, value in rows.items():
        h.update(name.encode())
        h.update(b"\0")
        h.update(bytes.fromhex(value))
    return h.hexdigest(), rows


def native_documents(root: Path) -> dict[str, dict]:
    documents = {}
    for path in sorted(root.rglob("*.json")):
        if path.name in METADATA:
            continue
        value = json.loads(path.read_text())
        if isinstance(value, dict):
            documents[path.relative_to(root).as_posix()] = value
    for path in sorted(root.rglob("*.yaml")):
        value = yaml.safe_load(path.read_text())
        if isinstance(value, dict):
            documents[path.relative_to(root).as_posix()] = value
    return documents


def source_info(source: Path) -> dict:
    with zipfile.ZipFile(source) as archive:
        xml_members = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        raw = {name: archive.read(name) for name in xml_members}
    xccdf_name = next(
        name for name in xml_members
        if ET.fromstring(raw[name]).findall(f".//{{{XCCDF}}}Rule")
    )
    root = ET.fromstring(raw[xccdf_name])
    rules = root.findall(f".//{{{XCCDF}}}Rule")
    manual = {
        rule.get("id") for rule in rules
        if any(check.get("system") == OCIL for check in rule.findall(f".//{{{XCCDF}}}check"))
    }
    return {
        "xml_members": xml_members,
        "xml_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()},
        "xccdf_member": xccdf_name,
        "rule_ids": [rule.get("id") for rule in rules if rule.get("id")],
        "ocil_rule_ids": sorted(manual),
    }


def validate_stage(stage: Path, repeat: Path, source: Path, pin: dict, snapshot) -> dict:
    errors = []
    target = stage / source.stem
    repeat_target = repeat / source.stem
    if not target.is_dir() or not repeat_target.is_dir():
        return {"validation": "FAIL", "errors": ["missing stage output"]}
    run = stage / f"{source.stem}.run.json"
    run_result = json.loads(run.read_text()) if run.exists() else {}
    cov = json.loads((target / "coverage.json").read_text())
    summary = cov["summary"]
    rows = cov["rules"]
    statuses = summary["statuses"]
    if digest(source) != pin["sha256"]:
        errors.append("source ZIP SHA-256 differs from pin")
    if run_result.get("returncode") != 0 or not json.loads(run_result.get("stdout", "{}")) .get("schema_validated", False):
        errors.append("converter receipt is not successful/schema-validated")
    if len(rows) != summary["source_rules"]:
        errors.append("coverage row count mismatch")
    if statuses.get("converted", 0) + statuses.get("blocked", 0) != len(rows):
        errors.append("converted/blocked status accounting mismatch")
    if len({row.get("source_rule") for row in rows}) != len(rows):
        errors.append("duplicate source Rule IDs in coverage")
    for root in (target, repeat_target):
        try:
            validate_native_documents(snapshot, native_documents(root))
        except Exception as exc:  # pragma: no cover - emitted as qualification evidence
            errors.append(f"schema validation failed for {root.name}: {exc}")
    first_tree, first_files = tree_digest(target)
    repeat_tree, repeat_files = tree_digest(repeat_target)
    if first_files != repeat_files:
        errors.append("repeat output file set/hash differs")
    unsupported_functions = {}
    for row in rows:
        for blocker in row.get("blockers", []):
            match = FUNCTION_RE.search(blocker.get("message", ""))
            if match:
                name = match.group(1)
                unsupported_functions[name] = unsupported_functions.get(name, 0) + 1
                if row.get("status") != "blocked":
                    errors.append(f"unsupported function {name} was not blocked")
    return {
        "validation": "PASS" if not errors else "FAIL",
        "errors": errors,
        "source_sha256": pin["sha256"],
        "source_bytes": pin["bytes"],
        "source_git_blob_sha": pin.get("git_blob_sha"),
        "source_rules": len(rows),
        "converted_rules": statuses.get("converted", 0),
        "blocked_rules": statuses.get("blocked", 0),
        "proof_levels": summary.get("proof_levels", {}),
        "blocker_categories": summary.get("rules_by_blocker_category", {}),
        "native_documents": len(native_documents(target)),
        "repeat_native_documents": len(native_documents(repeat_target)),
        "stage_tree_sha256": first_tree,
        "repeat_stage_tree_sha256": repeat_tree,
        "deterministic_stage_repeat": first_files == repeat_files,
        "unsupported_function_blockers": unsupported_functions,
    }


def validate_packaged(packaged: Path, packaged_repeat: Path, source: Path, pin: dict, stage_row: dict, snapshot, expected_tools: str, expected_schema: str) -> dict:
    errors = []
    target = packaged / source.stem
    repeat_target = packaged_repeat / source.stem
    if not target.is_dir() or not repeat_target.is_dir():
        return {"validation": "FAIL", "errors": ["missing packaged output"]}
    try:
        validate_native_documents(snapshot, native_documents(target / "native-automated-subset"))
        validate_native_documents(snapshot, native_documents(repeat_target / "native-automated-subset"))
    except Exception as exc:
        errors.append(f"packaged native schema validation failed: {exc}")
    source_data = source_info(source)
    preservation = target / "source-preservation"
    index = json.loads((preservation / "index.json").read_text())
    if digest(preservation / pin["file"]) != pin["sha256"]:
        errors.append("preserved source archive SHA-256 differs from pin")
    if index["xccdf_rule_count"] != len(source_data["rule_ids"]):
        errors.append("preserved XCCDF Rule count mismatch")
    if set(index["rules"]) != set(source_data["rule_ids"]):
        errors.append("preserved Rule ID set mismatch")
    if set(index["manual_ocil_rule_ids"]) != set(source_data["ocil_rule_ids"]):
        errors.append("preserved OCIL Rule ID set mismatch")
    for name in source_data["xml_members"]:
        preserved = preservation / "datastreams" / name
        if not preserved.exists() or digest(preserved) != source_data["xml_sha256"][name]:
            errors.append(f"preserved XML member mismatch: {name}")
    if index["coverage_rule_count"] != stage_row["source_rules"]:
        errors.append("packager/source coverage count mismatch")
    manifest = json.loads((target.parent / "stage-b-manifest.json").read_text())
    if manifest["status"] != "SOURCE_PRESERVING_AUTOMATED_SUBSET":
        errors.append("unexpected packager status")
    if manifest.get("tools_commit") != expected_tools:
        errors.append("packager tools commit does not match qualification pin")
    if manifest.get("schema_commit") != expected_schema:
        errors.append("packager schema commit does not match qualification pin")
    first_tree, first_files = tree_digest(target)
    repeat_tree, repeat_files = tree_digest(repeat_target)
    if first_files != repeat_files:
        errors.append("repeat packaged file set/hash differs")
    return {
        "validation": "PASS" if not errors else "FAIL",
        "errors": errors,
        "source_xml_member": source_data["xccdf_member"],
        "source_xml_sha256": source_data["xml_sha256"],
        "source_rule_xml_count": len(source_data["rule_ids"]),
        "manual_ocil_rules_retained": len(source_data["ocil_rule_ids"]),
        "native_documents": len(native_documents(target / "native-automated-subset")),
        "packaged_tree_sha256": first_tree,
        "repeat_packaged_tree_sha256": repeat_tree,
        "deterministic_packaged_repeat": first_files == repeat_files,
        "source_preservation": "PASS" if not errors else "CHECK",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--stage-a", type=Path, required=True)
    parser.add_argument("--stage-repeat", type=Path, required=True)
    parser.add_argument("--packaged", type=Path, required=True)
    parser.add_argument("--packaged-repeat", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--schema-commit", required=True)
    args = parser.parse_args()
    snapshot = FrozenSchemaSnapshot(args.schema_root)
    pins = {row["file"]: row for row in json.loads(args.pins.read_text())["sources"]}
    streams = []
    for run in sorted(args.stage_a.glob("*.run.json")):
        name = run.name.removesuffix(".run.json") + ".zip"
        source = args.sources / name
        stage_row = validate_stage(args.stage_a, args.stage_repeat, source, pins[name], snapshot)
        packaged_row = validate_packaged(args.packaged, args.packaged_repeat, source, pins[name], stage_row, snapshot, args.tools_commit, args.schema_commit)
        streams.append({"file": name, "stage": stage_row, "packaged": packaged_row})
    report = {
        "format": "scap-ng-tools-issue27-six-qualification/1",
        "status": "PASS" if all(row["stage"]["validation"] == "PASS" and row["packaged"]["validation"] == "PASS" for row in streams) else "FAIL",
        "schema": snapshot.manifest(),
        "tools_commit": args.tools_commit,
        "schema_commit": args.schema_commit,
        "streams": streams,
        "totals": {
            "source_rules": sum(row["stage"].get("source_rules", 0) for row in streams),
            "converted_rules": sum(row["stage"].get("converted_rules", 0) for row in streams),
            "blocked_rules": sum(row["stage"].get("blocked_rules", 0) for row in streams),
            "native_documents": sum(row["stage"].get("native_documents", 0) for row in streams),
            "manual_ocil_rules_retained": sum(row["packaged"].get("manual_ocil_rules_retained", 0) for row in streams),
        },
        "qualification_boundary": "PASS means source-preserving conversion and current-schema authoring validation only; no independent OVAL semantic proof or scanner qualification is claimed.",
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "totals": report["totals"]}, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
