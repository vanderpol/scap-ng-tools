#!/usr/bin/env python3
"""Produce a compact, source-linked audit of dynamic OVAL Variable Object Sets.

This is an evidence tool, not a converter fallback.  It inspects the original
ZIP member and the active canonical schema, and records whether the current
native expression/selector contracts can carry the source graph without
materializing host values or changing status/cardinality semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
WINDOWS = OVAL + "#windows"
XSD = "http://www.w3.org/2001/XMLSchema"
SCH = "http://purl.oclc.org/dsdl/schematron"

CASES = {
    "SV-218752": {
        "rule_id": "xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218752r1111807_rule",
        "definition_id": "oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:def:218752",
        "test_id": "oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:tst:21875201",
        "object_id": "oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:obj:21875201",
    },
    "SV-214463": {
        "rule_id": "xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214463r879643_rule",
        "definition_id": "oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:def:180",
        "test_id": "oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:tst:180",
        "object_id": "oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:obj:180",
    },
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def local(node: ET.Element) -> str:
    return node.tag.rsplit("}", 1)[-1]


def identity(node: ET.Element):
    return [node.tag, sorted(node.attrib.items()),
            node.text if not list(node) else None,
            [identity(child) for child in node]]


def identity_sha(node: ET.Element) -> str:
    raw = json.dumps(identity(node), sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode()
    return sha(raw)


def find_id(root: ET.Element, identifier: str) -> ET.Element:
    for node in root.iter():
        if node.get("id") == identifier:
            return node
    raise ValueError(f"source ID not found: {identifier}")


def graph(root: ET.Element, start: str) -> list[dict]:
    by_id = {n.get("id"): n for n in root.iter() if n.get("id")}
    seen: set[str] = set()
    todo = [start]
    rows = []
    while todo:
        identifier = todo.pop()
        if identifier in seen:
            continue
        node = by_id.get(identifier)
        if node is None:
            rows.append({"id": identifier, "missing": True})
            continue
        seen.add(identifier)
        rows.append({
            "id": identifier,
            "local_name": local(node),
            "namespace": node.tag.split("}", 1)[0][1:] if "}" in node.tag else "",
            "sha256": identity_sha(node),
            "references": [],
        })
        row = rows[-1]
        for child in node.iter():
            for attribute in ("object_ref", "state_ref", "var_ref"):
                ref = child.get(attribute)
                if ref:
                    row["references"].append({"kind": attribute, "id": ref})
                    todo.append(ref)
            if local(child) in {"object_reference", "filter", "var_ref"} and (child.text or "").strip():
                ref = child.text.strip()
                row["references"].append({"kind": local(child), "id": ref,
                                           "action": child.get("action")})
                todo.append(ref)
    return sorted(rows, key=lambda row: row["id"])


def schematron_filter_rules(schema: Path) -> dict[str, str]:
    root = ET.parse(schema).getroot()
    result = {}
    for rule in root.iter(f"{{{SCH}}}rule"):
        context = rule.get("context", "")
        match = re.search(r"(?:win-def:|ind-def:)([A-Za-z0-9_]+)//oval-def:filter$", context)
        if not match:
            continue
        for assertion in rule.findall(f"{{{SCH}}}assert"):
            expected = re.search(r"\$state_name='([^']+)'", assertion.get("test", ""))
            if expected:
                result[match.group(1)] = expected.group(1)
    return result


def filter_findings(root: ET.Element, start: str, expected: dict[str, str]) -> list[dict]:
    by_id = {n.get("id"): n for n in root.iter() if n.get("id")}
    identifiers = [row["id"] for row in graph(root, start) if not row.get("missing")]
    findings = []
    for identifier in identifiers:
        parent = by_id[identifier]
        parent_kind = local(parent)
        required = expected.get(parent_kind)
        if not required:
            continue
        for filter_node in parent.iter(f"{{{OVAL}}}filter"):
            state_id = (filter_node.text or "").strip()
            state = by_id.get(state_id)
            actual = local(state) if state is not None else None
            if actual != required:
                findings.append({
                    "object_id": parent.get("id"),
                    "object_kind": parent_kind,
                    "filter_state_id": state_id,
                    "actual_state_kind": actual,
                    "required_state_kind": required,
                    "schematron_rule": f"{parent_kind}//oval-def:filter",
                })
    return findings


def refs_for(schema_path: Path, needle: str) -> list[str]:
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    found = []
    def walk(value, path=""):
        if isinstance(value, dict):
            if value.get("$ref", "").split("#", 1)[-1] == needle:
                found.append(path)
            for key, child in value.items():
                walk(child, path + "/" + key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, path + f"/{index}")
    walk(data)
    return found


def canonical_contract(schema_root: Path) -> dict:
    common = schema_root / "capability-common.schema.json"
    variables = schema_root / "variable-expression.schema.json"
    selectors = schema_root / "native-selector.schema.json"
    return {
        "schema_root": "SCAP_NG_SCHEMA_ROOT/schema",
        "schema_family_sha256": schema_family(schema_root),
        "values_expression_present": bool(refs_for(variables, "/$defs/expression")) and
            "values" in json.loads(variables.read_text())["$defs"]["expression"]["oneOf"][3]["properties"],
        "unique_multi_population_present": "unique" in json.loads(variables.read_text())["$defs"]["expression"]["oneOf"][8]["properties"],
        "set_expression_present": "set_expression" in json.loads(common.read_text())["$defs"],
        "set_operand_accepts_variable_population": False,
        "foreach_binding_refs": refs_for(common, "/$defs/foreach_binding"),
        "active_foreach_authoring": False,
        "selector_set_refs": refs_for(selectors, "/$defs/set_expression"),
    }


def schema_family(root: Path) -> str:
    digest = hashlib.sha256()
    paths = sorted([*root.glob("*.json"), *(root / "capability-mappings").rglob("*.json")])
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def audit_case(case: dict, source_zip: Path, schema_root: Path, xsd_root: Path) -> dict:
    with zipfile.ZipFile(source_zip) as archive:
        members = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        if len(members) != 1:
            raise ValueError(f"expected one XML member in {source_zip}, found {members}")
        member = members[0]
        raw = archive.read(member)
    root = ET.fromstring(raw)
    definition = find_id(root, case["definition_id"])
    test = find_id(root, case["test_id"])
    obj = find_id(root, case["object_id"])
    expected = schematron_filter_rules(xsd_root / "windows-definitions-schema.xsd")
    return {
        "rule_id": case["rule_id"],
        "definition_id": case["definition_id"],
        "test_id": case["test_id"],
        "root_object_id": case["object_id"],
        "source": {
            "zip": source_zip.name,
            "zip_sha256": sha(source_zip.read_bytes()),
            "xml_member": member,
            "xml_member_sha256": sha(raw),
            "definition_sha256": identity_sha(definition),
            "test_sha256": identity_sha(test),
            "root_object_sha256": identity_sha(obj),
        },
        "graph": graph(root, case["object_id"]),
        "schematron": {
            "rules_used": {
                "appcmd_object": {
                    "pattern_id": "win-def_appcmd_object_verify_filter_state",
                    "required_state_kind": expected.get("appcmd_object"),
                    "schema_file": "windows-definitions-schema.xsd",
                    "schema_lines": [8777, 8785],
                    "schema_xpath": "/xsd:schema/xsd:element[@name='appcmd_object']/xsd:annotation/xsd:appinfo/sch:pattern[@id='win-def_appcmd_object_verify_filter_state']",
                },
                "appcmdlistconfig_object": {
                    "pattern_id": "win-def_appcmdlistconfig_object_verify_filter_state",
                    "required_state_kind": expected.get("appcmdlistconfig_object"),
                    "schema_file": "windows-definitions-schema.xsd",
                    "schema_lines": [8893, 8901],
                    "schema_xpath": "/xsd:schema/xsd:element[@name='appcmdlistconfig_object']/xsd:annotation/xsd:appinfo/sch:pattern[@id='win-def_appcmdlistconfig_object_verify_filter_state']",
                },
            },
            "cross_capability_filter_findings": filter_findings(root, case["object_id"], expected),
        },
        "attempts": {
            "values": {
                "status": "insufficient",
                "reason": "values reads one field from one collected Object; it cannot apply the two-branch transformed UNION as one Object population",
            },
            "for_each": {
                "status": "not_active",
                "reason": "foreach_binding is a shared helper with no active Assessment authoring reference",
            },
            "set_filter": {
                "status": "insufficient",
                "reason": "native Set operands are Object uses with homogeneous capability/filter semantics; they cannot union a transformed Variable population across appcmd and environmentvariable",
            },
            "unique_expression": {
                "status": "candidate_generic_lowering",
                "reason": "native unique accepts ordered expression populations and preserves runtime expression identity; production visitor now lowers unfiltered UNION leaves to this form",
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--oval-schema-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", action="append", choices=sorted(CASES), required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    args = parser.parse_args()
    source_dir = args.source_dir
    zips = {
        "SV-218752": source_dir / "U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip",
        "SV-214463": source_dir / "U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip",
    }
    report = {
        "format": "scap-ng-tools/issue83-dynamic-variable-object-set/1",
        "source_commit": "8c8e5dff860af6b1290ee9273a282db24278f8d5",
        "oval_schema_commit": "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706",
        "oval_definitions_schema_sha256": sha((args.oval_schema_root / "oval-definitions-schema.xsd").read_bytes()),
        "windows_definitions_schema_sha256": sha((args.oval_schema_root / "windows-definitions-schema.xsd").read_bytes()),
        "canonical_schema_commit": "2d983fcbd7b2367d567ca8ccc689a378d08905e4",
        "canonical_repository_head": "d67394f0d5df425da6febf6bc5959540cb7f540f",
        "canonical": canonical_contract(args.schema_root),
        "cases": [audit_case(CASES[name], zips[name], args.schema_root, args.oval_schema_root)
                  for name in args.case],
        "conclusion": {
            "dynamic_union_generic_lowering": "implemented_in_converter_for_unfiltered_union_of_variable_leaves",
            "source_closure_validity": "requires_source_schematron_repair_or_reclassification",
            "runtime_equivalence": False,
            "host_execution": False,
            "source_values_materialized": False,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out), "cases": len(report["cases"]),
                      "schema_family_sha256": report["canonical"]["schema_family_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
