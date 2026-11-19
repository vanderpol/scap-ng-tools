#!/usr/bin/env python3
"""Build a source-pinned OVAL ``var_check`` crosswalk.

This is a source grammar/conversion audit, not an evaluator.  It records every
var_check occurrence in the pinned Self-Assertion corpus with its exact source
file hash, owning Test/Definition IDs, referenced Variable cardinality and the
admitted SCAP-NG 0.4.1 value-match projection.  Source values are retained
verbatim; the projection never supplies expected outcomes to the converter.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile

CORPUS_REL = Path("SCAP_1.4/OVAL_Test_Content")
ZIP_NAME = "oval-def-ext.zip"
ZIP_MEMBER = "oval-def-ext.xml"
FORMAT = "scap-ng-tools/issue83-oval-var-check-crosswalk/1"
MATCHING = {
    "all": "every",
    "at least one": "one_or_more",
    "none satisfy": "none",
    "none exist": "none",
    "only one": "exactly_one",
}


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return digest(path.read_bytes())


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def identified(root: ET.Element) -> dict[str, ET.Element]:
    return {node.get("id"): node for node in root.iter() if node.get("id")}


def definition_owners(root: ET.Element) -> dict[str, list[str]]:
    """Resolve direct and transitive Definition criterion ownership."""
    definitions = {node.get("id"): node for node in root.iter()
                   if local(node.tag) == "definition" and node.get("id")}
    direct: dict[str, list[str]] = {}
    for ident, definition in definitions.items():
        direct[ident] = [node.get("test_ref") for node in definition.iter()
                         if local(node.tag) == "criterion" and node.get("test_ref")]

    def refs(ident: str, active: tuple[str, ...] = ()) -> list[str]:
        if ident in active:
            raise ValueError("cyclic extend_definition: " + ident)
        result = list(direct[ident])
        definition = definitions[ident]
        for child in definition.iter():
            if local(child.tag) == "extend_definition":
                target = child.get("definition_ref")
                if not target or target not in definitions:
                    raise ValueError("unresolved extend_definition: " + str(target))
                for test_id in refs(target, active + (ident,)):
                    if test_id not in result:
                        result.append(test_id)
        return result

    owners: dict[str, list[str]] = defaultdict(list)
    for ident in definitions:
        for test_id in refs(ident):
            owners[test_id].append(ident)
    return {key: sorted(value) for key, value in owners.items()}


def source_documents(corpus: Path):
    root = corpus / CORPUS_REL
    for family in sorted(path for path in root.iterdir() if path.is_dir()):
        for path in sorted(family.glob("*.xml")):
            yield CORPUS_REL / family.name / path.name, path.read_bytes()
        if family.name == "agnostic":
            archive = family / ZIP_NAME
            with ZipFile(archive) as package:
                yield CORPUS_REL / family.name / f"{ZIP_NAME}!{ZIP_MEMBER}", package.read(ZIP_MEMBER)


def referenced_components(test: ET.Element, by_id: dict[str, ET.Element]) -> list[ET.Element]:
    """Return the Test and explicitly referenced Object/State graph nodes."""
    result: list[ET.Element] = [test]
    seen: set[str] = set()
    pending: list[str] = []
    for node in test.iter():
        for key, value in node.attrib.items():
            if key.endswith("_ref") and value:
                pending.append(value)
        if local(node.tag) in {"var_ref", "object_reference", "filter"} and (node.text or "").strip():
            pending.append(node.text.strip())
    while pending:
        ident = pending.pop()
        if ident in seen:
            continue
        seen.add(ident)
        node = by_id.get(ident)
        if node is None:
            continue
        result.append(node)
        for child in node.iter():
            for key, value in child.attrib.items():
                if key.endswith("_ref") and value:
                    pending.append(value)
            if local(child.tag) in {"var_ref", "object_reference", "filter"} and (child.text or "").strip():
                pending.append(child.text.strip())
    return result


def rows_for_document(source_path: Path, raw: bytes, source_commit: str) -> list[dict]:
    root = ET.fromstring(raw)
    by_id = identified(root)
    owners = definition_owners(root)
    parent: dict[int, ET.Element] = {}
    for node in root.iter():
        for child in node:
            parent[id(child)] = node

    def nearest_component_id(element: ET.Element) -> str | None:
        current = parent.get(id(element))
        while current is not None:
            if current.get("id"):
                return current.get("id")
            current = parent.get(id(current))
        return None

    tests = [node for node in root.iter() if local(node.tag).endswith("_test") and node.get("id")]
    rows: list[dict] = []
    captured: set[int] = set()
    for test in tests:
        test_id = test.get("id")
        for component in referenced_components(test, by_id):
            for element in component.iter():
                if "var_check" not in element.attrib:
                    continue
                captured.add(id(element))
                value = element.get("var_check")
                variable_id = (element.get("var_ref") or "").strip() or None
                variable = by_id.get(variable_id) if variable_id else None
                variable_values = []
                restrictions = []
                if variable is not None:
                    variable_values = [child.text or "" for child in variable
                                       if local(child.tag) == "value"]
                    restrictions = [child for child in variable.iter()
                                    if local(child.tag) == "possible_restriction"]
                rows.append(_row(
                    source_path, digest(raw), source_commit, test_id, local(test.tag),
                    owners.get(test_id, []), nearest_component_id(element),
                    element, value, variable_id, variable, variable_values,
                    len(restrictions)))

    # Some source Objects/States carry var_check but are not referenced by any
    # Test in the same XML document. Keep them as explicit orphan records
    # rather than silently dropping source grammar. They cannot be assigned a
    # Definition/Test owner until the source adds the missing reference.
    for element in root.iter():
        if "var_check" not in element.attrib or id(element) in captured:
            continue
        value = element.get("var_check")
        variable_id = (element.get("var_ref") or "").strip() or None
        variable = by_id.get(variable_id) if variable_id else None
        variable_values = ([child.text or "" for child in variable
                            if local(child.tag) == "value"] if variable is not None else [])
        restrictions = ([child for child in variable.iter()
                         if local(child.tag) == "possible_restriction"] if variable is not None else [])
        rows.append(_row(
            source_path, digest(raw), source_commit, None, None, [], nearest_component_id(element),
            element, value, variable_id, variable, variable_values,
            len(restrictions), orphan=True))
    return rows


def _row(source_path: Path, source_sha256: str, source_commit: str, test_id: str | None,
         test_kind: str | None, definition_ids: list[str], component_id: str | None,
         element: ET.Element, value: str, variable_id: str | None,
         variable: ET.Element | None, variable_values: list[str],
         possible_restriction_count: int, *, orphan: bool = False) -> dict:
    return {
        "source_path": source_path.as_posix(),
        "source_sha256": source_sha256,
        "source_commit": source_commit,
        "test_id": test_id,
        "test_kind": test_kind,
        "definition_ids": definition_ids,
        "component_id": component_id,
        "orphan_component": orphan,
        "element": local(element.tag),
        "var_check": value,
        "var_ref": variable_id,
        "variable_kind": local(variable.tag) if variable is not None else None,
        "variable_datatype": variable.get("datatype") if variable is not None else None,
        "variable_value_count": len(variable_values),
        "variable_values_sha256": digest(
            json.dumps(variable_values, ensure_ascii=False,
                       separators=(",", ":")).encode()) if variable is not None else None,
        "possible_restriction_count": possible_restriction_count,
        "native_value_match": MATCHING.get(value),
        "native_disposition": (
            "admitted_value_match_crosswalk" if value in MATCHING
            else "unsupported_source_enumeration"),
        "runtime_qualification": "not_run",
        "independent_equivalence": "not_proved",
    }


def build(corpus: Path, source_commit: str) -> dict:
    rows: list[dict] = []
    for source_path, raw in source_documents(corpus):
        rows.extend(rows_for_document(source_path, raw, source_commit))
    rows.sort(key=lambda row: (row["source_path"], row["test_id"] or "", row["orphan_component"], row["element"], row["var_ref"] or ""))
    values = Counter(row["var_check"] for row in rows)
    families = Counter(Path(row["source_path"]).parts[-2] for row in rows)
    disposition = Counter(row["native_disposition"] for row in rows)
    return {
        "format": FORMAT,
        "source": {
            "repository": "OVAL-Community/SCAP-Self-Assertion",
            "commit": source_commit,
            "root": CORPUS_REL.as_posix(),
            "documents_with_var_check": len({row["source_path"] for row in rows}),
        },
        "summary": {
            "var_check_rows": len(rows),
            "source_elements_with_var_check": len({(row["source_path"], row["source_sha256"], row["component_id"], row["element"], row["var_ref"], row["var_check"], row["orphan_component"]) for row in rows}),
            "test_linked_rows": sum(not row["orphan_component"] for row in rows),
            "orphan_rows": sum(row["orphan_component"] for row in rows),
            "tests_with_var_check": len({(row["source_path"], row["test_id"]) for row in rows if row["test_id"]}),
            "definitions_referenced": len({definition for row in rows for definition in row["definition_ids"]}),
            "values": dict(sorted(values.items())),
            "families": dict(sorted(families.items())),
            "native_disposition": dict(sorted(disposition.items())),
            "runtime_qualification": "not_run",
            "independent_equivalence": "not_proved",
        },
        "semantic_notes": {
            "missing_var_check": "OVAL defaults missing var_check to all; this ledger covers only explicit authored occurrences.",
            "none_exist": "Retained as source identity; native projection is value_match=none per the current converter crosswalk and requires runtime semantic qualification.",
            "expected_outcomes": "Not used as evaluator input and not inferred by this inventory.",
            "variable_values": "Only cardinality and a digest are recorded; source values are not copied into the compact receipt.",
        },
        "rows": rows,
    }


def markdown(result: dict) -> str:
    summary = result["summary"]
    lines = [
        "# OVAL `var_check` source crosswalk",
        "",
        "This source-pinned crosswalk records authored `var_check` values and their current native value-match projection. It is not runtime qualification or independent OVAL equivalence proof.",
        "",
        f"- Source: `{result['source']['repository']}@{result['source']['commit']}`",
        f"- Source root: `{result['source']['root']}`",
        f"- Tools converter: `{result['pins']['converter_commit']}`",
        f"- OVAL definitions XSD SHA-256: `{result['pins']['oval_definitions_schema_sha256']}`",
        f"- OVAL common XSD SHA-256: `{result['pins']['oval_common_schema_sha256']}`",
        f"- Canonical 0.4.1: `{result['pins']['canonical_commit']}`",
        f"- Schema family SHA-256: `{result['pins']['canonical_schema_family_sha256']}`",
        "",
        "## Inventory",
        "",
        f"- Source elements with `var_check`: **{summary['source_elements_with_var_check']}**",
        f"- Test-linked rows: **{summary['test_linked_rows']}**",
        f"- Explicit orphan component rows: **{summary['orphan_rows']}**",
        f"- Rows including shared-component links: **{summary['var_check_rows']}**",
        f"- Tests with `var_check`: **{summary['tests_with_var_check']}**",
        f"- Definitions referenced: **{summary['definitions_referenced']}**",
        "",
        "| Source family | Rows |",
        "|---|---:|",
    ]
    lines.extend(f"| `{family}` | {count} |" for family, count in summary["families"].items())
    lines.extend([
        "",
        "| Authored value | Count | Native projection |",
        "|---|---:|---|",
    ])
    for value, count in summary["values"].items():
        lines.append(f"| `{value}` | {count} | `{MATCHING[value]}` |")
    lines.extend([
        "",
        "## Orphan source components",
        "",
        "These components contain authored `var_check` but are not reachable from a Test in the same source document. They remain explicit source rows and are not treated as converted or executable.",
        "",
        "| Source path | Component | Element | `var_check` | Variable |",
        "|---|---|---|---|---|",
    ])
    for row in result["rows"]:
        if row["orphan_component"]:
            lines.append(f"| `{row['source_path']}` | `{row['component_id']}` | `{row['element']}` | `{row['var_check']}` | `{row['var_ref']}` |")
    lines.extend([
        "",
        "## Reproduction",
        "",
        "```sh",
        "python scripts/build_oval_var_check_crosswalk.py "
        "--corpus \"$SCAP_NG_SELF_ASSERTION_ROOT\" "
        f"--source-commit {result['source']['commit']} "
        f"--oval-schema-commit {result['pins']['oval_schema_commit']} "
        f"--oval-definitions-schema-sha256 {result['pins']['oval_definitions_schema_sha256']} "
        f"--oval-common-schema-sha256 {result['pins']['oval_common_schema_sha256']} "
        f"--converter-commit {result['pins']['converter_commit']} "
        f"--canonical-commit {result['pins']['canonical_commit']} "
        f"--schema-family-sha256 {result['pins']['canonical_schema_family_sha256']} "
        "--output /tmp/oval-var-check.json --markdown-output /tmp/oval-var-check.md",
        "```",
        "",
        "## Semantic boundaries",
        "",
        "- Missing `var_check` defaults to OVAL `all`; this ledger covers explicit authored values only.",
        "- `none exist` is retained as source identity and currently projects to native `value_match: none`; this requires runtime semantic qualification.",
        "- Variable values are represented only by cardinality and a SHA-256 digest; source values are not copied into the compact report.",
        "- No source expectation is supplied to the converter or evaluator.",
        "- Runtime qualification: **not run**; independent equivalence: **not proved**.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--oval-schema-commit", required=True)
    parser.add_argument("--oval-definitions-schema-sha256", required=True)
    parser.add_argument("--oval-common-schema-sha256", required=True)
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--canonical-commit", required=True)
    parser.add_argument("--schema-family-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.output}")
    result = build(args.corpus, args.source_commit)
    result["generated_by"] = {
        "script": "scripts/build_oval_var_check_crosswalk.py",
        "script_sha256": file_sha256(Path(__file__).resolve()),
    }
    result["pins"] = {
        "oval_schema_commit": args.oval_schema_commit,
        "oval_definitions_schema_sha256": args.oval_definitions_schema_sha256,
        "oval_common_schema_sha256": args.oval_common_schema_sha256,
        "converter_commit": args.converter_commit,
        "canonical_commit": args.canonical_commit,
        "canonical_schema_family_sha256": args.schema_family_sha256,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        if args.markdown_output.exists():
            raise SystemExit(f"refusing to overwrite existing output: {args.markdown_output}")
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(markdown(result), encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
