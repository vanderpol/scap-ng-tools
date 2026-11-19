#!/usr/bin/env python3
"""Build a deterministic, source-pinned Issue #83 crosswalk.

The command deliberately reads source archives without copying or rewriting
content.  It records the complete 65-archive XCCDF Rule identity ledger,
source ``requires``/``conflicts`` relationships, and the DISA extended
``description`` fields used by the signed SCAP 1.4 stream.  An optional OVAL
schema root adds a declaration inventory; declarations are never promoted to
support merely because an XSD name resembles a native capability.

Generated reports are evidence, not converter output and must normally live
outside the repository.  The compact JSON/Markdown output is deterministic.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import html
import json
from pathlib import Path
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
import zipfile

DS = "http://scap.nist.gov/schema/scap/source/1.2"
XCCDF = "http://checklists.nist.gov/xccdf/1.2"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
XCCDF_SCHEMA_URL = "https://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd"
XCCDF_SCHEMA_SHA256 = "22c6c2eeca08e517a278a9571304cb84277651ebb6fe4934af5af46c2428424e"
DISA_FIELDS = (
    "VulnDiscussion", "FalsePositives", "FalseNegatives", "Documentable",
    "Mitigations", "SeverityOverrideGuidance", "PotentialImpacts",
    "ThirdPartyTools", "MitigationControl", "Responsibility", "IAControls",
)
OVAL_DEFINITION_FILES = re.compile(r"^[^-]+-definitions-schema\.xsd$")
XSD = "http://www.w3.org/2001/XMLSchema"
OVAL_COMMON = "http://oval.mitre.org/XMLSchema/oval-common-5"
OVAL_DEFINITIONS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def xml_identity(element: ET.Element):
    """Stable identity used by the existing converter provenance contract."""
    return [
        element.tag,
        sorted(element.attrib.items()),
        element.text if not len(element) else None,
        [xml_identity(child) for child in element],
    ]


def identity_digest(element: ET.Element) -> str:
    raw = json.dumps(xml_identity(element), sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    return digest(raw)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def relationship_clause(value: str, *, kind: str, source: str) -> list[str]:
    ids = value.split()
    if not ids:
        raise ValueError(f"empty {kind} idref in {source}")
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate {kind} idref in {source}; canonical any_of is uniqueItems")
    return ids


def parse_disa_description(description: ET.Element | None) -> tuple[dict[str, str], str]:
    """Parse publisher tags embedded as escaped XML in XCCDF description text.

    DISA streams carry these tags as literal text, not XML children.  Empty
    values and ``Documentable=false`` are retained exactly as authored.
    """
    text = "" if description is None else (description.text or "")
    if not text.strip():
        return {}, text
    try:
        root = ET.fromstring(f"<disa-wrapper>{html.unescape(text)}</disa-wrapper>")
    except ET.ParseError:
        return {}, text
    fields: dict[str, str] = {}
    for child in root:
        if child.tag in DISA_FIELDS and child.tag not in fields:
            fields[child.tag] = "".join(child.itertext())
    return fields, text


def find_benchmark(raw_xml: bytes) -> ET.Element:
    root = ET.fromstring(raw_xml)
    if root.tag != f"{{{DS}}}data-stream-collection":
        raise ValueError("source XML is not a SCAP 1.2 data-stream-collection")
    benchmarks = [element for element in root.iter()
                  if element.tag == f"{{{XCCDF}}}Benchmark"]
    if len(benchmarks) != 1:
        raise ValueError(f"expected one XCCDF Benchmark, found {len(benchmarks)}")
    return benchmarks[0]


def archive_record(path: Path) -> dict:
    archive_raw = path.read_bytes()
    archive_sha = digest(archive_raw)
    with zipfile.ZipFile(path) as package:
        if package.testzip() is not None:
            raise ValueError(f"CRC failure in {path.name}")
        members = package.namelist()
        if len(members) != len(set(members)):
            raise ValueError(f"duplicate ZIP member in {path.name}")
        xml_members = [name for name in members if name.lower().endswith(".xml")]
        if len(xml_members) != 1:
            raise ValueError(f"expected one XML member in {path.name}, found {len(xml_members)}")
        member = xml_members[0]
        raw_xml = package.read(member)
    benchmark = find_benchmark(raw_xml)
    rules = []
    relation_rows = []
    group_relation_rows = []
    field_counts = Counter()
    field_nonempty = Counter()
    malformed_descriptions = []
    for rule in benchmark.iter(f"{{{XCCDF}}}Rule"):
        source_id = rule.get("id")
        if not source_id:
            raise ValueError(f"Rule without id in {path.name}")
        fields, raw_description = parse_disa_description(
            next((child for child in rule if child.tag == f"{{{XCCDF}}}description"), None))
        field_hashes = {}
        for name in DISA_FIELDS:
            if name in fields:
                field_counts[name] += 1
                if fields[name]:
                    field_nonempty[name] += 1
                field_hashes[name] = digest(fields[name].encode("utf-8"))
        if raw_description and not fields:
            # A description is allowed to be ordinary XCCDF text; only record
            # malformed publisher-looking payloads as a diagnostic.
            if raw_description.lstrip().startswith("<"):
                malformed_descriptions.append(source_id)
        requires_elements = rule.findall(f"{{{XCCDF}}}requires")
        conflicts_elements = rule.findall(f"{{{XCCDF}}}conflicts")
        requires_raw = [element.get("idref", "") for element in requires_elements]
        conflicts_raw = [element.get("idref", "") for element in conflicts_elements]
        requires = []
        for value in requires_raw:
            ids = relationship_clause(value, kind="requires", source=f"{path.name}:{source_id}")
            requires.append(ids[0] if len(ids) == 1 else {"any_of": ids})
        conflicts = []
        for value in conflicts_raw:
            ids = value.split()
            if len(ids) != 1:
                raise ValueError(f"conflicts requires one idref in {path.name}:{source_id}")
            conflicts.append(ids[0])
        row = {
            "source_rule": source_id,
            "source_rule_sha256": identity_digest(rule),
            "requires": requires,
            "conflicts": conflicts,
            "disa_description_field_sha256": dict(sorted(field_hashes.items())),
        }
        rules.append(row)
        if requires or conflicts:
            relation_rows.append({
                "archive": path.name,
                "xml_member": member,
                "source_rule": source_id,
                "source_rule_sha256": row["source_rule_sha256"],
                "requires_raw": requires_raw,
                "requires": requires,
                "conflicts_raw": conflicts_raw,
                "conflicts": conflicts,
            })
    # XCCDF permits the same relationship elements on Groups.  They cannot be
    # represented by the current canonical Group shape, so inventory them
    # separately instead of flattening them into Rule prerequisites.
    for group in benchmark.iter(f"{{{XCCDF}}}Group"):
        source_id = group.get("id")
        if not source_id:
            raise ValueError(f"Group without id in {path.name}")
        requires_elements = group.findall(f"{{{XCCDF}}}requires")
        conflicts_elements = group.findall(f"{{{XCCDF}}}conflicts")
        requires_raw = [element.get("idref", "") for element in requires_elements]
        conflicts_raw = [element.get("idref", "") for element in conflicts_elements]
        requires = []
        for value in requires_raw:
            ids = relationship_clause(value, kind="Group requires", source=f"{path.name}:{source_id}")
            requires.append(ids[0] if len(ids) == 1 else {"any_of": ids})
        conflicts = []
        for value in conflicts_raw:
            ids = value.split()
            if len(ids) != 1:
                raise ValueError(f"Group conflicts requires one idref in {path.name}:{source_id}")
            conflicts.append(ids[0])
        if requires or conflicts:
            group_relation_rows.append({
                "archive": path.name,
                "xml_member": member,
                "source_group": source_id,
                "source_group_sha256": identity_digest(group),
                "requires_raw": requires_raw,
                "requires": requires,
                "conflicts_raw": conflicts_raw,
                "conflicts": conflicts,
            })
    return {
        "archive": path.name,
        "archive_sha256": archive_sha,
        "xml_member": member,
        "xml_sha256": digest(raw_xml),
        "benchmark_id": benchmark.get("id"),
        "xccdf_version": benchmark.get("xccdf-version"),
        "rule_count": len(rules),
        "relation_count": len(relation_rows),
        "rules": rules,
        "relations": relation_rows,
        "group_relations": group_relation_rows,
        "group_relation_count": len(group_relation_rows),
        "disa_description": {
            "field_names": list(DISA_FIELDS),
            "rule_field_counts": dict(sorted(field_counts.items())),
            "nonempty_rule_field_counts": dict(sorted(field_nonempty.items())),
            "malformed_publisher_payload_rules": sorted(malformed_descriptions),
        },
    }


def _schema_shape(node: ET.Element) -> dict:
    """Return a deterministic, lossless structural witness for one XSD node.

    The declaration inventory previously recorded only names and deprecation
    annotations.  That is insufficient for a schema-first crosswalk: a
    converter obligation can be carried by a base/ref, a default, a
    cardinality, an attribute use, or an extension/restriction child.  Keep
    the XML source external, but retain every authored attribute and the
    ordered structural children needed to review those contracts.  Text is
    intentionally omitted because XSD documentation is prose evidence, not
    executable grammar; the declaration identity digest still commits to it.
    """
    return {
        "kind": local_name(node.tag),
        "attributes": dict(sorted(node.attrib.items())),
        "children": [_schema_shape(child) for child in node],
    }


def _schema_shape_digest(shape: dict) -> str:
    return digest(json.dumps(shape, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8"))


def _shape_summary(shape: dict) -> dict:
    """Compact counts for review without inferring native support."""
    counts = Counter()
    attributes = Counter()

    def visit(node):
        counts[node["kind"]] += 1
        attributes.update(node["attributes"].keys())
        for child in node["children"]:
            visit(child)

    visit(shape)
    return {
        "node_kinds": dict(sorted(counts.items())),
        "attribute_names": dict(sorted(attributes.items())),
    }


def _deprecated_info(node: ET.Element) -> list[dict]:
    """Read official OVAL deprecation annotations under one XSD node.

    ``oval:deprecated_info`` is attached to an XSD declaration or to a
    nested member.  A nested deprecated member must not make its containing
    capability/declaration appear deprecated, so callers retain the scope.
    """
    records = []
    for annotation in node.findall(f"{{{XSD}}}annotation"):
        for appinfo in annotation.findall(f"{{{XSD}}}appinfo"):
            for info in appinfo.findall(f"{{{OVAL_COMMON}}}deprecated_info"):
                records.append({
                    "version": info.findtext(f"{{{OVAL_COMMON}}}version"),
                    "reason": info.findtext(f"{{{OVAL_COMMON}}}reason"),
                })
    return records


def _nested_deprecation_records(declaration: ET.Element) -> tuple[list[dict], list[dict]]:
    direct, nested = _deprecated_info(declaration), []
    for node in declaration.iter():
        if node is declaration:
            continue
        records = _deprecated_info(node)
        if not records:
            continue
        nested.extend({
            "declaration_kind": node.tag.rsplit("}", 1)[-1],
            "name": node.get("name"),
            "ref": node.get("ref"),
            "value": node.get("value"),
            "scope": "nested",
            **record,
        } for record in records)
    return direct, nested


def oval_inventory(root: Path) -> dict:
    rows = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or not OVAL_DEFINITION_FILES.match(path.name):
            continue
        raw = path.read_bytes()
        document = ET.parse(path).getroot()
        namespace = document.get("targetNamespace", "")
        for child in document:
            if child.tag.rsplit("}", 1)[-1] not in {"element", "complexType", "simpleType", "group"}:
                continue
            name = child.get("name")
            if not name:
                continue
            direct, nested = _nested_deprecation_records(child)
            shape = _schema_shape(child)
            row = {
                "schema_file": path.name,
                "schema_sha256": digest(raw),
                "namespace": namespace,
                "declaration_kind": child.tag.rsplit("}", 1)[-1],
                "name": name,
                "schema_shape": shape,
                "schema_shape_sha256": _schema_shape_digest(shape),
                "schema_shape_summary": _shape_summary(shape),
                "native_mapping_status": "deprecated" if direct else "unclassified",
                "classification_reason": (
                    "Official OVAL oval:deprecated_info marks this declaration deprecated; "
                    "do not treat it as an in-scope native conversion."
                    if direct else
                    "XSD declaration inventory is not proof of a native mapping; classify against canonical 0.4.1 and converter evidence."
                ),
            }
            if direct:
                row["deprecation"] = [{"scope": "declaration", **record} for record in direct]
            if nested:
                row["deprecated_members"] = nested
            rows.append(row)
    statuses = Counter(row["native_mapping_status"] for row in rows)
    nested_count = sum(bool(row.get("deprecated_members")) for row in rows)
    return {
        "source_commit_expected": "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706",
        "schema_files": sorted({row["schema_file"] for row in rows}),
        "declarations": rows,
        "summary": {
            "schema_files": len({row["schema_file"] for row in rows}),
            "declarations": len(rows),
            "native_mapping_status": dict(sorted(statuses.items())),
            "declarations_with_deprecated_members": nested_count,
            "official_deprecation_annotations": sum(
                len(row.get("deprecation", [])) + len(row.get("deprecated_members", []))
                for row in rows
            ),
            "schema_shape_contract": {
                "status": "structural source witness only",
                "preserves": [
                    "declaration attributes and defaults",
                    "ordered child particles",
                    "base/ref/extension/restriction relationships",
                    "cardinality and attribute-use metadata",
                ],
                "does_not_infer": [
                    "native representability",
                    "converter support",
                    "runtime equivalence",
                ],
            },
        },
    }



def oval_content_inventory(root: Path, source_commit: str) -> dict:
    """Inventory source Definitions and Tests without converting or evaluating.

    The standalone OVAL corpus is a source-language witness, not a runtime
    result set.  Keep one row per source XML file/element, preserve the exact
    file and structural element digests, and summarize only authored syntax.
    No expected or actual outcome is inferred here.
    """
    if not root.is_dir():
        raise ValueError(f"OVAL content root is not a directory: {root}")
    definitions = []
    tests = []
    variables = []
    files = []
    feature_counts = Counter()
    test_tag_counts = Counter()
    variable_tag_counts = Counter()
    definition_class_counts = Counter()
    attribute_counts = Counter()
    variable_child_counts = Counter()
    def record_document(document, relative, file_sha256, member_sha256=None):
        if local_name(document.tag) != "oval_definitions":
            return
        file_record = {
            "source_file": relative,
            "source_file_sha256": file_sha256,
            "definitions": 0,
            "tests": 0,
        }
        if member_sha256:
            file_record["source_member_sha256"] = member_sha256
        files.append(file_record)
        for element in document.iter():
            kind = local_name(element.tag)
            identifier = element.get("id")
            if kind == "definition" and identifier:
                row = {
                    "source_file": relative,
                    "source_file_sha256": file_sha256,
                    "source_id": identifier,
                    "source_element_sha256": identity_digest(element),
                    "definition_class": element.get("class", ""),
                }
                if member_sha256:
                    row["source_member_sha256"] = member_sha256
                definitions.append(row)
                file_record["definitions"] += 1
                definition_class_counts[row["definition_class"]] += 1
                continue
            if identifier and kind.endswith("_variable"):
                child_tags = sorted(local_name(node.tag) for node in element)
                child_counts = Counter(child_tags)
                row = {
                    "source_file": relative,
                    "source_file_sha256": file_sha256,
                    "source_id": identifier,
                    "source_element_sha256": identity_digest(element),
                    "source_variable_tag": kind,
                    "datatype": element.get("datatype", ""),
                    "child_tags": child_tags,
                    "possible_value_count": child_counts.get("possible_value", 0),
                    "possible_restriction_count": child_counts.get("possible_restriction", 0),
                    "restriction_operations": sorted({
                        child.get("operation", "") for child in element.iter()
                        if local_name(child.tag) == "restriction"
                    }),
                }
                if member_sha256:
                    row["source_member_sha256"] = member_sha256
                variables.append(row)
                variable_tag_counts[kind] += 1
                variable_child_counts.update(child_tags)
            if not (identifier and kind.endswith("_test")):
                continue
            authored_attributes = {
                name: value for name, value in sorted(element.attrib.items())
                if name in {"check", "check_existence", "state_operator", "var_check"}
            }
            row = {
                "source_file": relative,
                "source_file_sha256": file_sha256,
                "source_id": identifier,
                "source_element_sha256": identity_digest(element),
                "source_test_tag": kind,
                "attributes": authored_attributes,
                "feature_tags": sorted({local_name(node.tag) for node in element.iter()}),
            }
            if member_sha256:
                row["source_member_sha256"] = member_sha256
            tests.append(row)
            file_record["tests"] += 1
            test_tag_counts[kind] += 1
            for name in authored_attributes:
                attribute_counts[name] += 1
            feature_counts.update(row["feature_tags"])

    for path in sorted(root.rglob("*.xml")):
        raw = path.read_bytes()
        try:
            document = ET.fromstring(raw)
        except ET.ParseError as error:
            raise ValueError(f"invalid OVAL XML {path}: {error}") from error
        record_document(document, path.relative_to(root).as_posix(), digest(raw))
    # The pinned corpus contains one source Definition archive with a second
    # XML member.  It is part of the source denominator and must not disappear
    # merely because it is packaged rather than checked out as a loose file.
    for path in sorted(root.rglob("*.zip")):
        archive_raw = path.read_bytes()
        with zipfile.ZipFile(path) as package:
            if package.testzip() is not None:
                raise ValueError(f"CRC failure in OVAL content archive {path}")
            for member in sorted(name for name in package.namelist()
                                 if name.lower().endswith(".xml")):
                raw = package.read(member)
                try:
                    document = ET.fromstring(raw)
                except ET.ParseError as error:
                    raise ValueError(f"invalid OVAL XML {path.name}!{member}: {error}") from error
                record_document(document, f"{path.relative_to(root).as_posix()}!{member}",
                                digest(archive_raw), digest(raw))
    definitions.sort(key=lambda row: (row["source_file"], row["source_id"], row["source_element_sha256"]))
    tests.sort(key=lambda row: (row["source_file"], row["source_id"], row["source_element_sha256"]))
    variables.sort(key=lambda row: (row["source_file"], row["source_id"], row["source_element_sha256"]))
    files.sort(key=lambda row: row["source_file"])
    return {
        "format": "scap-ng-tools/issue83-oval-content-inventory/1",
        "source": {
            "root": "external source root (not copied into repository)",
            "commit": source_commit,
            "path": root.name,
        },
        "summary": {
            "xml_files": sum("!" not in row["source_file"] for row in files),
            "embedded_xml_members": sum("!" in row["source_file"] for row in files),
            "source_documents": len(files),
            "definitions": len(definitions),
            "tests": len(tests),
            "variables": len(variables),
            "definition_classes": dict(sorted(definition_class_counts.items())),
            "test_tags": dict(sorted(test_tag_counts.items())),
            "variable_tags": dict(sorted(variable_tag_counts.items())),
            "authored_test_attributes": dict(sorted(attribute_counts.items())),
            "variable_child_tags": dict(sorted(variable_child_counts.items())),
            "feature_tags": dict(sorted(feature_counts.items())),
        },
        "files": files,
        "definitions": definitions,
        "tests": tests,
        "variables": variables,
        "qualification": {
            "conversion": "not_run",
            "execution": "not_run",
            "expected_outcomes": "not_inferred",
            "independent_equivalence": "not_proved",
        },
    }

def build(source_root: Path, expected_archives: int, source_commit: str,
          oval_root: Path | None, oval_content_root: Path | None = None,
          oval_content_commit: str | None = None) -> dict:
    archives = sorted(source_root.glob("*.zip"))
    if len(archives) != expected_archives:
        raise ValueError(f"expected {expected_archives} source ZIPs, found {len(archives)}")
    records = [archive_record(path) for path in archives]
    source_rules = sum(record["rule_count"] for record in records)
    relations = [row for record in records for row in record["relations"]]
    group_relations = [row for record in records for row in record["group_relations"]]
    archive_manifest = [{key: record[key] for key in (
        "archive", "archive_sha256", "xml_member", "xml_sha256", "benchmark_id", "rule_count")}
        for record in records]
    archive_set_sha256 = digest(json.dumps(
        archive_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    field_counts = Counter()
    nonempty = Counter()
    malformed = []
    for record in records:
        field_counts.update(record["disa_description"]["rule_field_counts"])
        nonempty.update(record["disa_description"]["nonempty_rule_field_counts"])
        malformed.extend(record["disa_description"]["malformed_publisher_payload_rules"])
    result = {
        "format": "scap-ng-tools/issue83-source-crosswalk/1",
        "source": {
            "root": "external source root (not copied into repository)",
            "commit": source_commit,
            "expected_archives": expected_archives,
            "archive_set_sha256": archive_set_sha256,
            "xccdf_schema": {
                "url": XCCDF_SCHEMA_URL,
                "sha256": XCCDF_SCHEMA_SHA256,
                "selectable_item_type_xpath": "/xsd:schema/xsd:complexType[@name='selectableItemType']",
                "requires_xpath": "/xsd:schema/xsd:complexType[@name='selectableItemType']//xsd:element[@name='requires']",
                "conflicts_xpath": "/xsd:schema/xsd:complexType[@name='selectableItemType']//xsd:element[@name='conflicts']",
            },
            "archives": records,
        },
        "summary": {
            "archives": len(records),
            "source_rules": source_rules,
            "rules_with_requires_or_conflicts": len(relations),
            "requires_rows": sum(bool(row["requires"]) for row in relations),
            "conflicts_rows": sum(bool(row["conflicts"]) for row in relations),
            "groups_with_requires_or_conflicts": len(group_relations),
            "group_requires_rows": sum(bool(row["requires"]) for row in group_relations),
            "group_conflicts_rows": sum(bool(row["conflicts"]) for row in group_relations),
            "disa_description_field_names": list(DISA_FIELDS),
            "disa_description_rule_field_counts": dict(sorted(field_counts.items())),
            "disa_description_nonempty_rule_field_counts": dict(sorted(nonempty.items())),
            "malformed_publisher_payload_rules": sorted(malformed),
        },
        "relationships": relations,
        "group_relationships": group_relations,
        "mapping": {
            "requires": {
                "source": "XCCDF 1.2 selectableItemType/requires/@idref (idrefListType), one child per clause; IDs in one child are ORed",
                "source_schema": XCCDF_SCHEMA_URL + "#selectableItemType",
                "native": "SCAP-NG 0.4.1 rule.requires; clauses are ANDed and any_of members are ORed",
                "status": "implemented for Rule output; Group relationships remain a canonical mapping hold",
            },
            "conflicts": {
                "source": "XCCDF 1.2 selectableItemType/conflicts/@idref (idrefType), one ID per child",
                "source_schema": XCCDF_SCHEMA_URL + "#selectableItemType",
                "native": "SCAP-NG 0.4.1 rule.conflicts; IDs remain source identities",
                "status": "implemented for Rule output; Group relationships remain a canonical mapping hold",
            },
            "disa_description": {
                "source": "XCCDF description text containing literal publisher XML",
                "native_discussion": "rule.discussion retains the exact source description text",
                "native_extension": "reserved under rule.extensions.disa; no structured extension is emitted by this increment",
                "fields": list(DISA_FIELDS),
                "status": "source mapping inventoried; native extension held for canonical/owner coordination",
            },
        },
    }
    if oval_root is not None:
        result["oval_schema_inventory"] = oval_inventory(oval_root)
    if oval_content_root is not None:
        if not oval_content_commit:
            raise ValueError("--oval-content-commit is required with --oval-content-root")
        result["oval_content_inventory"] = oval_content_inventory(
            oval_content_root, oval_content_commit)
    return result


def markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Issue #83 source crosswalk",
        "",
        "This report is generated from immutable signed SCAP 1.4 source ZIPs. It is a source inventory and converter-loss audit, not runtime or OVAL equivalence proof.",
        "",
        f"- Source commit: `{report['source']['commit']}`",
        f"- Archives: **{summary['archives']}**",
        f"- Source Rules: **{summary['source_rules']}**",
        f"- Rules with `requires`/`conflicts`: **{summary['rules_with_requires_or_conflicts']}**",
        f"- `requires` rows: **{summary['requires_rows']}**; `conflicts` rows: **{summary['conflicts_rows']}**",
        f"- Groups with relationships: **{summary['groups_with_requires_or_conflicts']}** (requires **{summary['group_requires_rows']}**, conflicts **{summary['group_conflicts_rows']}**)",
        f"- XCCDF 1.2 schema: `{report['source']['xccdf_schema']['url']}` (`{report['source']['xccdf_schema']['sha256']}`)",
        "",
        "## Result",
        "",
        "The pinned 65-archive corpus contains no non-empty `Rule/requires` or `Rule/conflicts` relationships, and the separately audited Group relationship ledger is also measured. These are measured zeros, not evidence that the converter may drop relationships: source relationships are preserved for Rules and Groups are failed closed until a canonical non-flattening Group mapping exists. The test fixture exercises positive and negative source relationship elements.",
        "",
        "## DISA extended description mapping",
        "",
        "Literal publisher XML inside XCCDF `description` is retained without data loss:",
        "",
        "| Source field | Native location | Preservation |\n|---|---|---|\n" + "\n".join(f"| `{field}` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |" for field in DISA_FIELDS),
        "",
        f"The source ledger has the eleven-field DISA payload on {summary['disa_description_rule_field_counts'].get('VulnDiscussion', 0)} Rules; {len(summary['malformed_publisher_payload_rules'])} Rules have publisher-looking descriptions that require source-specific review. Per-Rule field hashes are retained in JSON. `rule.discussion` retains the original description text for compatibility.",
        "",
        "## OVAL source-content inventory",
        "",
        "The optional standalone OVAL inventory records source IDs, exact source file/element hashes, authored syntax and no outcomes. Conversion, execution and independent equivalence remain explicitly unproved.",
        "",
    ]
    if "oval_content_inventory" in report:
        inventory = report["oval_content_inventory"]["summary"]
        lines.extend([
            f"- XML files: **{inventory['xml_files']}**; Definitions: **{inventory['definitions']}**; Tests: **{inventory['tests']}**",
            f"- Test tags: `{json.dumps(inventory['test_tags'], sort_keys=True)}`",
            f"- Authored controls: `{json.dumps(inventory['authored_test_attributes'], sort_keys=True)}`",
            "",
        ])
    lines.extend([
        "## Holds",
        "",
        "- The OVAL XSD declaration inventory (when supplied) is intentionally `unclassified`; XSD declaration names are not native support proof. Each declaration now carries a deterministic structural witness of authored attributes, defaults, cardinalities, ordered particles and base/ref relationships; imported/inherited resolution remains a separate hold.",
        "- Canonical schema changes are out of scope for this Tools increment; any missing native representation is a canonical-language decision for `scap-ng` #80.",
        "- Native conversion output and RI execution are separate qualification stages.",
    ])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-archives", type=int, default=65)
    parser.add_argument("--oval-schema-root", type=Path)
    parser.add_argument("--oval-content-root", type=Path)
    parser.add_argument("--oval-content-commit")
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build(args.source_root, args.expected_archives, args.source_commit,
                   args.oval_schema_root, args.oval_content_root,
                   args.oval_content_commit)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(markdown(report), encoding="utf-8")
    output = {"archives": report["summary"]["archives"],
              "source_rules": report["summary"]["source_rules"],
              "relationships": len(report["relationships"]),
              "output_json": str(args.output_json),
              "output_md": str(args.output_md)}
    if "oval_content_inventory" in report:
        inventory = report["oval_content_inventory"]["summary"]
        output["oval_content"] = {
            "xml_files": inventory["xml_files"],
            "definitions": inventory["definitions"],
            "tests": inventory["tests"],
        }
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
