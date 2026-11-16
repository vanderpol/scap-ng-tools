#!/usr/bin/env python3
"""Generate the reviewed native 0.4 capability contract directly from metadata.

Version-neutral OVAL XSD helpers supply field/type identities. Native surfaces
and conditions are constructed once, with no historical grammar, wrapper
flattening or previous-version reference rewriting. Generated-contract parity is
covered by the full 100-capability fingerprint and semantic regression suites.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from v04_capability_native import native_surface

from v04_capability_source import direct_global, immediate_payload_elements, source_datatypes

VERSION = "0.4.1"
ROOT_ID = f"https://scap-ng.dev/schema/v{VERSION}/"
LANG = ROOT_ID + "assessment-language.schema.json"
COMMON = ROOT_ID + "capability-common.schema.json"
# Use the same explicit 0.4 Boolean spellings as assessment-language.schema:
# Source aliases belong to the upgrader, not generated current contracts.
LOGIC = ("and", "or", "one", "xor")


def _qualify_refs(schema):
    """Keep generated-local recursion and normative document scopes distinct."""
    from urllib.parse import urljoin
    def visit(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == '$ref':
                    node[key] = (schema['$id'] + value if value.startswith('#')
                                 else urljoin(ROOT_ID, value))
                else:
                    visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)
    visit(schema)
    return schema


def _present(schema, root, enabled, mapping):
    if enabled:
        from v04_editor_annotations import apply_authoring_metadata
        apply_authoring_metadata(schema, root)
        controls = {
            'object_title': 'Human-readable name of this collection source. It does not select targets or change collection results.',
            'capability': 'Collector capability for a shared or Variable-owned Object. Inline Test Objects inherit it from their Test; do not repeat it there.',
            'set': 'Acquire a collection through explicit Object Set operands and ordered per-operand filters. Set membership is distinct from Test truth aggregation.',
            'traversal': 'Optional downward traversal for a compatible directory or hierarchy selector. Omit it to disable recursion; when present serialize depth and platform-specific traversal kind explicitly.'}
        parameters = mapping['native'].get('collection_parameters', {})
        for name, node in schema.get('$defs', {}).get('object', {}).get('properties', {}).items():
            if not node.get('description'):
                description = parameters.get(name, {}).get('description') or controls.get(name)
                if description: node['description'] = description
        catalog_path = Path(root) / 'schema/v0.4.1/selector-api-contracts.json'
        if catalog_path.is_file():
            catalog = json.loads(catalog_path.read_text())
            contract = catalog['capabilities'].get(mapping['capability'], {})
            for name, field in contract.get('fields', {}).items():
                node = schema.get('$defs', {}).get('object', {}).get('properties', {}).get(name)
                if node is None:
                    raise ValueError('selector/API annotation field absent from generated Object: ' + name)
                references = ' '.join(catalog['sources'][key]['url'] for key in field['sources'])
                node['description'] = node.get('description', '') + ' Decision22 selection/API contract: ' + field['rule'] + ' Collected-value comparisons remain independent. Sources: ' + references
    return schema


def _field_expression(name: str, child: dict) -> dict:
    return {
        "type": "object", "required": [name],
        "properties": {name: child},
        "additionalProperties": False,
    }


def _generated_state_fields(mapping: dict, root: Path, document=None) -> tuple[dict, set]:
    source = mapping["source"]
    document = document if document is not None else ET.parse(root / source["definitions_schema"]).getroot()
    state = direct_global(document, "element", source["state"])
    entities = immediate_payload_elements(state)
    overrides = mapping["native"].get("state_field_datatypes", {})
    datatypes = mapping["native"].get("field_datatypes", {})
    fields = {}
    for source_name, output_name in mapping["native"].get("state_field_map", {}).items():
        if source_name not in entities:
            raise KeyError(f"Unmapped State entity {source_name!r}")
        fields[output_name] = overrides.get(
            output_name, datatypes.get(output_name, source_datatypes(entities[source_name]))
        )
    for source_name, spec in mapping["native"].get("native_added_state_fields", {}).items():
        output_name = spec.get("native_name", source_name)
        if source_name not in entities:
            # Native-added fields correspond to Item-only fields and may have
            # no equivalent source State entity. Use reviewed override first.
            fields[output_name] = overrides.get(
                output_name, datatypes.get(output_name, ["string"])
            )
        else:
            fields[output_name] = overrides.get(
                output_name, datatypes.get(output_name, source_datatypes(entities[source_name]))
            )
    records = set(mapping["native"].get("record_state_fields", []))
    return fields, records


def _selector_fields(mapping: dict, root: Path, document=None) -> dict:
    source = mapping["source"]
    if not source.get("object"):
        return {}
    document = document if document is not None else ET.parse(root / source["definitions_schema"]).getroot()
    obj = direct_global(document, "element", source["object"])
    native_to_source = {
        output: name for name, output in mapping["native"].get("selector_map", {}).items()
    }
    entities = immediate_payload_elements(obj)
    overrides = mapping["native"].get("selector_datatypes", {})
    return {
        output: overrides.get(output,source_datatypes(entities[source_name]))
        for output,source_name in native_to_source.items()
    }


def generate(mapping: dict, repo_root: Path, *, authoring_metadata=True) -> dict:
    if mapping.get("specification_version") != VERSION:
        raise ValueError("0.4.1 generator accepts only reviewed 0.4 source mappings")
    result, source_document = native_surface(mapping, repo_root)
    result["$id"] = (
        ROOT_ID + "generated/capabilities/" + mapping["capability"] + ".schema.json"
    )
    result["description"] = (
        "DRAFT: SCAP-NG 0.4.1 generated native capability contract. One authored "
        "Test/Object/State grammar; derived from reviewed source OVAL 5.12.3 mappings."
    )
    result["x-specification-version"] = VERSION
    defs = result["$defs"]

    # Only a mapping with an explicit native.fixed_result is a fixed-result
    # capability. Ordinary native no-Object capabilities such as
    # windows.passwordpolicy, audit subcategories and independent.family have
    # normal State predicates and paired requirements; they SHALL go through
    # the full common path below even though no Object schema exists.
    if mapping.get("native",{}).get("fixed_result") is not None:
        return _present(_qualify_refs(result), repo_root, authoring_metadata, mapping)

    native_selector_fields = _selector_fields(mapping,repo_root,source_document)
    selector_properties = defs.get("object",{}).get("properties")
    if selector_properties is not None:
        for name in native_selector_fields:
            dtypes = native_selector_fields[name]
            selector = {
                "allOf": [
                    {"$ref": COMMON + "#/$defs/object_entity_base"},
                    {"type": "object", "properties": {
                        "datatype": {"enum": sorted(set(dtypes))}
                    }},
                ],
                "description": f"0.4 native Object selector: {name} (type checked)",
            }
            reviewed_enum=mapping["native"].get("selector_value_enums",{}).get(name)
            if reviewed_enum:
                # Reviewed enumerated Object selectors are equalities, not
                # arbitrary string comparisons. The only scalar/array literal
                # operands are the values in the capability's enum catalog.
                # Dynamic Variables remain typed and require value_match; their
                # resolved membership needs separate semantic validation.
                # Do not add a second legacy bare-string selector dialect.
                selector["allOf"].append({
                    "type":"object",
                    "required":["equals"],
                    "propertyNames":{"enum":[
                        "equals","datatype","value_match","redact_result"
                    ]},
                    "properties":{"equals":{"oneOf":[
                        {"type":"string","enum":list(reviewed_enum)},
                        {"type":"array","minItems":1,
                         "items":{"type":"string","enum":list(reviewed_enum)}},
                        {"$ref":COMMON+"#/$defs/variable_reference"},
                    ]}},
                })
            # Nullable native selector values, e.g. Windows registry name,
            # retain their original existence/absence meaning.
            if name in mapping["native"].get("nullable_selectors",["name"]):
                selector = {"oneOf":[selector,{"type":"null"}]}
            # Explicit for_each projection is a distinct branch,
            # never hide it as a default Object selector comparison.
            selector = {"oneOf":[selector,{
                "$ref": COMMON + "#/$defs/foreach_selector_binding"
            }]}
            selector_properties[name] = selector

    # Set operands MUST reuse the native version-local Object contract.
    # The generic common.set_expression validates structural operations but
    # cannot enforce that nested collection uses this capability's native
    # selector names, nullable values, foreach binding or typed selectors.
    # A separate native recursion preserves those constraints for nested Sets.
    defs["native_set_operand"]={
        "oneOf":[
            {
                "type":"object",
                "required":["object","filters"],
                "properties":{
                    "object":{"oneOf":[
                        {"$ref": COMMON + "#/$defs/object_reference"},
                        {"$ref":"#/$defs/object"},
                    ]},
                    "filters":{"type":"array","items":{
                        "$ref": COMMON + "#/$defs/state_filter"
                    }},
                },
                "additionalProperties":False,
            },
            {
                "type":"object",
                "required":["set"],
                "properties":{"set":{"$ref":"#/$defs/native_set_expression"}},
                "additionalProperties":False,
            },
        ],
    }
    defs["native_set_expression"]={
        "type":"object",
        "required":["operator","operands"],
        "properties":{
            "operator":{"enum":["union","intersection","difference"]},
            "operands":{"type":"array","minItems":1,
                        "items":{"$ref":"#/$defs/native_set_operand"}},
        },
        "allOf":[{
            "if":{"properties":{"operator":{"const":"difference"}},
                  "required":["operator"]},
            "then":{"properties":{"operands":{"maxItems":2}}},
        }],
        "additionalProperties":False,
    }
    if "object" in defs:
        obj = defs["object"]
        # An inline Object inherits the Test capability. The generated
        # capability-specific contract already fixes the optional explicit
        # Object capability via `const`; requiring it duplicated the Test
        # declaration and rejected canonical flat six-STIG authoring.
        obj["required"] = [field for field in obj.get("required", [])
                           if field != "capability"]
        obj["properties"]["set"]={"$ref":"#/$defs/native_set_expression"}
        # 0.4.1: a filtered leaf Object is not a Set. Permit the same
        # ordered, observed-Item include/exclude predicates already supported
        # on Set operands, without inventing a one-operand Union.
        obj["properties"]["filters"]={
            "type":"array", "minItems":1,
            "items":{"$ref":COMMON+"#/$defs/state_filter"},
            "description":"Ordered observed-Item Filters applied after acquisition and before Test matching.",
        }
        # Applying a direct leaf Filter to a composite Set is a different
        # evaluation position; force source-explicit Set operand placement.
        obj.setdefault("allOf",[]).append({
            "not":{"required":["set","filters"]}
        })
    state_fields, records = _generated_state_fields(mapping,repo_root,source_document)
    entries = []
    for name,dtypes in sorted(state_fields.items()):
        if name in records:
            child = {"$ref": LANG + "#/$defs/record_wrapper_predicate"}
        else:
            child = {
                "allOf": [
                    {"$ref": LANG + "#/$defs/scalar_field_predicate"},
                    {"type": "object", "properties": {
                        "datatype": {"enum": sorted(set(dtypes))}
                    }},
                ],
            }
        entries.append(_field_expression(name,child))
    defs["state_predicate"] = {"oneOf":entries} if entries else False
    defs["state_expression"] = {
        "oneOf": [
            {"$ref": "#/$defs/state_predicate"},
            *[
                {"type":"object","required":[logical],
                 "properties":{logical:{
                     "type":"array","minItems":1,
                     "items":{"$ref":"#/$defs/state_expression"},
                 }},"additionalProperties":False}
                for logical in LOGIC
            ],
        ]
    }
    result["x-authoring-gate"] = (
        "Draft structural generation only; source enumeration and cross-field "
        "semantics require additional validation before 0.4.1 freeze."
    )
    # Resolver scope changes when traversing external 0.4 language schemas.
    # Use fully qualified references for generated native recursion, so local
    # State expressions cannot accidentally resolve against an external schema.
    return _present(_qualify_refs(result), repo_root, authoring_metadata, mapping)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mapping",type=Path,required=True)
    p.add_argument("--repo-root",type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    m=json.loads(args.mapping.read_text(encoding="utf-8"))
    output=generate(m,args.repo_root)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
        "capability":m["capability"],"version":VERSION,
        # A flat native Object has no generic select/collect wrappers.
        # Report source-declared selector/parameter counts, not the obsolete
        # nested select.properties path (which now always returned zero).
        "object_selector_fields":len(m["native"].get("selector_map",{})),
        "object_acquisition_parameters":len(
            m["native"].get("collection_parameters",{})),
        "direct_object_filters_supported":(
            "filters" in output.get("$defs",{}).get("object",{}).
            get("properties",{})
        ),
        "state_predicates":len(
            output.get("$defs",{}).get("state_predicate",{}).get("oneOf",[])
        ) if isinstance(output.get("$defs",{}).get("state_predicate",{}),dict) else 0,
        "output":str(args.output),
    },sort_keys=True))
if __name__=="__main__":
    main()
