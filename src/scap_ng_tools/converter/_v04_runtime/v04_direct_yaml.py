"""Presentation only: native dictionaries -> readable, lossless YAML.

Simple Registry Objects and scalar comparisons use flow mappings. Logical
requirements, Sets, Filters and computed selectors remain block structures.
No source interpretation or post-serialization text rewriting belongs here.
"""
from copy import deepcopy
import yaml


class FlowMapping(dict):
    """A serialization hint; never part of the native conversion model."""


class AuthoringDumper(yaml.SafeDumper):
    pass


def string_scalar(dumper, value):
    # Single quotes keep literal Windows paths/regex backslashes easy to read.
    # Other strings retain SafeDumper's ambiguity/escaping decisions.
    style = "'" if '\\' in value and '\n' not in value else None
    return dumper.represent_scalar('tag:yaml.org,2002:str', value, style=style)


AuthoringDumper.add_representer(str, string_scalar)
AuthoringDumper.add_representer(FlowMapping, lambda dumper, value:
    dumper.represent_mapping('tag:yaml.org,2002:map', value.items(), flow_style=True))


def simple_mapping(value):
    return isinstance(value, dict) and bool(value) and all(
        v is None or isinstance(v, (str, int, float, bool)) for v in value.values()) and not any(
        isinstance(v, str) and '\n' in v for v in value.values())


def compact_registry_object(value, capability):
    """Only flat Registry selectors; do not hide Sets/Filters/traversal/Variables."""
    if isinstance(value, dict):
        capability = value.get('capability', capability)
    return (capability == 'windows.registry' and isinstance(value, dict) and
            set(value) <= {'hive', 'key', 'name', 'capability'} and
            all(simple_mapping(v) for k, v in value.items() if k != 'capability'))


def presentation(value, capability=None):
    if isinstance(value, list):
        return [presentation(child, capability) for child in value]
    if not isinstance(value, dict):
        return value
    capability = value.get('capability', capability)
    result = {}
    for key, child in value.items():
        rendered = presentation(child, capability)
        if key == 'object' and compact_registry_object(child, capability):
            rendered = FlowMapping(rendered)
        elif key not in ('require', 'fields') and simple_mapping(child) and (
                'equals' in child or 'datatype' in child or 'values_found' in child or 'matches_regex' in child):
            rendered = FlowMapping(rendered)
        result[key] = rendered
    return result


def authoring_yaml(document):
    # Width prevents PyYAML from folding a deliberately compact Object. Complex
    # acquisitions remain block mappings by construction, regardless of width.
    return yaml.dump(presentation(deepcopy(document)), Dumper=AuthoringDumper,
                     sort_keys=False, allow_unicode=True, width=1_000_000)
