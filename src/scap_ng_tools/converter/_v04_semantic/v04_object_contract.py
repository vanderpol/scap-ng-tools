#!/usr/bin/env python3
"""One grammar-owned acquisition Object visitor and 0.4 validation gate (#251).

No normalization here. Migration explicitly consumes the same sites. Literal
records, result/evidence payloads and arbitrary maps named object are opaque.
"""
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path

from . import capability_contract, schema_resources, snapshot


@dataclass(frozen=True)
class ObjectSite:
    node: dict
    capability: str | None
    path: tuple
    private: bool
    context: str
    inherited: str | None


def object_sites(assessment):
    """Visit acquisition grammar, not generic dictionary key spellings.

    Capabilities inherit only down Test/Object Set boundaries. Variable
    expressions start a new context: a private values.object must declare its
    own capability, even when the Variable feeds a different collector Test.
    """
    def obj(node, inherited, path, private, context):
        if not isinstance(node, dict):
            return
        cap = node.get('capability', inherited)
        yield ObjectSite(node, cap, path, private, context, inherited)
        if isinstance(node.get('set'), dict):
            yield from set_expr(node['set'], cap, path + ('set',), context)

    def set_expr(node, cap, path, context):
        operands = node.get('operands')
        if not isinstance(operands, list):
            return  # Structural schema diagnoses invalid Set shapes.
        for i, operand in enumerate(operands):
            if not isinstance(operand, dict):
                continue
            p = path + ('operands', i)
            yield from obj(operand.get('object'), cap, p + ('object',), True, context + '/set')
            if isinstance(operand.get('set'), dict):
                yield from set_expr(operand['set'], cap, p + ('set',), context + '/set')

    # These are existing native expression operand positions, not a new
    # expression grammar. Descriptive options (pattern/delimiter/order/etc.)
    # and literal/record payloads are never recursively interpreted as code.
    functions = {'concat', 'regex_capture', 'unique', 'merge', 'split', 'count',
                 'arithmetic', 'begin', 'end', 'substring', 'escape_regex',
                 'glob_to_regex', 'time_difference', 'to_lower', 'to_upper'}
    slots = {'value', 'values', 'components', 'operands', 'left', 'right'}

    def expression(node, path):
        if isinstance(node, list):
            for i, child in enumerate(node):
                yield from expression(child, path + (i,))
        elif isinstance(node, dict):
            if isinstance(node.get('values'), dict):
                yield from obj(node['values'].get('object'), None,
                               path + ('values', 'object'), True, 'variable')
            for op, value in node.items():
                if op not in functions:
                    continue
                p = path + (op,)
                if isinstance(value, list):
                    yield from expression(value, p)
                elif isinstance(value, dict):
                    if op in {'unique', 'count', 'to_lower', 'to_upper', 'escape_regex'}:
                        yield from expression(value, p)
                    else:
                        for name, operand in value.items():
                            if name in slots:
                                yield from expression(operand, p + (name,))

    for section in ('objects', 'shared_objects'):
        library = assessment.get(section)
        if isinstance(library, dict):
            for ident, node in library.items():
                yield from obj(node, None, ('assessment', section, ident), False, section)
    tests = assessment.get('tests')
    if isinstance(tests, dict):
        for ident, test in tests.items():
            if isinstance(test, dict):
                yield from obj(test.get('object'), test.get('capability'),
                               ('assessment', 'tests', ident, 'object'), True, 'test')
    variables = assessment.get('variables')
    if isinstance(variables, dict):
        for ident, variable in variables.items():
            if isinstance(variable, dict) and 'expression' in variable:
                yield from expression(variable['expression'], ('assessment', 'variables', ident, 'expression'))


def format_path(path):
    result = ''
    for part in path:
        result += '[' + str(part) + ']' if isinstance(part, int) else ('.' if result else '') + part
    return result


@lru_cache(maxsize=4)
def resources(schema_dir):
    return schema_resources(schema_dir)


@lru_cache(maxsize=400)
def object_validator(capability, schema_dir):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    _, contract = capability_contract(capability)
    schema = contract['generated']
    if 'object' not in schema['$defs']:
        raise ValueError('capability has no acquisition Object: ' + capability)
    registry = Registry().with_resources({**resources(schema_dir),
        schema['$id']: Resource.from_contents(schema)}.items())
    return Draft202012Validator({'$ref': schema['$id'] + '#/$defs/object'}, registry=registry)


def object_errors(document, schema_dir=None):
    """Yield JSON Schema ValidationErrors with exact original lexical paths."""
    from jsonschema import ValidationError
    schema_dir = str(Path(schema_dir or snapshot().schema_root).resolve())
    assessment = document.get('assessment')
    if not isinstance(assessment, dict) or (assessment.get('specification') or {}).get('version') != '0.4.1':
        return
    for site in object_sites(assessment):
        node, cap, path = site.node, site.capability, site.path
        def error(message, suffix=()):
            return ValidationError(format_path(path + suffix) + ': ' + message,
                path=deque(path + suffix), validator='native_0.4.1_object_contract')
        if not isinstance(cap, str):
            yield error('acquisition Object requires explicit capability outside a Test/Set', ('capability',))
            continue
        if site.inherited is not None and cap != site.inherited:
            yield error('Object capability conflicts with enclosing Test/Set', ('capability',))
            continue
        wrappers = set(node) & {'collect', 'select'}
        if cap == 'windows.cmdlet':
            wrappers.discard('select')  # Genuine reviewed cmdlet acquisition parameter.
        if wrappers:
            for wrapper in sorted(wrappers):
                yield error('obsolete generic Object ' + wrapper + ' wrapper; explicit migration required', (wrapper,))
            continue
        try:
            validator = object_validator(cap, schema_dir)
        except ValueError as exc:
            yield error(str(exc), ('capability',))
            continue
        for e in validator.iter_errors(node):
            e.path.extendleft(reversed(path))
            e.message = format_path(e.absolute_path) + ': ' + e.message
            yield e
