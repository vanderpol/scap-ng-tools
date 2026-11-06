"""Independent, side-effect-free OVAL 5.12.3 semantic reference vectors.

This module is deliberately not imported by the converter.  It is an oracle
for fixture tests: source lexical/function semantics are calculated separately
from native document generation, including empty collections and explicit
non-Boolean outcomes.
"""
from __future__ import annotations

import itertools
import re
from enum import Enum


class Outcome(str, Enum):
    TRUE = 'true'
    FALSE = 'false'
    ERROR = 'error'
    UNKNOWN = 'unknown'
    NOT_EVALUATED = 'not_evaluated'
    NOT_APPLICABLE = 'not_applicable'
    INCOMPLETE = 'incomplete'
    NOT_COLLECTED = 'not_collected'


# The outer OVAL Test population contract and the native 0.4 contract are
# recorded independently.  The all_exist lowering is owner-approved syntax,
# not a claim that an empty population has been source-proved.
EXISTENCE = {
    'all_exist': 'one_or_more',
    'at_least_one_exists': 'one_or_more',
    'none_exist': 'none',
    'only_one_exists': 'exactly_one',
    'any_exist': 'zero_or_more',
}


def _propagate(values):
    for status in (Outcome.ERROR, Outcome.UNKNOWN, Outcome.INCOMPLETE,
                   Outcome.NOT_COLLECTED, Outcome.NOT_APPLICABLE,
                   Outcome.NOT_EVALUATED):
        if status in values:
            return status
    return None


def quantify(values, requirement):
    """Reference result for native collection cardinality.

    A missing/empty population is never silently converted to a successful
    match.  Diagnostic statuses propagate before Boolean cardinality logic.
    """
    values = list(values)
    diagnostic = _propagate(values)
    if diagnostic is not None:
        return diagnostic
    booleans = [v == Outcome.TRUE if isinstance(v, Outcome) else bool(v) for v in values]
    if requirement == 'none':
        return Outcome.TRUE if not any(booleans) else Outcome.FALSE
    if requirement == 'zero_or_more':
        return Outcome.TRUE
    if requirement == 'exactly_one':
        return Outcome.TRUE if sum(booleans) == 1 else Outcome.FALSE
    if requirement == 'one_or_more':
        return Outcome.TRUE if any(booleans) else Outcome.FALSE
    if requirement == 'every':
        return Outcome.TRUE if booleans and all(booleans) else Outcome.FALSE
    raise ValueError('unknown requirement: ' + requirement)


def count(values):
    """Reference result for OVAL count over one or more components.

    Components are concatenated in source order before cardinality is taken;
    an empty collection is a valid population of size zero and diagnostic
    outcomes are propagated rather than coerced into zero.
    """
    values = list(values)
    diagnostic = _propagate(values)
    return diagnostic if diagnostic is not None else len(values)


def flatten_components(components):
    """Flatten multi-component collections without changing order or duplicates."""
    result = []
    for component in components:
        result.extend(component)
    return result


def cartesian_components(components, operation):
    """Apply *operation* to the OVAL ordered Cartesian product.

    A component is a collection, not a scalar shortcut.  An empty component
    therefore yields an empty result population; diagnostic statuses remain
    caller-visible rather than being converted to empty strings.
    """
    populations = [list(component) for component in components]
    if any(not population for population in populations):
        return []
    return [operation(*values) for values in itertools.product(*populations)]


def split(value, delimiter):
    # Empty is a literal delimiter: it occurs nowhere, so the source value is
    # one preserved value rather than a host-language regex/split error.
    return [value] if delimiter == '' else value.split(delimiter)


def substring(value, start, length):
    # OVAL positions are one-based.  Values below one clamp to the first
    # character, values beyond the end are evaluation errors, and negative or
    # oversized lengths mean the remainder.
    start = max(1, start)
    if start > len(value):
        return Outcome.ERROR
    offset = start - 1
    if length < 0 or length > len(value) - offset:
        return value[offset:]
    return value[offset:offset + length]


def concat(values):
    return ''.join(values)


def concat_components(components):
    return cartesian_components(components, lambda *values: ''.join(values))


def regex_capture(value, pattern):
    match = re.search(pattern, value)
    # OVAL returns an empty string for both no capture and no match.
    if match is None or not match.groups():
        return ['']
    return [match.group(1)]


def unique(values):
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def merge(values, delimiter='', sort='document', order='ascending'):
    values = list(values)
    if sort == 'lexical':
        values.sort(key=str)
    elif sort == 'numeric':
        values.sort(key=float)
    elif sort == 'natural':
        values.sort(key=lambda value: [int(token) if token.isdigit() else token
                                       for token in re.split(r'(\d+)', str(value))])
    if order == 'descending' and sort != 'document':
        values.reverse()
    return delimiter.join(str(value) for value in values)


def arithmetic_components(components, operation):
    return cartesian_components(components, lambda *values: arithmetic(values, operation))


def arithmetic(values, operation):
    values = list(values)
    if not values or any(isinstance(value, bool) or not isinstance(value, (int, float))
                         for value in values):
        raise ValueError('arithmetic requires non-empty numeric values')
    if operation == 'add':
        return sum(values)
    if operation == 'multiply':
        result = 1
        for value in values:
            result *= value
        return result
    raise ValueError('unsupported arithmetic operation: ' + operation)
