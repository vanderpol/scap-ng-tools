"""Source-conservative, opt-in 0.4 Test presentation compaction (Refs #264).

This is an authoring projection, not an OVAL/scanner equivalence proof. The
caller must coalesce a State's fields *before* combining separate source
States. The exact preimage travels in a sidecar so a review can undo edits.
"""

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json


LOGIC = frozenset({'and', 'or', 'one', 'xor'})
POLICY = ('values_found', 'values_matching')


def fingerprint(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False).encode()).hexdigest()


def _edit(original, candidate, operation):
    if candidate == original:
        return deepcopy(original), None
    return candidate, {'operation': operation, 'original': deepcopy(original),
                       'original_sha256': fingerprint(original),
                       'candidate_sha256': fingerprint(candidate)}


def restore(candidate, edit):
    """Reject stale/edited projections and reconstruct the exact source tree."""
    if not edit or fingerprint(candidate) != edit['candidate_sha256']:
        raise ValueError('compacted authoring changed after its review ledger')
    original = deepcopy(edit['original'])
    if fingerprint(original) != edit['original_sha256']:
        raise ValueError('compaction review ledger corrupted')
    return original


def compact_source_state(condition):
    """Fold a *single* OVAL State's scalar AND into its implicit fields AND.

    Do not call on an entire Test requirement or a conjunction of States.
    Repeated names, records, nested Boolean clauses, absence-only predicates,
    field-local scoped policies and other shapes remain untouched. Comparator-free scalar absence can share the same implicit AND.
    """
    original = deepcopy(condition)
    if not isinstance(condition, dict) or set(condition) != {'and'}:
        return original, None
    clauses = condition['and']
    if not isinstance(clauses, list) or len(clauses) < 2:
        return original, None
    fields = {}
    for clause in clauses:
        if (not isinstance(clause, dict) or set(clause) != {'fields'}
                or not isinstance(clause['fields'], dict)
                or len(clause['fields']) != 1):
            return original, None
        name, predicate = next(iter(clause['fields'].items()))
        if (not isinstance(name, str) or name in fields
                or not isinstance(predicate, dict) or not predicate
                or 'record' in predicate or 'field_requirement' in predicate
                or (set(predicate) != {'values_found'} or predicate['values_found'] != 'none')
                   and set(POLICY) - set(predicate)):
            return original, None
        fields[name] = deepcopy(predicate)
    return _edit(original, {'fields': fields}, 'source-state-scalar-and')


def _fields_in(condition):
    """Return scalar field predicates only for a fully understood condition."""
    if not isinstance(condition, dict) or not condition:
        return None
    if 'field_requirement' in condition:
        return None
    if 'fields' in condition and set(condition) == {'fields'}:
        fields = condition['fields']
        if not isinstance(fields, dict) or not fields:
            return None
        predicates = []
        for predicate in fields.values():
            if (not isinstance(predicate, dict) or 'record' in predicate
                    or 'field_requirement' in predicate
                    or not set(POLICY) <= set(predicate)):
                return None
            predicates.append(predicate)
        return predicates
    if len(condition) == 1:
        op, children = next(iter(condition.items()))
        if op in LOGIC and isinstance(children, list) and children:
            predicates = []
            for child in children:
                part = _fields_in(child)
                if part is None:
                    return None
                predicates.extend(part)
            return predicates
    return None


def compact_test_requirement(requirement):
    """Lift the most common explicit pair; keep minority field overrides.

    No implicit quantifiers are introduced: all leaves must already have both
    controls. Do not alter an AND/OR/ONE/XOR boundary or record semantics.
    Fields containing absent-only or unrecognized forms veto the rewrite.
    """
    original = deepcopy(requirement)
    if (not isinstance(requirement, dict) or 'field_requirement' in requirement
            or 'items_satisfying' not in requirement):
        return original, None
    branches = set(requirement) - {'items_found', 'items_satisfying'}
    if len(branches) != 1:
        return original, None
    key = next(iter(branches))
    if key not in LOGIC | {'fields'}:
        return original, None
    condition = {key: requirement[key]}
    predicates = _fields_in(condition)
    if predicates is None or len(predicates) < 2:
        return original, None
    pairs = [tuple(predicate[field] for field in POLICY) for predicate in predicates]
    # Keep a deterministic winner by observed first occurrence on ties.
    counts = Counter(pairs)
    common = max(counts, key=lambda pair: counts[pair])
    if counts[common] < 2:
        return original, None
    candidate = deepcopy(requirement)

    def rewrite(node):
        if 'fields' in node:
            for predicate in node['fields'].values():
                if tuple(predicate[field] for field in POLICY) == common:
                    for field in POLICY:
                        del predicate[field]
        else:
            op = next(iter(node))
            for child in node[op]:
                rewrite(child)

    rewrite({key: candidate[key]})
    candidate['field_requirement'] = dict(zip(POLICY, common))
    # Put defaults before conditions so the YAML reads from general to specific.
    condition_value = candidate.pop(key)
    candidate[key] = condition_value
    return _edit(original, candidate, 'test-inherited-field-cardinality')
