"""Materialize approved authoring policy from explicit converter terms (#255/#268).

This is a producer boundary, not a compiler repair/defaulting path. Source
entities must already have effective counts; no missing source check is filled
from an editor suggestion. Boolean/record boundaries and exceptions are kept.
"""
from copy import deepcopy

PAIR = ('values_found', 'values_matching')
LOGIC = ('and', 'or', 'one', 'xor')


def test_requirement(source):
    result = deepcopy(source)

    def vocabulary(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ('items_found', 'values_found', 'records_found') and value == 'may_be_absent':
                    node[key] = 'zero_or_more'
                else:
                    vocabulary(value)
        elif isinstance(node, list):
            for child in node:
                vocabulary(child)

    vocabulary(result)
    if set(result) == {'items_found'}:
        return result
    pairs = []

    def policy(node, inherited=None, *, prune=False):
        own = node.get('field_requirement', inherited)
        if own is not None and (not isinstance(own, dict) or set(own) != set(PAIR)):
            raise ValueError('source converter produced incomplete inherited field policy')
        for key in LOGIC:
            for child in node.get(key, []):
                policy(child, own, prune=prune)
        for predicate in node.get('fields', {}).values():
            if 'record' in predicate:
                policy(predicate['record'], own, prune=prune)
                continue
            present = set(PAIR) & set(predicate)
            if predicate.get('values_found') == 'none' and not (set(predicate) - {'values_found'}):
                continue  # Absence has no matching operation to inherit.
            if present and present != set(PAIR):
                raise ValueError('source converter produced incomplete field override')
            effective = {key: predicate[key] for key in PAIR} if present else own
            if effective is None:
                raise ValueError('source comparison has no effective explicit field policy')
            pairs.append(effective)
            if prune and present and effective == own:
                for key in PAIR:
                    predicate.pop(key)

    policy(result)
    if 'field_requirement' not in result:
        # An all-absence condition has no value matching. This complete pair is
        # deliberately non-operative for its explicit values_found:none leaves.
        result['field_requirement'] = deepcopy(pairs[0] if pairs else {
            'values_found': 'one_or_more', 'values_matching': 'every'})
    policy(result, prune=True)
    return result
