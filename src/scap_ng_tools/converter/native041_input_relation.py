"""Project finite integer XCCDF Value relations to explicit Input allowed sets.

For a closed allowed enumeration A and source relation P, A intersection P
preserves the exact conjunction without new schema grammar, value casts, or
modification of the provenance-pinned OVAL visitor. Unsupported cases block.
"""
from copy import deepcopy
import operator

_OPS = {
    'less_than': operator.lt,
    'less_than_or_equal': operator.le,
    'greater_than': operator.gt,
    'greater_than_or_equal': operator.ge,
}


def project_input_relation(document):
    assessment = document.get('assessment') if isinstance(document, dict) else None
    if not isinstance(assessment, dict):
        return []
    inputs = assessment.get('inputs', {})
    if not isinstance(inputs, dict):
        return []  # Native schema diagnoses malformed Input mappings.
    updates, receipts = {}, []
    for name, spec in inputs.items():
        if not isinstance(spec, dict):
            continue
        constraint = spec.get('constraints')
        if not isinstance(constraint, dict) or 'relation' not in constraint:
            continue
        if spec.get('datatype') != 'integer':
            raise ValueError(f'Input {name}: finite-set relation needs integer source')
        if set(constraint) != {'allowed', 'relation'}:
            raise ValueError(f'Input {name}: relational constraint needs exact finite allowed set')
        allowed, relation = constraint['allowed'], constraint['relation']
        if not isinstance(allowed, list) or not allowed or not all(type(v) is int for v in allowed):
            raise ValueError(f'Input {name}: relation needs nonempty integer-only allowed list')
        if not isinstance(relation, dict) or set(relation) != {'operator', 'value'}:
            raise ValueError(f'Input {name}: unsupported relation shape')
        if relation['operator'] not in _OPS or type(relation['value']) is not int:
            raise ValueError(f'Input {name}: unsupported/noninteger relation boundary')
        predicate = _OPS[relation['operator']]
        narrowed = [v for v in allowed if predicate(v, relation['value'])]
        if not narrowed:
            raise ValueError(f'Input {name}: relation leaves no permitted values')
        updates[name] = {'allowed': narrowed}
        receipts.append({
            'input': name,
            'original_allowed': deepcopy(allowed),
            'source_relation': deepcopy(relation),
            'emitted_allowed': deepcopy(narrowed),
            'basis': 'finite_integer_allowed_intersection',
            'scanner_equivalence': False,
        })
    # Atomic: no partially lowered Input declarations on a failure.
    for name, constraints in updates.items():
        inputs[name]['constraints'] = constraints
    return receipts
