"""Reviewed cmdlet inputs: nullable module constraints and named input records.

Collector records use selection_match, not Test field existence/matching. Scalar
comparisons delegate to the common visitor so value_match remains independent.
"""
from copy import deepcopy

from v04_direct_scap_source import OVAL, attributes, ensure, local_name

NIL = '{http://www.w3.org/2001/XMLSchema-instance}nil'
SELECTION = {'all': 'every', 'at least one': 'one_or_more',
             'none satisfy': 'none', 'only one': 'exactly_one'}


def cmdlet_input(element, contract, compare_field, scalar_parameter):
    """One original input + its approved contract -> native parameter value."""
    if NIL in element.attrib:
        attributes(element, {NIL, 'datatype'})
        ensure(element.get(NIL) in ('true', '1') and contract.get('nullable') and
               not len(element) and not (element.text or '').strip(), 'unsupported cmdlet nil input')
        expected = 'record' if contract.get('schema_ref') == 'object_record' else (
            'version' if local_name(element) == 'module_version' else 'string')
        ensure(element.get('datatype', 'string' if expected == 'string' else None) == expected,
               'invalid nil input datatype')
        return None
    if contract.get('schema_ref') != 'object_record':
        value = scalar_parameter(element)
        if 'enum' in contract:
            ensure(isinstance(value, str) and value in contract['enum'], 'unknown/computed cmdlet enum input')
        return value
    attributes(element, {'datatype', 'operation'})
    ensure(element.get('datatype') == 'record' and element.get('operation', 'equals') == 'equals' and
           not (element.text or '').strip(), 'unsupported collector record type/comparator')
    fields = {}
    for child in element:
        attributes(child, {'name', 'datatype', 'operation', 'var_ref', 'var_check', 'entity_check'})
        name = child.get('name')
        ensure(child.tag == '{' + OVAL + '}field' and name and name not in fields and
               not any('A' <= c <= 'Z' for c in name), 'invalid/duplicate original collector field')
        selection = child.get('entity_check', 'all')
        ensure(selection in SELECTION, 'unsupported collector field entity_check')
        scalar = deepcopy(child)
        scalar.attrib.pop('name'); scalar.attrib.pop('entity_check', None)
        fields[name] = {**compare_field(scalar), 'selection_match': SELECTION[selection]}
        if local_name(element) == 'select':
            ensure(fields[name].get('equals') != '*', 'wildcard output selection outside approved contract')
    return {'fields': fields}
