"""Approved OVAL/native datatype identities; no comparison evaluation.

String-based special types keep their exact lexical values and select the
already-approved typed comparison operator. They never fall back to ordinary
string equality/order. Float conversion remains unsupported here: finite JSON
numbers alone do not establish source floating-point representation fidelity.
"""
from v04_direct_scap_source import UnsupportedSource, ensure

SOURCE_TYPES = {
    'string': 'string', 'int': 'integer', 'boolean': 'boolean',
    'binary': 'binary', 'version': 'version',
    'evr_string': 'rpm_evr', 'debian_evr_string': 'debian_evr',
    'fileset_revision': 'fileset_revision', 'ios_version': 'ios_version',
    'ipv4_address': 'ipv4', 'ipv6_address': 'ipv6',
}
SPECIAL_TYPES = {key: value for key, value in SOURCE_TYPES.items()
                 if key not in ('string', 'int', 'boolean')}
ORDERED = frozenset({'equals', 'not equal', 'greater than', 'greater than or equal',
                     'less than', 'less than or equal'})
SPECIAL_OPERATIONS = {name: ORDERED for name in SPECIAL_TYPES}
SPECIAL_OPERATIONS.update(binary=frozenset({'equals', 'not equal'}),
    ipv4_address=ORDERED | {'subset of', 'superset of'},
    ipv6_address=ORDERED | {'subset of', 'superset of'})


def native_datatype(source_type):
    ensure(source_type in SOURCE_TYPES, f'unsupported Variable datatype: {source_type}')
    return SOURCE_TYPES[source_type]


def literal(source_type, text):
    """Convert only source lexical forms with an approved native representation."""
    ensure(source_type in SOURCE_TYPES, f'unsupported scalar datatype: {source_type}')
    if source_type == 'boolean':
        ensure(text in ('true', 'false', '1', '0'), 'invalid boolean literal')
        return text in ('true', '1')
    try:
        return int(text) if source_type == 'int' else text
    except ValueError as error:
        raise UnsupportedSource(f'invalid {source_type} literal: {text!r}') from error


def comparison(source_type, operation, generic):
    """Keep the source algorithm as a self-describing native typed operator."""
    if source_type not in SPECIAL_TYPES:
        ensure(operation not in ('subset of', 'superset of'), 'address operation requires address datatype')
        ensure(operation not in ('bitwise and', 'bitwise or') or source_type == 'int',
               'bitwise operation requires integer datatype')
        return generic
    ensure(operation in SPECIAL_OPERATIONS[source_type],
           f'unsupported typed comparison: {source_type} {operation}')
    return SPECIAL_TYPES[source_type] + '_' + generic
