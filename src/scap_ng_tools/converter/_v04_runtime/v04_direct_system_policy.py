"""Source field contracts for two approved current-system policy acquisitions.

Input is one original State entity plus its versioned capability mapping; output
is the checked entity, without changing the source tree. The independent proof
reader derives the required fixed datatype attributes separately
from the original XSD, rather than importing this conversion helper.
"""
from v04_direct_scap_source import UnsupportedSource, ensure, local_name

POLICIES = frozenset({'windows.passwordpolicy', 'windows.lockoutpolicy'})
NONNEGATIVE = {'windows.passwordpolicy': {'max_passwd_age'},
               'windows.lockoutpolicy': {'force_logoff', 'lockout_duration'}}


def policy_entity(element, mapping):
    """Check required source types/ranges; keep Variable checks for evaluation."""
    if mapping['capability'] not in POLICIES:
        return element
    field = local_name(element)
    types = mapping['native']['field_datatypes'].get(field)
    ensure(types in (['integer'], ['boolean']), 'unsupported policy field datatype')
    datatype = 'int' if types == ['integer'] else 'boolean'
    # EntityStateIntType/BoolType use="required", fixed="int"/"boolean".
    # A fixed attribute is not an omission default when its use is required.
    ensure(element.get('datatype') == datatype, 'policy field requires explicit source datatype ' + datatype)
    if field in NONNEGATIVE[mapping['capability']] and not element.get('var_ref'):
        try:
            value = int(element.text or '')
        except ValueError as error:
            raise UnsupportedSource('policy field requires an integer literal') from error
        ensure(value >= 0, 'policy source literal must be nonnegative')
    return element
