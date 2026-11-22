"""Approved explicit Input provision, static dominance and supplied-binding harness.

No collector, provider, wire-format binding adapter or implicit binding/default.
Refs #255 #269. Snapshots and supplied-result caches are invocation-bound.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import re

def canonical_json(value):
    """Exact canonical bytes of the original graph index, minus its imports."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')

PRESENCE_VERSION = 1
CARDS = {'exactly_one', 'zero_or_one', 'one_or_more', 'zero_or_more'}
RELATION_OPERATORS = {'less_than', 'less_than_or_equal', 'greater_than', 'greater_than_or_equal'}
CONSTRAINT_OPERATORS = {'equals', 'not_equal', 'case_insensitive_equals', 'case_insensitive_not_equal',
                        'greater_than', 'greater_than_or_equal', 'less_than', 'less_than_or_equal',
                        'matches_regex', 'subset_of', 'superset_of', 'bitwise_and', 'bitwise_or',
                        'float_equals', 'float_not_equal', 'float_greater_than', 'float_greater_than_or_equal',
                        'float_less_than', 'float_less_than_or_equal', 'binary_equals', 'binary_not_equal',
                        'ipv4_equals', 'ipv4_not_equal', 'ipv4_greater_than', 'ipv4_greater_than_or_equal',
                        'ipv4_less_than', 'ipv4_less_than_or_equal', 'ipv4_subset_of', 'ipv4_superset_of',
                        'ipv6_equals', 'ipv6_not_equal', 'ipv6_greater_than', 'ipv6_greater_than_or_equal',
                        'ipv6_less_than', 'ipv6_less_than_or_equal', 'ipv6_subset_of', 'ipv6_superset_of',
                        'version_equals', 'version_not_equal', 'version_greater_than', 'version_greater_than_or_equal',
                        'version_less_than', 'version_less_than_or_equal', 'rpm_evr_equals', 'rpm_evr_not_equal',
                        'rpm_evr_greater_than', 'rpm_evr_greater_than_or_equal', 'rpm_evr_less_than',
                        'rpm_evr_less_than_or_equal', 'debian_evr_equals', 'debian_evr_not_equal',
                        'debian_evr_greater_than', 'debian_evr_greater_than_or_equal', 'debian_evr_less_than',
                        'debian_evr_less_than_or_equal', 'fileset_revision_equals', 'fileset_revision_not_equal',
                        'fileset_revision_greater_than', 'fileset_revision_greater_than_or_equal',
                        'fileset_revision_less_than', 'fileset_revision_less_than_or_equal', 'ios_version_equals',
                        'ios_version_not_equal', 'ios_version_greater_than', 'ios_version_greater_than_or_equal',
                        'ios_version_less_than', 'ios_version_less_than_or_equal'}
CONSTRAINT_BOOLEAN = {'and', 'or', 'one', 'xor'}
MAX_CONSTRAINT_DEPTH = 32
MAX_CONSTRAINT_NODES = 256
DOMAINS = {'string', 'integer', 'boolean', 'float', 'binary', 'version', 'ipv4',
           'ipv6', 'rpm_evr', 'debian_evr', 'fileset_revision', 'ios_version', 'record'}


def _constraint_domain(operation):
    # Longest prefixes must win: ``rpm_evr_equals`` is an rpm_evr
    # comparison, not an (invalid) ``rpm`` domain.
    for domain in ('rpm_evr', 'debian_evr', 'fileset_revision', 'ios_version',
                   'ipv4', 'ipv6', 'float', 'binary', 'version'):
        if operation.startswith(domain + '_'):
            return domain
    return None


def _constraint_operation_allowed(datatype, operation):
    """Enforce the OVAL datatype/operation crosswalk for Input predicates."""
    domain = _constraint_domain(operation)
    if domain is not None:
        return domain == datatype
    if datatype == 'string':
        return operation in {'equals', 'not_equal', 'case_insensitive_equals',
                             'case_insensitive_not_equal', 'matches_regex'}
    if datatype == 'boolean':
        return operation in {'equals', 'not_equal'}
    if datatype == 'integer':
        return operation in {'equals', 'not_equal', 'greater_than',
                             'greater_than_or_equal', 'less_than',
                             'less_than_or_equal', 'bitwise_and', 'bitwise_or'}
    # Generic numeric order operators are retained for a native float Input;
    # source converters emit the explicit float_* keys.
    if datatype == 'float':
        return operation in {'equals', 'not_equal', 'greater_than',
                             'greater_than_or_equal', 'less_than',
                             'less_than_or_equal'}
    return False


def _validate_constraint_expression(node, datatype, *, depth=1, counter=None):
    counter = counter if counter is not None else [0]
    if depth > MAX_CONSTRAINT_DEPTH:
        raise ValueError('Input predicate exceeds expression depth limit')
    counter[0] += 1
    if counter[0] > MAX_CONSTRAINT_NODES:
        raise ValueError('Input predicate exceeds expression node limit')
    if not isinstance(node, dict) or not node:
        raise ValueError('Input predicate must be an object')

    # A comparison leaf is valid with or without the optional explicit
    # datatype annotation.  The previous implementation only recognized a
    # leaf when it had more than one property, so a normal one-property
    # ``matches_regex``/``equals`` leaf fell through to the Boolean-operator
    # branch and was rejected despite being admitted by the canonical schema.
    operations = set(node) & CONSTRAINT_OPERATORS
    if len(operations) == 1 and set(node) - operations <= {'datatype'}:
        operation = next(iter(operations))
        explicit = node.get('datatype')
        if explicit is not None and explicit != datatype:
            raise ValueError('Input predicate datatype conflicts with enclosing Input')
        if not _constraint_operation_allowed(datatype, operation):
            raise ValueError('Input predicate operation is incompatible with datatype')
        bound = node[operation]
        if operation in {'matches_regex', 'case_insensitive_equals', 'case_insensitive_not_equal'}:
            if not isinstance(bound, str) or len(bound) > 4096:
                raise ValueError('Input predicate requires bounded string comparison literal')
            if operation == 'matches_regex':
                try:
                    re.compile(bound)
                except re.error as exc:
                    raise ValueError('Input predicate has malformed regex') from exc
        elif not _value_valid(bound, datatype if _constraint_domain(operation) is None
                              else _constraint_domain(operation)):
            raise ValueError('Input predicate literal conflicts with enclosing Input datatype')
        return

    if len(node) != 1:
        raise ValueError('Input predicate must contain exactly one comparison or Boolean operator')
    operation, value = next(iter(node.items()))
    if operation in CONSTRAINT_BOOLEAN:
        if not isinstance(value, list) or not value or len(value) > 64:
            raise ValueError('Input predicate Boolean branch count is outside bounds')
        for child in value:
            _validate_constraint_expression(child, datatype, depth=depth + 1, counter=counter)
        return
    raise ValueError('unsupported Input predicate operation: ' + str(operation))


def _natural_compare(left, right):
    """Bounded OVAL-compatible fallback ordering for string version domains.

    Native typed comparison tags remain explicit in the emitted contract. This
    helper is only the invocation binding gate; it never rewrites source text.
    Numeric runs compare numerically and other runs lexically, preserving the
    source's separator-independent version structure for the generic domains.
    """
    def key(value):
        return [(0, int(part)) if part.isdigit() else (1, part.lower())
                for part in re.findall(r'[0-9]+|[^0-9]+', value)]
    a, b = key(left), key(right)
    for x, y in zip(a, b):
        if x != y:
            return -1 if x < y else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def _version_compare(left, right):
    # OVAL version values are hierarchical non-negative integer components;
    # missing trailing components are padded with zero.
    a = [int(part) for part in re.findall(r'[0-9]+', left)]
    b = [int(part) for part in re.findall(r'[0-9]+', right)]
    size = max(len(a), len(b))
    a.extend([0] * (size - len(a)))
    b.extend([0] * (size - len(b)))
    return (a > b) - (a < b)


def _typed_compare(domain, operation, value, bound):
    base = operation[len(domain) + 1:]
    if domain == 'binary':
        try:
            value, bound = bytes.fromhex(value), bytes.fromhex(bound)
        except (TypeError, ValueError):
            return False
    elif domain in {'ipv4', 'ipv6'}:
        from ipaddress import ip_network
        try:
            value, bound = ip_network(value, strict=False), ip_network(bound, strict=False)
        except ValueError:
            return False
        if value.version != (4 if domain == 'ipv4' else 6) or bound.version != value.version:
            return False
        if base in {'subset_of', 'superset_of'}:
            return (value.subnet_of(bound) if base == 'subset_of'
                    else value.supernet_of(bound))
        if value.network.prefixlen != bound.network.prefixlen:
            return False
        value, bound = int(value.network.network_address), int(bound.network.network_address)
    elif domain == 'float':
        try:
            value, bound = float(value), float(bound)
        except (TypeError, ValueError):
            return False
    elif domain == 'version':
        comparison = _version_compare(value, bound)
        return {'equals': comparison == 0, 'not_equal': comparison != 0,
                'greater_than': comparison > 0, 'greater_than_or_equal': comparison >= 0,
                'less_than': comparison < 0, 'less_than_or_equal': comparison <= 0}[base]
    elif domain in {'rpm_evr', 'debian_evr', 'fileset_revision', 'ios_version'}:
        comparison = _natural_compare(value, bound)
        return {'equals': comparison == 0, 'not_equal': comparison != 0,
                'greater_than': comparison > 0, 'greater_than_or_equal': comparison >= 0,
                'less_than': comparison < 0, 'less_than_or_equal': comparison <= 0}[base]
    if base == 'equals': return value == bound
    if base == 'not_equal': return value != bound
    if base == 'greater_than': return value > bound
    if base == 'greater_than_or_equal': return value >= bound
    if base == 'less_than': return value < bound
    if base == 'less_than_or_equal': return value <= bound
    return False


def _constraint_matches(value, node):
    if 'and' in node: return all(_constraint_matches(value, child) for child in node['and'])
    if 'or' in node: return any(_constraint_matches(value, child) for child in node['or'])
    if 'one' in node: return sum(_constraint_matches(value, child) for child in node['one']) == 1
    if 'xor' in node: return sum(_constraint_matches(value, child) for child in node['xor']) % 2 == 1
    operation = next(key for key in node if key != 'datatype')
    bound = node[operation]
    domain = _constraint_domain(operation)
    if domain:
        return _typed_compare(domain, operation, value, bound)
    if operation == 'equals': return value == bound
    if operation == 'not_equal': return value != bound
    if operation == 'case_insensitive_equals': return isinstance(value, str) and value.casefold() == bound.casefold()
    if operation == 'case_insensitive_not_equal': return isinstance(value, str) and value.casefold() != bound.casefold()
    if operation == 'matches_regex': return isinstance(value, str) and re.fullmatch(bound, value) is not None
    if operation in {'greater_than','greater_than_or_equal','less_than','less_than_or_equal'}:
        return {'greater_than': value > bound, 'greater_than_or_equal': value >= bound,
                'less_than': value < bound, 'less_than_or_equal': value <= bound}[operation]
    if operation == 'bitwise_and': return type(value) is int and type(bound) is int and (value & bound) == bound
    if operation == 'bitwise_or': return type(value) is int and type(bound) is int and (value | bound) == bound
    raise ValueError('Input predicate operation is not executable: ' + operation)


def _input_constraints_valid(value, constraints):
    alternatives = [canonical_json(value) == canonical_json(item) for item in constraints.get('allowed', [])]
    if 'predicate' in constraints:
        alternatives.append(_constraint_matches(value, constraints['predicate']))
    return not alternatives or any(alternatives)

def input_contracts(assessment):
    inputs = assessment.get('inputs', {})
    if not isinstance(inputs, dict):
        raise ValueError('Input declarations must be a mapping')
    for name, decl in inputs.items():
        if (not isinstance(name, str) or len(name) > 64 or
                not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*-input', name)):
            raise ValueError('invalid Input identity')
        if (not isinstance(decl, dict) or decl.get('datatype') not in DOMAINS or
                decl.get('cardinality') not in CARDS or type(decl.get('required')) is not bool):
            raise ValueError('Input requires explicit datatype/cardinality/required: ' + name)
        if set(decl)-{'datatype','cardinality','required','description','constraints'}:
            raise ValueError('unsupported Input declaration control; no implicit default: ' + name)
        constraints = decl.get('constraints', {})
        if not isinstance(constraints,dict) or set(constraints)-{'allowed', 'predicate', 'relation'}:
            raise ValueError('unsupported Input constraints: ' + name)
        if 'allowed' in constraints and (not isinstance(constraints['allowed'],list) or
                any(not _value_valid(v,decl['datatype']) for v in constraints['allowed'])):
            raise ValueError('invalid typed Input allowed-value constraints: ' + name)
        if 'predicate' in constraints:
            _validate_constraint_expression(constraints['predicate'], decl['datatype'])
        if 'relation' in constraints:
            relation = constraints['relation']
            if (not isinstance(relation, dict) or set(relation) != {'operator', 'value'} or
                    relation['operator'] not in RELATION_OPERATORS or
                    decl['datatype'] not in {'integer', 'float'} or
                    not _value_valid(relation['value'], decl['datatype'])):
                raise ValueError('invalid typed Input relational constraint: ' + name)
    return json.loads(canonical_json(inputs))


def presence_contract(assessment):
    """Check all source references; prove positive dominance at every use site."""
    inputs = input_contracts(assessment)
    tables = {'test': assessment.get('tests', {}), 'object': assessment.get('shared_objects', {}),
              'variable': assessment.get('variables', {}), 'assessment': assessment.get('dependencies', {})}
    active, complete = set(), {}

    def dependencies(kind, name):
        key = (kind, name)
        if name not in tables[kind]:
            raise ValueError('unresolved ' + kind + ' reference: ' + str(name))
        if key in active:
            raise ValueError('cyclic optional Input dependency')
        if key in complete:
            return complete[key]
        if len(active) > 256:
            raise ValueError('Input dependency resource limit')
        active.add(key)
        found = set()
        stack = [(tables[kind][name], False)]
        count = 0
        while stack:
            node, field_map = stack.pop(); count += 1
            if count > 16384:
                raise ValueError('Input dependency resource limit')
            if isinstance(node, list):
                stack.extend((child, False) for child in node)
            elif isinstance(node, dict):
                if set(node) == {'literal'} and not field_map:
                    continue  # Literal records are opaque data.
                if set(node) == {'input'} and isinstance(node['input'], str):
                    if node['input'] not in inputs:
                        raise ValueError('unresolved or untyped input: ' + node['input'])
                    found.add(node['input'])
                    continue
                for field in ('variable', 'object'):
                    if isinstance(node.get(field), str):
                        found.update(dependencies(field, node[field]))
                loop = node.get('for_each')
                if isinstance(loop, dict) and isinstance(loop.get('in'), str):
                    found.update(dependencies('object', loop['in']))
                stack.extend((v, k == 'fields') for k, v in node.items())
        active.remove(key)
        complete[key] = found
        return found

    for kind, table in tables.items():
        for name in table:
            if kind == 'assessment' and isinstance(table[name],dict) and set(table[name]) & {'inputs','input_bindings'}:
                raise ValueError('dependency Input binding syntax is not implemented; no implicit binding')
            dependencies(kind, name)  # Even unused declarations close statically.
    sites, guards = [], set()
    count = 0

    def walk(node, provided, path, *, guard=False, applicability=False):
        nonlocal count
        count += 1
        if count > 16384 or len(path) > 256 or not isinstance(node, dict):
            raise ValueError('invalid Input guard expression/resource limit')
        if 'if' in node:
            if not {'if', 'then', 'else'} <= set(node) or set(node) - {'if','then','else','else_if'}:
                raise ValueError('conditional requires if/then/final else')
            alternatives = node.get('else_if', [])
            if not isinstance(alternatives, list) or ('else_if' in node and not alternatives):
                raise ValueError('invalid ordered else_if')
            for index, branch in enumerate([node, *alternatives]):
                if index and (not isinstance(branch, dict) or set(branch) != {'if', 'then'}):
                    raise ValueError('invalid else_if entry')
                at = path if not index else path + ['else_if', index - 1]
                condition = branch['if']
                walk(condition, provided, at + ['if'], guard=True, applicability=applicability)
                additional = {condition['input_provided']} if set(condition) == {'input_provided'} else set()
                walk(branch['then'], provided | additional, at + ['then'], applicability=applicability)
            walk(node['else'], provided, path + ['else'], applicability=applicability)
            return
        if len(node) != 1:
            raise ValueError('expression must have exactly one operator')
        op, value = next(iter(node.items()))
        if op == 'input_provided':
            if not guard or applicability:
                raise ValueError('input_provided is only a direct evaluate if/else_if guard')
            if not isinstance(value, str) or value not in inputs:
                raise ValueError('unresolved Input presence reference')
            guards.add(value)
        elif op in ('test', 'assessment'):
            if not isinstance(value, str):
                raise ValueError('invalid consumer reference')
            needed = dependencies(op, value)
            optional = {i for i in needed if not inputs[i]['required']}
            if optional - provided:
                raise ValueError('unguarded optional Input consumption at ' + '/'.join(map(str, path)) +
                                 ': ' + ', '.join(sorted(optional - provided)))
            sites.append({'kind': op, 'id': value, 'path': path, 'inputs': sorted(needed)})
        elif op in ('and', 'or', 'one', 'xor'):
            if not isinstance(value, list) or not value:
                raise ValueError('empty logical group')
            for i, child in enumerate(value):
                walk(child, provided, path + [op, i], applicability=applicability)
        elif op == 'not':
            walk(value, provided, path + [op], applicability=applicability)
        elif op not in ('not_applicable', 'not_evaluated'):
            raise ValueError('unsupported result operator: ' + op)

    for field in ('evaluate', 'applicability'):
        if assessment.get(field) is not None:
            walk(assessment[field], set(), [field], applicability=field == 'applicability')
    return {'version': PRESENCE_VERSION, 'guards': sorted(guards), 'contracts': inputs,
            'consumers': sites}


class PendingInputBinding(ValueError):
    """No final technical outcome exists while provision resolution is pending."""


_SNAPSHOT_TOKEN = object()


@dataclass(frozen=True, init=False)
class InputBindingSnapshot:
    """Immutable canonical bytes include invocation ID, contracts, states and sources."""
    raw: bytes

    def __init__(self, raw, *, _token=None):
        if _token is not _SNAPSHOT_TOKEN:
            raise ValueError('construct binding snapshots through bind_inputs')
        object.__setattr__(self, 'raw', raw)

    @property
    def identity(self):
        return sha256(self.raw).hexdigest()

    def document(self):
        return json.loads(self.raw)  # Mutating a returned copy cannot alter the snapshot.

    def state(self, name):
        doc = self.document()
        entry = doc['bindings'][name]
        if entry['state'] == 'pending':
            raise PendingInputBinding(entry['reason'])
        if entry['state'] == 'omitted':
            # Canonical 0.4.1 treats a missing required Input as not evaluated;
            # an explicitly omitted optional Input remains a false presence
            # guard.  Do not collapse either case into acquisition error.
            return 'not_evaluated' if doc['contracts'][name]['required'] else 'false'
        return {'provided': 'true', 'error': 'error', 'unknown': 'unknown'}[entry['state']]


def _value_valid(value, datatype):
    if datatype == 'integer': return type(value) is int
    if datatype == 'boolean': return type(value) is bool
    if datatype == 'float': return type(value) in (float, int) and math.isfinite(value)
    if datatype == 'record': return isinstance(value, dict)
    if not isinstance(value, str): return False
    if datatype == 'version': return re.fullmatch(r'[0-9]+(?:[^0-9][0-9]+)*', value) is not None
    if datatype == 'binary': return re.fullmatch(r'(?:[0-9a-fA-F]{2})*', value) is not None
    if datatype in ('ipv4', 'ipv6'):
        from ipaddress import ip_interface
        try: return ip_interface(value).version == (4 if datatype == 'ipv4' else 6)
        except ValueError: return False
    return True  # Other approved text domains keep lexical data; no comparison executes.


def _relation_valid(value, operator, bound):
    """Compare already-typed numeric Input values; never coerce lexical data."""
    if type(value) is bool or type(bound) is bool:
        return False
    try:
        return {'less_than': value < bound,
                'less_than_or_equal': value <= bound,
                'greater_than': value > bound,
                'greater_than_or_equal': value >= bound}[operator]
    except (KeyError, TypeError):
        return False


def bind_inputs(contracts, bindings, *, invocation_id):
    """Bind explicit states, not wire syntax. No missing entry is inferred omitted."""
    contracts = input_contracts({'inputs': contracts})
    if not isinstance(invocation_id, str) or not invocation_id.strip():
        raise ValueError('explicit invocation identity required')
    if not isinstance(bindings, dict) or set(bindings) != set(contracts):
        raise ValueError('explicit binding state required for every declared Input; no unknown bindings')
    entries = json.loads(canonical_json(bindings))
    for name, entry in entries.items():
        if (not isinstance(entry, dict) or entry.get('state') not in
                {'provided','omitted','error','unknown','pending'} or
                not isinstance(entry.get('source'), str) or not entry['source'].strip()):
            raise ValueError('binding state/source must be explicit')
        if 'reason' in entry and (not isinstance(entry['reason'],str) or not entry['reason'].strip()):
            raise ValueError('binding reason must be nonempty text')
        if 'source_ref' in entry and entry['source_ref'] is not None and not isinstance(entry['source_ref'],str):
            raise ValueError('binding source reference must be text or null')
        if set(entry) - {'state','source','source_ref','reason','values'}:
            raise ValueError('unknown binding fields')
        state, contract = entry['state'], contracts[name]
        if state in ('error','unknown','pending') and (not isinstance(entry.get('reason'),str) or not entry['reason'].strip()):
            raise ValueError('indeterminate/failed binding requires reason')
        if state != 'provided' and 'values' in entry:
            raise ValueError('values on an unprovided binding')
        reason = None
        if state == 'omitted' and contract['required']:
            reason = 'required Input was omitted'
        elif state == 'provided':
            values = entry.get('values')
            if not isinstance(values, list):
                reason = 'provided Input requires explicit value population'
            else:
                card, n = contract['cardinality'], len(values)
                if ((card == 'exactly_one' and n != 1) or (card == 'zero_or_one' and n > 1)
                        or (card == 'one_or_more' and n < 1)):
                    reason = 'provided Input violates cardinality'
                elif any(not _value_valid(v, contract['datatype']) for v in values):
                    reason = 'provided Input violates datatype'
                constraints = contract.get('constraints', {})
                if not isinstance(constraints, dict) or set(constraints) - {'allowed', 'predicate', 'relation'}:
                    reason = 'unsupported Input constraints; binding cannot be validated'
                elif any(not _input_constraints_valid(v, constraints) for v in values):
                    reason = 'provided Input violates allowed/restriction constraints'
                elif 'relation' in constraints:
                    relation = constraints['relation']
                    if (not isinstance(relation, dict) or set(relation) != {'operator', 'value'} or
                            relation.get('operator') not in RELATION_OPERATORS):
                        reason = 'invalid Input relational constraint'
                    elif any(not _relation_valid(v, relation['operator'], relation['value']) for v in values):
                        reason = 'provided Input violates relational constraint'
        if reason:
            # Preserve attempted values/source as evidence, never substitute a
            # value. Required omission is a canonical not_evaluated state, not
            # an acquisition error; all other invalid attempts are errors.
            if state == 'omitted' and contract['required']:
                entry['reason'] = reason
            else:
                entry['state'], entry['reason'] = 'error', reason
    return InputBindingSnapshot(canonical_json({'version': PRESENCE_VERSION, 'invocation_id': invocation_id,
                                               'contracts': contracts, 'bindings': entries}), _token=_SNAPSHOT_TOKEN)
