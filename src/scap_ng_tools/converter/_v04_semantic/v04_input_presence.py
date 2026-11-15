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
DOMAINS = {'string', 'integer', 'boolean', 'float', 'binary', 'version', 'ipv4',
           'ipv6', 'rpm_evr', 'debian_evr', 'fileset_revision', 'ios_version', 'record'}


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
        if not isinstance(constraints,dict) or set(constraints)-{'allowed', 'relation'}:
            raise ValueError('unsupported Input constraints: ' + name)
        if 'allowed' in constraints and (not isinstance(constraints['allowed'],list) or
                any(not _value_valid(v,decl['datatype']) for v in constraints['allowed'])):
            raise ValueError('invalid typed Input allowed-value constraints: ' + name)
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
        return {'provided': 'true', 'omitted': 'false', 'error': 'error', 'unknown': 'unknown'}[entry['state']]


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
                if not isinstance(constraints, dict) or set(constraints) - {'allowed', 'relation'}:
                    reason = 'unsupported Input constraints; binding cannot be validated'
                elif 'allowed' in constraints and (not isinstance(constraints['allowed'],list) or
                        any(not any(canonical_json(v) == canonical_json(a) for a in constraints['allowed']) for v in values)):
                    reason = 'provided Input violates allowed values'
                elif 'relation' in constraints:
                    relation = constraints['relation']
                    if (not isinstance(relation, dict) or set(relation) != {'operator', 'value'} or
                            relation.get('operator') not in RELATION_OPERATORS):
                        reason = 'invalid Input relational constraint'
                    elif any(not _relation_valid(v, relation['operator'], relation['value']) for v in values):
                        reason = 'provided Input violates relational constraint'
        if reason:
            # Preserve attempted values/source as evidence, never substitute a value.
            entry['state'], entry['reason'] = 'error', reason
    return InputBindingSnapshot(canonical_json({'version': PRESENCE_VERSION, 'invocation_id': invocation_id,
                                               'contracts': contracts, 'bindings': entries}), _token=_SNAPSHOT_TOKEN)
