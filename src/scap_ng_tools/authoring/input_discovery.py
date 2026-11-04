"""Native SCAP-NG 0.4 Organizational Input discovery.

The index is compiler metadata, not author-entered source coordinates and not
an evaluation/scanner result.  It walks only the native 0.4 Assessment body:
actual ``input`` value references and direct ``input_provided`` guards become
RFC 6901 pointers.  Literal payloads remain opaque data.
"""
from collections import Counter
import json
import re


_PARAMETER_CARDINALITY = {
    'one': 'exactly_one',
    'exactly_one': 'exactly_one',
    'zero_or_one': 'zero_or_one',
    'optional': 'zero_or_one',
    'one_or_more': 'one_or_more',
    'zero_or_more': 'zero_or_more',
}


def _pointer_escape(value):
    return str(value).replace('~', '~0').replace('/', '~1')


def _pointer_parts(pointer):
    """Decode an RFC 6901 pointer and reject non-canonical escape syntax."""
    if not isinstance(pointer, str) or not pointer.startswith('/'):
        raise ValueError('source_path must be an RFC 6901 pointer')
    parts = []
    for token in pointer[1:].split('/'):
        # A bare '~' or '~' followed by anything except 0/1 is invalid.
        if re.search(r'~(?![01])', token):
            raise ValueError('source_path contains an invalid RFC 6901 escape')
        parts.append(token.replace('~1', '/').replace('~0', '~'))
    return parts


def _resolve_pointer(document, pointer):
    node = document
    for part in _pointer_parts(pointer):
        if isinstance(node, list):
            if not re.fullmatch(r'0|[1-9][0-9]*', part):
                raise ValueError('source_path contains an invalid array index')
            index = int(part)
            if index >= len(node):
                raise ValueError('source_path points outside an array')
            node = node[index]
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            raise ValueError('source_path does not resolve in the Assessment')
    return node


def input_locations(assessment):
    """Return every native Input reference with its exact Assessment pointer."""
    result = []

    def walk(node, path):
        if isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, path + [str(index)])
        elif isinstance(node, dict):
            # A literal is typed data, including records that happen to contain
            # keys named ``input`` or ``input_provided``.  Record fields are
            # grammar-owned predicates and are therefore traversed.
            if set(node) == {'literal'} and (not path or path[-1] != 'fields'):
                return
            for key, child in node.items():
                route = path + [key]
                if (isinstance(child, str) and
                        ((key == 'input' and set(node) == {'input'}) or
                         (key == 'input_provided' and set(node) == {'input_provided'}))):
                    result.append({
                        'input': child,
                        'source_path': '/' + '/'.join(_pointer_escape(part) for part in route),
                        'kind': 'presence' if key == 'input_provided' else 'value',
                    })
                else:
                    walk(child, route)

    for section in ('tests', 'variables', 'shared_objects', 'evaluate', 'applicability'):
        walk(assessment.get(section), [section])
    return result


def _parameter_id(binding):
    if isinstance(binding, str):
        return binding
    if isinstance(binding, dict) and set(binding) == {'parameter'}:
        return binding['parameter']
    return None


def _normalize_cardinality(value):
    return _PARAMETER_CARDINALITY.get(value)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False)


def _validate_bindings(assessment, bindings, parameters):
    contracts = assessment.get('inputs', {})
    if not isinstance(contracts, dict):
        raise ValueError('Assessment inputs must be a mapping')
    if not isinstance(bindings, dict):
        raise ValueError('Assessment Input-to-Parameter bindings must be a mapping')
    if not isinstance(parameters, dict):
        raise ValueError('Benchmark Parameters must be a mapping')
    unknown = set(bindings) - set(contracts)
    if unknown:
        raise ValueError('binding references unknown Assessment Input: ' + ', '.join(sorted(unknown)))
    for name, declaration in contracts.items():
        if not isinstance(declaration, dict):
            raise ValueError('Input declaration is not an object: ' + str(name))
        if declaration.get('required') is True and name not in bindings:
            raise ValueError('required Input has no Rule binding: ' + name)
    for name, binding in bindings.items():
        parameter = _parameter_id(binding)
        if not isinstance(parameter, str) or not parameter:
            raise ValueError('Input binding must name exactly one Benchmark Parameter: ' + name)
        if parameter not in parameters or not isinstance(parameters[parameter], dict):
            raise ValueError('Input binding names a nonexistent Benchmark Parameter: ' + parameter)
        declaration = contracts[name]
        benchmark = parameters[parameter]
        if ('datatype' in benchmark and 'datatype' in declaration and
                benchmark['datatype'] != declaration['datatype']):
            raise ValueError('Input/Parameter datatype mismatch: ' + name)
        input_cardinality = declaration.get('cardinality')
        parameter_cardinality = _normalize_cardinality(benchmark.get('cardinality'))
        if (input_cardinality is not None and parameter_cardinality is not None and
                input_cardinality != parameter_cardinality):
            raise ValueError('Input/Parameter cardinality mismatch: ' + name)
    return contracts


def derive_choice(assessment, bindings, parameters):
    """Derive all organization-resolved native references for one choice."""
    contracts = _validate_bindings(assessment, bindings, parameters)
    locations = input_locations(assessment)
    grouped = {}
    for name, binding in bindings.items():
        parameter = _parameter_id(binding)
        if parameters[parameter].get('resolution') != 'organization':
            continue
        declaration = contracts[name]
        if type(declaration.get('required')) is not bool:
            raise ValueError('discovery derivation requires explicit Input required flag')
        uses = [{key: site[key] for key in ('kind', 'source_path')}
                for site in locations if site['input'] == name]
        # A declared/bound Input may be intentionally orphaned; only actual
        # native consumers belong in the discoverability map.
        if not uses:
            continue
        row = grouped.setdefault(parameter, {'input': parameter, 'required': False, 'uses': []})
        row['required'] = row['required'] or declaration['required']
        row['uses'].extend(uses)
    result = []
    for parameter, row in sorted(grouped.items()):
        row['uses'].sort(key=lambda use: (use['source_path'], use['kind']))
        result.append(row)
    return result


def validate_choice_map(assessment, bindings, parameters, explicit_rows=None):
    """Derive and, when supplied, exactly verify a packaged discovery map.

    The comparison is an exact multiset comparison.  Pointer targets are also
    resolved and checked against the Input name and its Parameter binding, so a
    structurally valid but dishonest map cannot pass.
    """
    expected = derive_choice(assessment, bindings, parameters)
    if explicit_rows is None:
        return expected
    if not isinstance(explicit_rows, list):
        raise ValueError('organizational discovery choice must be an array')
    locations = {site['source_path']: site for site in input_locations(assessment)}
    expected_keys = Counter((row['input'], row['required'], use['kind'], use['source_path'])
                            for row in expected for use in row['uses'])
    actual_keys = Counter()
    parameter_to_inputs = {}
    for name, binding in bindings.items():
        parameter_to_inputs.setdefault(_parameter_id(binding), set()).add(name)
    for row in explicit_rows:
        if not isinstance(row, dict) or set(row) != {'input', 'required', 'uses'}:
            raise ValueError('discovery entry has unsupported or missing fields')
        parameter = row['input']
        if parameter not in parameter_to_inputs:
            raise ValueError('discovery entry names an unbound Benchmark Parameter: ' + str(parameter))
        if type(row['required']) is not bool or not isinstance(row['uses'], list):
            raise ValueError('discovery entry has invalid required/uses values')
        for use in row['uses']:
            if (not isinstance(use, dict) or set(use) != {'kind', 'source_path'} or
                    use['kind'] not in {'value', 'presence'}):
                raise ValueError('discovery use must be exactly kind and source_path')
            path = use['source_path']
            if path not in locations:
                raise ValueError('discovery pointer is not an actual native Input reference: ' + str(path))
            target = _resolve_pointer(assessment, path)
            site = locations[path]
            input_names = parameter_to_inputs[parameter]
            if target not in input_names or site['kind'] != use['kind']:
                raise ValueError('discovery pointer Input/Parameter/kind mismatch: ' + path)
            actual_keys[(parameter, row['required'], use['kind'], path)] += 1
    if actual_keys != expected_keys:
        raise ValueError('discovery map does not exactly match derived native Input references')
    return expected


def validate_rule_discovery(assessment, choice, parameters, discovery=None, choice_id='automated'):
    """Validate one native 0.4 Rule choice and its optional/packaged map."""
    if not isinstance(choice, dict):
        raise ValueError('Assessment choice must be an object')
    bindings = choice.get('inputs', {})
    if discovery is None:
        explicit_rows = None
    else:
        if not isinstance(discovery, dict):
            raise ValueError('organizational discovery map must be an object')
        # An explicitly supplied map that omits this choice is an explicit
        # empty list, not an omitted authoring map; exact comparison rejects a
        # dishonest empty map for a choice with real consumers.
        explicit_rows = discovery.get(choice_id, [])
    return validate_choice_map(assessment, bindings, parameters, explicit_rows)
