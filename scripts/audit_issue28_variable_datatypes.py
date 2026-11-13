#!/usr/bin/env python3
"""Build the exhaustive Issue #28 OVAL Variable datatype audit.

This is a source-backed, read-only audit.  It deliberately does not repair
source declarations or infer an implicit cast.  The report separates the
value datatype from collection cardinality and records the source Rule/check
provenance needed to review every inference.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import argparse
import hashlib
import gzip
import json
from pathlib import Path
import re
import zipfile
import xml.etree.ElementTree as ET

OVAL = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
DS = 'http://scap.nist.gov/schema/scap/source/1.2'
XLINK = 'http://www.w3.org/1999/xlink'
O = '{' + OVAL + '}'
X = '{' + XCCDF + '}'
D = '{' + DS + '}'
FUNCTIONS = {
    'arithmetic', 'begin', 'concat', 'end', 'escape_regex', 'split',
    'substring', 'time_difference', 'regex_capture', 'unique', 'count',
    'glob_to_regex', 'merge',
}
SIMPLE_TYPES = {'string', 'int', 'integer', 'float', 'boolean', 'binary',
                'version', 'ipv4', 'ipv6', 'rpm_evr', 'debian_evr',
                'fileset_revision', 'ios_version', 'evr_string'}
TYPE_ALIASES = {'int': 'integer'}


def lname(node):
    return node.tag.rsplit('}', 1)[-1]


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha_file(path):
    return sha_bytes(path.read_bytes())


def norm_type(value):
    return TYPE_ALIASES.get(value or 'string', value or 'string')


def text_value(node):
    return node.text or ''


def lexical_valid(value, datatype):
    """Small source-audit lexical check; unknown OVAL datatypes stay unknown."""
    value = value.strip()
    datatype = norm_type(datatype)
    if datatype == 'string':
        return True
    if datatype == 'integer':
        return re.fullmatch(r'[+-]?[0-9]+', value) is not None
    if datatype == 'float':
        return re.fullmatch(
            r'[+-]?(?:[0-9]+(?:\.[0-9]+)?|[0-9]+\.)(?:[eE][+-]?[0-9]+)?|'
            r'NaN|INF|-INF', value) is not None
    if datatype == 'boolean':
        return value in {'true', 'false', '1', '0'}
    if datatype == 'binary':
        return re.fullmatch(r'[0-9a-fA-F]*', value) is not None
    # OVAL version/E-V-R/IP lexical details are intentionally not guessed.
    return None


def flatten_shape(node, functions, components, path=''):
    op = lname(node)
    current = path or '/'
    if op in FUNCTIONS:
        functions.append({'name': op, 'path': current,
                          'attributes': dict(sorted(node.attrib.items()))})
    if op in {'literal_component', 'variable_component', 'object_component'}:
        components.append({'kind': op, 'path': current,
                           'attributes': dict(sorted(node.attrib.items())),
                           'text': text_value(node)})
    for index, child in enumerate(node):
        flatten_shape(child, functions, components, f'{current}{op}[{index}]/')


def component_catalog(root):
    components = {}
    for component in root.findall(D + 'component'):
        if component.get('id') and len(component) == 1:
            components[component.get('id')] = component[0]
    stream = root.find(D + 'data-stream')
    refs = {}
    if stream is not None:
        for ref in stream.iter(D + 'component-ref'):
            rid = ref.get('id')
            href = ref.get('{' + XLINK + '}href', '')
            if rid:
                refs[rid] = href[1:] if href.startswith('#') else href
    # A data-stream uses component-ref IDs, while XCCDF hrefs use filenames.
    aliases = {}
    if stream is not None:
        for ref in stream.iter(D + 'component-ref'):
            rid = ref.get('id', '')
            href = ref.get('{' + XLINK + '}href', '')
            component = refs.get(rid)
            if component:
                if href.startswith('#'):
                    aliases[href] = component
                if '_cref_' in rid:
                    aliases[rid.split('_cref_', 1)[1]] = component
    return components, refs, aliases, stream


def source_model(root):
    components, refs, aliases, stream = component_catalog(root)
    indexes = {cid: {n.get('id'): n for n in value.iter() if n.get('id')}
               for cid, value in components.items()}
    oval_components = {cid: value for cid, value in components.items()
                       if value.tag == O + 'oval_definitions'}
    variables = {}
    for cid, value in oval_components.items():
        for node in value.iter():
            if lname(node) in {'local_variable', 'constant_variable', 'external_variable'}:
                variables[node.get('id')] = (cid, node)

    rules = {}
    benchmark = None
    if stream is not None:
        checklist = stream.find(D + 'checklists/' + D + 'component-ref')
        benchmark = components.get(refs.get(checklist.get('id'))) if checklist is not None else None
    if benchmark is not None:
        for rule in benchmark.iter(X + 'Rule'):
            if rule.get('id'):
                checks = []
                for check in rule.findall(X + 'check'):
                    system = check.get('system', '')
                    checks.append({
                        'system': system,
                        'kind': ('oval' if 'oval.mitre.org' in system else
                                 'ocil' if 'ocil' in system else 'other'),
                        'content_refs': [
                            {'href': ref.get('href', ''), 'name': ref.get('name', '')}
                            for ref in check.findall(X + 'check-content-ref')
                        ],
                    })
                rules[rule.get('id')] = {
                    'id': rule.get('id'), 'title': next(
                        ((n.text or '').strip() for n in rule.findall(X + 'title')), ''),
                    'checks': checks,
                }

    def closure(component, identifier, rule_id, visited, found):
        key = (component, identifier)
        if not identifier or key in visited:
            return
        visited.add(key)
        node = indexes.get(component, {}).get(identifier)
        if node is None:
            return
        if node.get('id') in variables:
            found.add(node.get('id'))
        for descendant in node.iter():
            if descendant.get('id') in variables:
                found.add(descendant.get('id'))
            for attribute in ('definition_ref', 'test_ref', 'object_ref', 'state_ref', 'var_ref'):
                target = descendant.get(attribute)
                if target:
                    closure(component, target, rule_id, visited, found)
            # Some family-specific var_ref forms use text content.
            if lname(descendant) == 'var_ref' and text_value(descendant).strip():
                closure(component, text_value(descendant).strip(), rule_id, visited, found)
            if lname(descendant) in {'object_reference', 'filter'} and text_value(descendant).strip():
                closure(component, text_value(descendant).strip(), rule_id, visited, found)

    variable_rules = defaultdict(set)
    for rule_id, rule in rules.items():
        visited = set(); found = set()
        for check in rule['checks']:
            for ref in check['content_refs']:
                component = aliases.get(ref['href'])
                if component and ref['name']:
                    closure(component, ref['name'], rule_id, visited, found)
        for var_id in found:
            variable_rules[var_id].add(rule_id)
    return {
        'components': components, 'indexes': indexes, 'variables': variables,
        'rules': rules, 'variable_rules': variable_rules,
    }


def function_result(name, argument_domains, argument_cards):
    unknown = {'unknown'}
    if name == 'arithmetic':
        if any('unknown' in d for d in argument_domains):
            domains = {'integer', 'float'}
        elif all(d <= {'integer'} for d in argument_domains):
            domains = {'integer'}
        elif all(d <= {'integer', 'float'} for d in argument_domains):
            domains = {'float'}
        else:
            domains = {'error'}
        card = 'collection' if any(c in {'collection', 'unknown'} for c in argument_cards) else 'single'
    elif name in {'count', 'time_difference'}:
        domains = {'integer'}
        card = 'single' if name == 'count' else (
            'collection' if any(c in {'collection', 'unknown'} for c in argument_cards) else 'single')
    elif name in {'split'}:
        domains, card = {'string'}, 'collection'
    elif name in {'merge'}:
        domains, card = {'string'}, 'single'
    elif name in {'concat', 'begin', 'end', 'escape_regex', 'glob_to_regex',
                  'regex_capture', 'substring'}:
        domains = {'string'}
        card = 'collection' if any(c in {'collection', 'unknown'} for c in argument_cards) else 'single'
    elif name == 'unique':
        domains = {'string'}
        card = 'collection' if any(c in {'collection', 'unknown'} for c in argument_cards) else 'single'
    else:
        domains, card = unknown, 'unknown'
    return domains, card


def audit_archive(path, source_revision, schema_xsd_hash, schema_root):
    raw = path.read_bytes()
    with zipfile.ZipFile(path) as package:
        members = [name for name in package.namelist() if name.endswith('.xml')]
        if len(members) != 1:
            raise ValueError(f'{path.name}: expected one XML member, got {members}')
        root = ET.fromstring(package.read(members[0]))
    model = source_model(root)
    variables = model['variables']
    declared_by_id = {vid: norm_type(node.get('datatype')) for vid, (_, node) in variables.items()}
    memo = {}; active = set()

    def infer_component(node):
        kind = lname(node)
        if kind == 'literal_component':
            return {norm_type(node.get('datatype', 'string'))}, 'single', 'literal'
        if kind == 'variable_component':
            vid = node.get('var_ref')
            if vid in memo:
                return memo[vid]['domains'], memo[vid]['cardinality'], 'variable'
            # A variable reference is typed by its declaration; evaluation of a
            # cycle/unresolved ref is separately recorded as an error condition.
            return ({declared_by_id[vid]} if vid in declared_by_id else {'unknown'},
                    'same_as_source', 'variable')
        if kind == 'object_component':
            return {'unknown'}, 'collection', 'object'
        return infer_expression(node)

    def infer_expression(node):
        name = lname(node)
        if name in FUNCTIONS:
            domains = []; cards = []
            for child in node:
                d, c, _ = infer_component(child)
                domains.append(d); cards.append(c)
            result, card = function_result(name, domains, cards)
            return result, card, name
        return infer_component(node)

    records = []
    totals = Counter(); mismatches = []
    declared_tokens = Counter(); literal_tokens = Counter(); object_fields = Counter()
    function_occurrences = Counter(); function_rules = defaultdict(set)
    rule_function_vars = defaultdict(set)
    for vid, (component_id, var) in sorted(variables.items()):
        kind = lname(var); child = next(iter(var), None)
        functions = []; components = []
        if child is not None:
            flatten_shape(child, functions, components)
        for component in components:
            if component['kind'] == 'literal_component':
                literal_tokens[component['attributes'].get('datatype', 'string')] += 1
            elif component['kind'] == 'object_component':
                object_fields[component['attributes'].get('item_field', '')] += 1
        for f in functions:
            function_occurrences[f['name']] += 1
            for rid in model['variable_rules'].get(vid, ()):
                function_rules[f['name']].add(rid)
                rule_function_vars[rid].add(vid)
        declared = norm_type(var.get('datatype'))
        declared_tokens[var.get('datatype', 'string')] += 1
        if kind == 'constant_variable':
            values = [text_value(n) for n in var if lname(n) == 'value']
            validity = [lexical_valid(v, declared) for v in values]
            domains = {declared}; cardinality = 'collection' if len(values) > 1 else 'single'
            inference = 'constant_declared_datatype'
            if any(v is False for v in validity):
                inference = 'constant_invalid_lexical_value'
        elif kind == 'external_variable':
            domains = {declared}; cardinality = 'unknown'
            values = [text_value(n) for n in var if lname(n) in {'possible_value', 'possible_restriction'}]
            validity = []
            inference = 'external_declared_datatype_with_constraints' if values else 'external_declared_datatype'
        elif child is None:
            domains, cardinality, _ = {'unknown'}, 'unknown', 'missing'
            validity = []; inference = 'missing_expression'
        else:
            # Variable components in this expression use recursive declarations.
            def infer_component_recursive(node):
                if lname(node) == 'variable_component':
                    # OVAL components are typed by the referenced Variable's
                    # declaration at the function boundary.  The referenced
                    # Variable's own expression is audited independently;
                    # using its derived expression here would incorrectly
                    # suppress OVAL's component-cast semantics.
                    ref = node.get('var_ref')
                    return ({declared_by_id[ref]} if ref in declared_by_id else {'unknown'}), \
                           ('same_as_source' if ref in declared_by_id else 'unknown'), 'variable'
                if lname(node) == 'object_component':
                    return {'unknown'}, 'collection', 'object'
                if lname(node) == 'literal_component':
                    return {norm_type(node.get('datatype', 'string'))}, 'single', 'literal'
                return infer_expression(node)
            infer_component_saved = infer_component
            infer_component = infer_component_recursive
            try:
                domains, cardinality, _ = infer_expression(child)
            finally:
                infer_component = infer_component_saved
            validity = []
            inference = 'function_result' if functions else 'component_result'
            memo[vid] = {'domains': domains, 'cardinality': cardinality}
        compatible = bool(domains & {declared}) if 'unknown' not in domains else None
        if compatible is False:
            inference = 'explicit_result_datatype_mismatch'
            mismatch = {
                'variable_id': vid, 'declared_datatype': declared,
                'root_expression': lname(child) if child is not None else 'missing',
                'function': functions[0]['name'] if functions else None,
                'inferred_domains': sorted(domains),
                'cardinality': cardinality,
                'rules': sorted(model['variable_rules'].get(vid, ())),
            }
            mismatches.append(mismatch)
        elif compatible is None:
            inference = inference + '_source_dependent'
        elif inference == 'function_result' and functions:
            inference = 'function_result_compatible'
        totals[inference] += 1
        record = {
            'variable_id': vid, 'component_id': component_id, 'kind': kind,
            'declared_datatype': declared, 'source_datatype_token': var.get('datatype'),
            'version': var.get('version'), 'comment': var.get('comment', ''),
            'root_expression': lname(child) if child is not None else 'missing',
            'functions': functions, 'components': components,
            'inferred_value_datatypes': sorted(domains), 'inferred_cardinality': cardinality,
            'compatibility': ('compatible' if compatible is True else
                              'mismatch' if compatible is False else 'indeterminate'),
            'inference_class': inference,
            'rules': sorted(model['variable_rules'].get(vid, ())),
            # Keep the exact original declaration for every function-bearing
            # or mismatching Variable; declarations without an expression are
            # represented by their typed metadata below.
            'source_xml': (ET.tostring(var, encoding='unicode')
                           if functions or compatible is False else None),
        }
        if kind == 'constant_variable':
            record['constant_values'] = values
            record['constant_lexical_validity'] = validity
        if kind == 'external_variable':
            record['external_constraints'] = values
        records.append(record)

    # Dependency audit is independent of result-domain inference.  A
    # reference is resolved by source ID here; cycles are reported rather than
    # treated as a datatype or an implicit cast.
    variable_ids = set(variables)
    dependency_edges = []
    unresolved_references = []
    graph = defaultdict(list)
    for record in records:
        for component in record['components']:
            if component['kind'] != 'variable_component':
                continue
            ref = component['attributes'].get('var_ref')
            dependency_edges.append({'from': record['variable_id'], 'to': ref})
            if ref not in variable_ids:
                unresolved_references.append({'from': record['variable_id'], 'to': ref})
            else:
                graph[record['variable_id']].append(ref)
    cycles = []
    visited = set(); active_path = []
    def visit(node):
        if node in active_path:
            cycles.append(active_path[active_path.index(node):] + [node])
            return
        if node in visited:
            return
        visited.add(node); active_path.append(node)
        for target in graph.get(node, []):
            visit(target)
        active_path.pop()
    for node in list(graph):
        visit(node)
    rule_rows = []
    for rid, rule in sorted(model['rules'].items()):
        kinds = Counter(c['kind'] for c in rule['checks'])
        rule_rows.append({
            'id': rid, 'title': rule['title'], 'check_kinds': dict(sorted(kinds.items())),
            'variable_ids': sorted(rule_function_vars.get(rid, set())),
            'functions': sorted({f for f, rids in function_rules.items() if rid in rids}),
        })
    check_counts = Counter()
    for rule in rule_rows:
        kinds = set(rule['check_kinds'])
        if 'oval' in kinds: check_counts['rules_with_oval'] += 1
        if 'ocil' in kinds: check_counts['rules_with_ocil'] += 1
        if kinds >= {'oval', 'ocil'}: check_counts['rules_with_both'] += 1
        if 'ocil' in kinds and 'oval' not in kinds: check_counts['ocil_only'] += 1
        if 'oval' in kinds and 'ocil' not in kinds: check_counts['oval_only'] += 1
        if not kinds: check_counts['rules_without_check'] += 1
    return {
        'filename': path.name, 'source_sha256': sha_bytes(raw),
        'source_xml_member': members[0], 'source_rules': len(model['rules']),
        'check_selection': dict(sorted(check_counts.items())),
        'variable_counts': dict(Counter(r['kind'] for r in records)),
        'declared_datatype_tokens': dict(sorted(declared_tokens.items())),
        'literal_datatype_tokens': dict(sorted(literal_tokens.items())),
        'object_component_fields': dict(sorted(object_fields.items())),
        'function_occurrences': dict(sorted(function_occurrences.items())),
        'mismatch_count': len(mismatches), 'mismatches': mismatches,
        'inference_classes': dict(sorted(totals.items())),
        'dependency_audit': {'reference_edges': len(dependency_edges),
                             'unresolved_references': unresolved_references,
                             'cycle_count': len(cycles), 'cycles': cycles},
        'rules': rule_rows, 'variables': records,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--oval-xsd', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sources = sorted(args.source_dir.glob('*.zip'))
    if len(sources) != 65:
        raise SystemExit(f'expected 65 source ZIPs, found {len(sources)}')
    xsd_hash = sha_file(args.oval_xsd)
    reports = [audit_archive(p, 'niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5', xsd_hash, args.schema_root) for p in sources]
    functions = Counter(); variable_counts = Counter(); classes = Counter(); mismatches = []
    declared_tokens = Counter(); literal_tokens = Counter(); object_fields = Counter()
    source_rules = 0; selection = Counter(); dependency_edges = 0
    unresolved = []; cycles = 0
    for report in reports:
        source_rules += report['source_rules']; functions.update(report['function_occurrences'])
        variable_counts.update(report['variable_counts']); classes.update(report['inference_classes']); selection.update(report['check_selection'])
        declared_tokens.update(report['declared_datatype_tokens']); literal_tokens.update(report['literal_datatype_tokens']); object_fields.update(report['object_component_fields'])
        dependency_edges += report['dependency_audit']['reference_edges']
        unresolved.extend({'benchmark': report['filename'], **item} for item in report['dependency_audit']['unresolved_references'])
        cycles += report['dependency_audit']['cycle_count']
        for mismatch in report['mismatches']:
            mismatches.append({'benchmark': report['filename'], 'source_sha256': report['source_sha256'], **mismatch})
    schema_dir = args.schema_root / 'schema'
    schema_json = json.loads((schema_dir / 'variable-expression.schema.json').read_text())
    native_functions = sorted(schema_json['$defs']['function_expression']['properties']['function']['properties']['name']['enum'])
    pack_path = Path(__file__).parents[1] / 'src/scap_ng_tools/converter/_v04_semantic/contracts-0.4.0.json'
    pack = json.loads(pack_path.read_text())
    pack_field_types = Counter()
    for capability in pack.get('capabilities', {}).values():
        for types in capability.get('fields', {}).values():
            for datatype in types:
                pack_field_types[datatype] += 1
    result = {
        'format': 'scap-ng-tools/issue28-variable-datatype-inventory/2',
        'scope': {'benchmarks': len(reports), 'rules': source_rules, 'owner_rule_baseline': 8892,
                  'source_revision': 'niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5'},
        'oval_contract': {
            'schema': 'OVAL 5.12.3 oval-definitions-schema.xsd', 'xsd_sha256': xsd_hash,
            'variable_datatype': 'Required; all returned values must comply or evaluation reports an error.',
            'record_on_variable': 'Prohibited.',
            'component_cast': 'FunctionGroup permits attempted casts when a component has the wrong type.',
            'function_result_domains': {
                'arithmetic': ['integer', 'float'], 'split': ['string'], 'substring': ['string'],
                'count': ['integer'], 'concat': ['string'], 'regex_capture': ['string'],
                'unique': ['string'], 'merge': ['string'], 'begin': ['string'], 'end': ['string'],
                'escape_regex': ['string'], 'glob_to_regex': ['string'], 'time_difference': ['integer'],
            },
            'cardinality_contract': 'Function evaluation preserves OVAL collection semantics; arithmetic and other multi-input functions use Cartesian products, count flattens values, split preserves empty tokens and order.',
            'source_paths': {'variable_type_lines': '526-550', 'function_group_lines': '708-727',
                             'arithmetic_lines': '729-749', 'split_lines': '843-862',
                             'substring_lines': '864-885', 'count_lines': '953-960',
                             'operation_cast_lines': '1368-1382'},
        },
        'inventory': {
            'variable_counts': dict(sorted(variable_counts.items())),
            'declared_datatype_tokens': dict(sorted(declared_tokens.items())),
            'literal_datatype_tokens': dict(sorted(literal_tokens.items())),
            'object_component_fields': dict(sorted(object_fields.items())),
            'semantic_pack_field_datatypes': dict(sorted(pack_field_types.items())),
            'function_occurrences': dict(sorted(functions.items())),
            'inference_classes': dict(sorted(classes.items())),
            'check_selection': dict(sorted(selection.items())),
            'dependency_audit': {'reference_edges': dependency_edges,
                                 'unresolved_references': unresolved,
                                 'cycle_count': cycles},
            'mismatch_count': len(mismatches), 'mismatches': mismatches,
        },
        'native_contract_snapshot': {
            'schema_root': 'vanderpol/scap-ng@919732d4c570b521edf82196a7694dfd8c27fe50',
            'schema_family_digest': '910beeebfb90a63c773615907289a0e4b93095ee41cd1ad41b33652363900c74',
            'native_schema_functions': native_functions,
            'compiler': 'No separate SCAP-NG compiler executable is present in checked-out repositories.',
            'runtime': 'No SCAP-NG runtime executable is present; source/evaluator probes are separate evidence.',
            'converter': 'scap-ng-tools native Variable validator performs static domain checks and does not add implicit casts.',
            'editor': 'VS Code editor was not modified; canonical schema-derived metadata requires repin.',
        },
        'qualification': {
            'declarations_overridden': False, 'implicit_casts_added': False,
            'mismatch_rules_promoted': False,
            'independent_runtime_proof': 'Not claimed; no native runtime executable is available in these repositories.',
        },
        'benchmarks': reports,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    if args.output.suffix == '.gz':
        with gzip.open(args.output, 'wb', compresslevel=9) as stream:
            stream.write(payload)
    else:
        args.output.write_bytes(payload)
    print(json.dumps({'benchmarks': len(reports), 'rules': source_rules,
                      'variables': sum(variable_counts.values()),
                      'functions': dict(sorted(functions.items())),
                      'mismatches': len(mismatches)}, sort_keys=True))


if __name__ == '__main__':
    main()
