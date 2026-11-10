"""Lower source XCCDF/CPE applicability into native SCAP-NG 0.4 documents.

This module intentionally does *not* invent executable CPE checks.  A CPE
identity without an OVAL fact closure is represented by a native
``not_evaluated`` Assessment and retained in the trace.  OVAL-backed facts use
the same AssessmentConverter as compliance Rules, so their unknown/error
expressions and Boolean structure are not collapsed into Not Applicable.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import re

CPE = 'http://cpe.mitre.org/language/2.0'
XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
OVAL = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'


def _slug(value: str, prefix: str, suffix: str) -> str:
    stem = re.sub(r'[^a-z0-9]+', '-', value.lower()).strip('-') or 'source'
    token = hashlib.sha256(value.encode()).hexdigest()[:8]
    budget = 64 - len(prefix) - len(suffix) - len(token) - 2
    return f'{prefix}{stem[:max(1, budget)].rstrip("-")}-{token}{suffix}'


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _bool(value, default=False):
    if value is None:
        return default
    return str(value).lower() == 'true'


def _logical_record(element):
    """Preserve a CPE logical-test tree, including nested tests."""
    facts, children = [], []
    for child in element:
        if child.tag == f'{{{CPE}}}check-fact-ref':
            facts.append({
                'id_ref': child.get('id-ref'), 'system': child.get('system'),
                'href': child.get('href'),
                'source_xml_sha256': _xml_digest(child),
            })
        elif child.tag == f'{{{CPE}}}logical-test':
            children.append(_logical_record(child))
    return {
        'operator': element.get('operator', 'AND'),
        'negate': element.get('negate', 'false'),
        'facts': facts,
        'children': children,
        'source_xml_sha256': _xml_digest(element),
    }


def _xml_digest(element):
    # Keep this helper independent of the runtime import for source extraction.
    def identity(node):
        return [node.tag, sorted(node.attrib.items()),
                node.text if not len(node) else None,
                [identity(child) for child in node]]
    return hashlib.sha256(_canonical(identity(element)).encode()).hexdigest()


def extract_platform_specifications(source):
    """Return source CPE platform specifications keyed by platform ID."""
    specifications = OrderedDict()
    for platform in source.root.iter(f'{{{CPE}}}platform'):
        identifier = platform.get('id')
        if not identifier:
            continue
        specifications[identifier] = {
            'id': identifier,
            'title': platform.findtext(f'{{{CPE}}}title', identifier),
            'logical_tests': [
                _logical_record(node)
                for node in platform.findall(f'{{{CPE}}}logical-test')
            ],
            'source_xml_sha256': _xml_digest(platform),
        }
    return specifications


def inherited_platform_refs(source, rule):
    """Return effective XCCDF platform idrefs in source ancestor order."""
    refs = []
    item = rule
    while item is not None:
        refs.extend(child.get('idref')
                    for child in item.findall(f'{{{XCCDF}}}platform'))
        if item is source.benchmark:
            break
        parents = getattr(source, 'parents', None)
        if parents is None:
            parents = {child: parent for parent in source.benchmark.iter() for child in parent}
        item = parents.get(item)
    return [ref for ref in refs if ref]


def _assessment_document(source, component, definition_id, assessment_id, title,
                         mappings, *, human_compact=True, native_recovery=False,
                         source_fact=None):
    """Use the production OVAL visitor for one shared fact Assessment."""
    from scap_ng_tools.converter.direct04 import load_runtime
    engine = load_runtime()
    converter = engine.AssessmentConverter(
        source, component, mappings, canonical_variable_functions=False,
        human_compact=human_compact, native_recovery=native_recovery)
    expression = converter.reference(definition_id, 'definition')
    definition = source.node(component, definition_id, 'definition')
    assessment = {
        'id': assessment_id, 'version': 1, 'assessment_title': title,
        'mode': 'automated', 'class': definition.get('class') or 'compliance',
        'specification': {'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.0'},
    }
    for section in ('shared_objects', 'variables'):
        if getattr(converter, section):
            assessment[section] = getattr(converter, section)
    if converter.inputs:
        assessment['inputs'] = converter.inputs
    assessment.update(tests=converter.tests, evaluate=expression)
    trace = {
        'source_component': component,
        'source_definition': definition_id,
        'source_definition_sha256': engine.digest(engine.xml_identity(definition)),
        'assessment': assessment_id,
        'conversion_status': 'APPLICABILITY_CONVERTED_UNVERIFIED',
        'dependencies': converter.used,
    }
    if source_fact:
        trace['source_fact_ref'] = source_fact
    return {'assessment': assessment}, trace


def _not_evaluated(assessment_id, title, reason):
    return {'assessment': {
        'id': assessment_id, 'version': 1, 'assessment_title': title,
        'mode': 'automated', 'class': 'compliance',
        'specification': {'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.0'},
        'tests': {},
        'evaluate': {'not_evaluated': {'reason': reason}},
    }}


def _make_composite(title, source_key, child_ids, operator, negate, shared, traces):
    """Build a native Boolean wrapper over shared Assessment references."""
    op = str(operator).upper()
    if op not in ('AND', 'OR', 'ONE', 'XOR'):
        raise ValueError(f'unsupported applicability logical-test operator: {operator}')
    if not child_ids:
        raise ValueError('empty applicability logical-test')
    children = [{'assessment': item} for item in child_ids]
    expression = children[0] if len(children) == 1 and op in ('AND', 'OR') else {
        op.lower(): children}
    if _bool(negate):
        expression = {'not': expression}
    # A positive single-fact condition can directly reference the fact
    # Assessment; no redundant wrapper is emitted.
    if len(child_ids) == 1 and not _bool(negate) and op in ('AND', 'OR'):
        return child_ids[0]
    semantic = {
        'source_identity': source_key, 'operator': op,
        'negate': _bool(negate), 'children': list(child_ids),
    }
    fingerprint = hashlib.sha256(_canonical(semantic).encode()).hexdigest()
    assessment_id = _slug(f'{source_key}-{fingerprint}', 'platform-', '-assessment')
    if assessment_id not in shared:
        dependencies = {
            f'condition-{i}': {
                'assessment': child, 'expected_version': 1,
                'purpose': 'applicability',
            } for i, child in enumerate(child_ids)
        }
        shared[assessment_id] = {'assessment': {
            'id': assessment_id, 'version': 1,
            'assessment_title': f'Applicability: {title}',
            'mode': 'automated', 'class': 'compliance',
            'specification': {'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.0'},
            'tests': {}, 'dependencies': dependencies, 'evaluate': expression,
        }}
        traces[assessment_id] = {
            'assessment': assessment_id, 'source_identity': source_key,
            'semantic': semantic,
            'semantic_fingerprint': fingerprint,
            'conversion_status': 'APPLICABILITY_COMPOSITION_UNVERIFIED',
        }
    return assessment_id


def build_applicability(source, documents, coverage, mappings, *, human_compact=True,
                        native_recovery=False, rule_ids=None):
    """Attach source applicability to one converted benchmark document set."""
    specifications = extract_platform_specifications(source)
    shared, shared_traces = OrderedDict(), OrderedDict()
    conditions, condition_cache = OrderedDict(), {}
    unsupported, attached_rule_ids = [], set()
    fact_cache = {}

    def unsupported_condition(identity, title, reason):
        key = ('unsupported', identity, reason)
        if key not in condition_cache:
            condition_id = _slug(identity, 'platform-', '-condition')
            assessment_id = _slug(f'{identity}-{reason}', 'platform-', '-assessment')
            if assessment_id not in shared:
                shared[assessment_id] = _not_evaluated(assessment_id, title, reason)
                shared_traces[assessment_id] = {
                    'assessment': assessment_id, 'source_identity': identity,
                    'conversion_status': 'APPLICABILITY_UNSUPPORTED_NOT_EVALUATED',
                    'reason': reason,
                }
            conditions[condition_id] = {'assessment': assessment_id}
            condition_cache[key] = condition_id
        return condition_cache[key]

    def fact_assessment(fact):
        href = fact.get('href') or ''
        component = source.catalog.get(href) or source.catalog.get(href.lstrip('#'))
        source_id = fact.get('id_ref')
        identity = (component, source_id)
        if identity in fact_cache:
            return fact_cache[identity]
        source_fact = {
            'id_ref': source_id, 'href': href, 'system': fact.get('system'),
            'source_xml_sha256': fact.get('source_xml_sha256'),
            'source_component': component,
        }
        if not component or not source_id:
            reason = 'unresolved source applicability OVAL fact reference'
            cid = unsupported_condition(f'{href}:{source_id}',
                                        'Unsupported source applicability fact', reason)
            unsupported.append({'kind': 'oval_fact', 'identity': source_fact, 'reason': reason})
            fact_cache[identity] = (cid, None)
            return fact_cache[identity]
        try:
            definition = source.node(component, source_id, 'definition')
            definition_hash = _xml_digest(definition)
            semantic_key = (component, source_id, definition_hash)
            if semantic_key in fact_cache:
                result = fact_cache[semantic_key]
                fact_cache[identity] = result
                return result
            # SQLEXT is deliberately not treated as a supported native fact
            # merely because a same-named capability happens to exist.
            if '#sql' in definition.tag.lower() or 'sqlext' in definition.tag.lower():
                raise ValueError('SQLEXT-dependent applicability closure is unsupported')
            assessment_id = _slug(f'{component}-{source_id}-{definition_hash}',
                                  'platform-', '-assessment')
            engine = __import__('scap_ng_tools.converter.direct04', fromlist=['load_runtime']).load_runtime()
            title = definition.findtext(f'{{{OVAL}}}metadata/{{{OVAL}}}title') or source_id
            document, trace = _assessment_document(
                source, component, source_id, assessment_id,
                'Applicability: ' + title, mappings,
                human_compact=human_compact, native_recovery=native_recovery,
                source_fact=source_fact)
            shared[assessment_id] = document
            trace['semantic_fingerprint'] = definition_hash
            shared_traces[assessment_id] = trace
            result = (assessment_id, semantic_key)
            fact_cache[semantic_key] = result
            fact_cache[identity] = result
            return result
        except ValueError as error:
            message = str(error)
            reason = ('SQLEXT-dependent applicability closure is unsupported: ' + message
                      if 'SQLEXT' in message else
                      'unsupported source applicability OVAL fact closure: ' + message)
            cid = unsupported_condition(f'{component}:{source_id}',
                                        'Unsupported source applicability fact', reason)
            unsupported.append({'kind': 'oval_fact', 'identity': source_fact, 'reason': reason})
            fact_cache[identity] = (cid, None)
            return fact_cache[identity]

    def lower_logical(spec_id, logical, title):
        child_ids = [fact_assessment(fact)[0] for fact in logical['facts']]
        child_ids.extend(lower_logical(spec_id, child, title)
                          for child in logical.get('children', []))
        return _make_composite(title, f'{spec_id}:{logical["source_xml_sha256"]}',
                               child_ids, logical['operator'], logical['negate'],
                               shared, shared_traces)

    def condition_for_ref(ref):
        if ref.startswith('#'):
            platform_id = ref[1:]
            spec = specifications.get(platform_id)
            if spec is None:
                reason = 'unresolved CPE platform specification: ' + platform_id
                unsupported.append({'kind': 'platform', 'identity': platform_id, 'reason': reason})
                return unsupported_condition(platform_id, 'Unsupported CPE platform specification', reason)
            semantic = _canonical(spec)
            if semantic in condition_cache:
                return condition_cache[semantic]
            try:
                logical_ids = [lower_logical(platform_id, logical, spec['title'])
                               for logical in spec['logical_tests']]
                if not logical_ids:
                    raise ValueError('CPE platform specification has no logical tests')
                condition = logical_ids[0] if len(logical_ids) == 1 else _make_composite(
                    spec['title'], platform_id, logical_ids, 'AND', 'false',
                    shared, shared_traces)
            except ValueError as error:
                reason = f'unsupported CPE platform specification {platform_id}: {error}'
                unsupported.append({'kind': 'platform', 'identity': platform_id, 'reason': reason})
                condition = unsupported_condition(platform_id, spec['title'], reason)
            condition_id = _slug(platform_id, 'platform-', '-condition')
            conditions[condition_id] = {'assessment': condition}
            condition_cache[semantic] = condition_id
            return condition_id
        reason = 'CPE identity has no established executable SCAP-NG applicability mapping: ' + ref
        unsupported.append({'kind': 'cpe_identity', 'identity': ref, 'reason': reason})
        return unsupported_condition(ref, 'Unsupported CPE identity', reason)

    def refs_conditions(refs):
        result = []
        for ref in refs:
            cid = condition_for_ref(ref)
            if cid not in result:
                result.append(cid)
        return result

    for row in coverage.get('rules', []):
        if row.get('status') not in ('converted', 'manual_only'):
            continue
        rule_id = row.get('source_rule')
        if rule_ids is not None and rule_id not in rule_ids:
            continue
        rule = source.rules.get(rule_id)
        if rule is None:
            continue
        refs = inherited_platform_refs(source, rule)
        condition_ids = refs_conditions(refs)
        rule_path = next((path for path in row.get('artifacts', [])
                          if '/rules/' in path and path in documents), None)
        if rule_path:
            documents[rule_path]['rule']['applicability'] = condition_ids
            row['applicability'] = {
                'conditions': condition_ids, 'source_platform_refs': refs,
                'unsupported': [item for item in unsupported
                                if item.get('identity') in refs or
                                (isinstance(item.get('identity'), dict) and
                                 item['identity'].get('id_ref') in refs)],
            }
            attached_rule_ids.add(rule_id)

    benchmark_refs = [child.get('idref') for child in
                      source.benchmark.findall(f'{{{XCCDF}}}platform')]
    benchmark_conditions = refs_conditions([ref for ref in benchmark_refs if ref])
    benchmark_path = 'authoring/direct-slice/benchmark.json'
    if benchmark_path in documents:
        wrapper = documents[benchmark_path]['benchmark']
        wrapper['applicability_catalog'] = 'direct-slice-applicability'
        wrapper['platform']['title'] = (
            'Source platform applicability; unresolved identities remain not evaluated')
        wrapper['platform']['applicability'] = {
            'operator': 'AND', 'conditions': benchmark_conditions,
        }

    catalog_path = 'authoring/direct-slice/applicability.json'
    documents[catalog_path] = {'applicability': {
        'id': 'direct-slice-applicability', 'conditions': dict(conditions)}}
    for assessment_id, document in shared.items():
        documents[f'authoring/direct-slice/assessments/{assessment_id}.json'] = document

    # Deduplicate diagnostics while retaining complete source identities.
    unsupported = list({(_canonical(item)): item for item in unsupported}.values())

    # Verify the builder's core graph invariant before publication: every
    # catalog condition resolves to an emitted Assessment document.
    emitted_ids = {doc['assessment']['id'] for path, doc in documents.items()
                   if '/assessments/' in path and 'assessment' in doc}
    unresolved = sorted({value['assessment'] for value in conditions.values()} - emitted_ids)
    if unresolved:
        raise ValueError('applicability catalog has unresolved Assessments: ' + ', '.join(unresolved))
    condition_ids = set(conditions)
    for path, document in documents.items():
        if '/rules/' in path and 'rule' in document:
            missing = sorted(set(document['rule'].get('applicability', [])) - condition_ids)
            if missing:
                raise ValueError(f'Rule {path} has unresolved applicability conditions: {missing}')
    benchmark_document = documents.get('authoring/direct-slice/benchmark.json')
    if benchmark_document:
        missing = sorted(set(benchmark_document['benchmark']['platform'].get('applicability', {}).get('conditions', [])) - condition_ids)
        if missing:
            raise ValueError(f'Benchmark has unresolved applicability conditions: {missing}')

    trace = {
        'format': 'scap-ng-applicability/1', 'catalog': catalog_path,
        'catalog_id': 'direct-slice-applicability',
        'conditions': [{'id': key, **value} for key, value in conditions.items()],
        'shared_assessments': list(shared_traces.values()),
        'unsupported': unsupported,
        'source_platform_specifications': list(specifications.values()),
        'source_rule_count_attached': len(attached_rule_ids),
        'source_rule_count_with_conditions': sum(
            bool(row.get('applicability', {}).get('conditions'))
            for row in coverage.get('rules', [])),
        'source_platform_ref_count_attached': sum(
            len(row.get('applicability', {}).get('source_platform_refs', []))
            for row in coverage.get('rules', [])),
        'catalog_condition_count': len(conditions),
        'shared_assessment_count': len(shared),
        'source_identity_preserved': True,
        'independent_semantic_proof': False,
        'scanner_runtime': False,
    }
    coverage['applicability'] = trace
    return documents, trace
