"""Lower source XCCDF/CPE applicability into native SCAP-NG 0.4 documents.

This module intentionally does *not* invent executable CPE checks.  A CPE
identity without an OVAL fact closure is retained as a provenance-bearing
catalog condition with no Assessment; the RI reports that hold as an
applicability error rather than treating it as false. OVAL-backed facts use
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

# CPE is package input. Bound recursion and output fan-out before lowering so
# malformed or adversarial content cannot consume unbounded converter memory.
MAX_CPE_LOGICAL_DEPTH = 64
MAX_CPE_LOGICAL_NODES = 4096


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


def _cpe_binding(value):
    """Identify a source CPE naming binding without parsing or matching it.

    The converter preserves the exact source spelling. Syntax validation and
    attribute-level matching remain outside this metadata-only lowering.
    """
    if value.startswith('cpe:/'):
        return 'cpe_uri_2_2'
    if value.startswith('cpe:2.3:'):
        return 'cpe_formatted_string_2_3'
    return None


def _logical_record(element, *, depth=0, budget=None):
    """Preserve a CPE logical-test tree and source operand order.

    ``facts`` and ``children`` remain in the trace for compatibility with
    existing receipts, while ``operands`` is the source-order lowering input.
    """
    if depth > MAX_CPE_LOGICAL_DEPTH:
        raise ValueError(f'CPE logical-test nesting exceeds {MAX_CPE_LOGICAL_DEPTH} levels')
    budget = budget if budget is not None else [0]
    budget[0] += 1
    if budget[0] > MAX_CPE_LOGICAL_NODES:
        raise ValueError(f'CPE logical-test contains more than {MAX_CPE_LOGICAL_NODES} nodes')
    facts, children, operands = [], [], []
    for child in element:
        if child.tag == f'{{{CPE}}}check-fact-ref':
            budget[0] += 1
            if budget[0] > MAX_CPE_LOGICAL_NODES:
                raise ValueError(f'CPE logical-test contains more than {MAX_CPE_LOGICAL_NODES} nodes')
            fact = {
                'id_ref': child.get('id-ref'), 'system': child.get('system'),
                'href': child.get('href'), 'source_xml_sha256': _xml_digest(child),
            }
            facts.append(fact)
            operands.append(fact)
        elif child.tag == f'{{{CPE}}}logical-test':
            nested = _logical_record(child, depth=depth + 1, budget=budget)
            children.append(nested)
            operands.append(nested)
    return {
        'operator': element.get('operator', 'AND'), 'negate': element.get('negate', 'false'),
        'facts': facts, 'children': children, 'operands': operands,
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
        record = {
            'id': identifier,
            'title': platform.findtext(f'{{{CPE}}}title', identifier),
            'logical_tests': [
                _logical_record(node)
                for node in platform.findall(f'{{{CPE}}}logical-test')
            ],
            'source_xml_sha256': _xml_digest(platform),
        }
        if identifier in specifications:
            prior = specifications[identifier]
            if _canonical(prior) != _canonical(record):
                raise ValueError(f'conflicting duplicate CPE platform ID: {identifier}')
            raise ValueError(f'duplicate CPE platform ID: {identifier}')
        specifications[identifier] = record
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
        'specification': {'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.1'},
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


def build_applicability(source, documents, coverage, mappings, *, human_compact=True,
                        native_recovery=False, rule_ids=None):
    """Attach source applicability to one converted benchmark document set."""
    from ._v04_runtime.v04_direct_scap_source import source_native_identifier
    source_benchmark_id = source.benchmark.get('id') or 'benchmark'
    applicability_native_id = source_native_identifier(source_benchmark_id, 'applicability-')
    platform_native_id = source_native_identifier(source_benchmark_id + '\x00platform', 'platform-')
    specifications = extract_platform_specifications(source)
    shared, shared_traces = OrderedDict(), OrderedDict()
    conditions, condition_cache = OrderedDict(), {}

    # The historical key projection used only a normalized idref stem.  Two
    # distinct XCCDF references (for example ``#Linux`` and ``#linux``) can
    # therefore alias one native condition while retaining different CPE
    # meaning.  Keep the established readable key for the common case, but
    # reserve a deterministic digest suffix for a normalization collision.
    # This is deliberately based on the source reference, not generated
    # Assessment content, so provenance and catalog identity remain stable.
    platform_nodes = [node for node in source.benchmark.iter()
                      if node.tag == f'{{{XCCDF}}}platform' and node.get('idref')]
    platform_key_groups = {}
    for node in platform_nodes:
        if hasattr(source, 'applicability_condition_id'):
            base = source.applicability_condition_id(node)
        else:
            base = _slug(node.get('idref'), 'platform-', '-condition')
        platform_key_groups.setdefault(base, set()).add(node.get('idref'))
    unsupported, attached_rule_ids = [], set()
    fact_cache = {}
    fact_condition_cache = {}
    platform_expressions = OrderedDict()
    group_level_records = {}

    def add_shared(assessment_id, document, trace):
        existing = shared.get(assessment_id)
        if existing is not None and _canonical(existing) != _canonical(document):
            raise ValueError(f'conflicting generated Assessment identity: {assessment_id}')
        if existing is None:
            shared[assessment_id] = document
        if trace is not None:
            prior_trace = shared_traces.get(assessment_id)
            if prior_trace is not None and prior_trace.get('semantic_fingerprint') != trace.get('semantic_fingerprint'):
                raise ValueError(f'conflicting generated Assessment trace identity: {assessment_id}')
            shared_traces.setdefault(assessment_id, trace)

    def add_condition(condition_id, value):
        existing = conditions.get(condition_id)
        if existing is not None and _canonical(existing) != _canonical(value):
            raise ValueError(f'conflicting generated applicability condition identity: {condition_id}')
        conditions[condition_id] = value

    def condition_key(ref):
        platform = next((node for node in platform_nodes
                         if node.get('idref') == ref), None)
        if platform is not None and hasattr(source, 'applicability_condition_id'):
            base = source.applicability_condition_id(platform)
        else:
            base = _slug(ref, 'platform-', '-condition')
        if len(platform_key_groups.get(base, ())) <= 1:
            return base
        # Keep the suffix within the native identifier budget while making
        # every colliding source idref distinct.
        stem = base[:-len('-condition')] if base.endswith('-condition') else base
        suffix = hashlib.sha256(ref.encode('utf-8')).hexdigest()[:12]
        return f'{stem[:64 - len(suffix) - 2].rstrip("-")}-{suffix}-condition'

    def unsupported_condition(identity, title, reason, condition_id=None):
        # A source identity without a qualified executable mapping is an
        # explicit catalog hold, not a synthetic Assessment.  The RI must
        # report applicability ERROR for this condition; it must never turn
        # the hold into FALSE/not_applicable.
        key = ('unsupported', identity, reason)
        if key not in condition_cache:
            condition_cache[key] = condition_id or _slug(identity, 'platform-', '-condition')
        return condition_cache[key]

    def source_provenance(ref, spec=None):
        """Return source identity for one XCCDF platform reference."""
        platform = next((node for node in source.benchmark.iter()
                         if node.tag == f'{{{XCCDF}}}platform'
                         and node.get('idref') == ref), None)
        if spec is not None:
            value = {
                'kind': 'cpe_platform', 'id': ref.lstrip('#'),
                'sha256': spec['source_xml_sha256'], 'idref': ref,
            }
            expression = (spec['logical_tests'][0]
                          if len(spec['logical_tests']) == 1 else {
                              'operator': 'AND', 'negate': 'false',
                              'facts': [], 'children': spec['logical_tests'],
                          })
            value['cpe_expression'] = expression
            value['expression_sha256'] = hashlib.sha256(
                _canonical(expression).encode()).hexdigest()
            return value
        if platform is not None:
            kind = 'cpe_platform' if ref.startswith('cpe:') else 'xccdf_platform'
            return {'kind': kind, 'id': ref.lstrip('#'),
                    'sha256': _xml_digest(platform), 'idref': ref}
        kind = 'cpe_platform' if ref.startswith('cpe:') else 'xccdf_platform'
        return {'kind': kind, 'id': ref.lstrip('#') or ref,
                'sha256': hashlib.sha256(ref.encode()).hexdigest(), 'idref': ref}

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
            fact_cache[identity] = (None, None)
            return fact_cache[identity]
        try:
            definition = source.node(component, source_id, 'definition')
            definition_hash = _xml_digest(definition)
            semantic_key = (component, source_id, definition_hash)
            if semantic_key in fact_cache:
                result = fact_cache[semantic_key]
                fact_cache[identity] = result
                assessment_id = result[0]
                trace = shared_traces.get(assessment_id)
                if trace is not None:
                    trace.setdefault('source_fact_refs', []).append(source_fact)
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
            trace['semantic_fingerprint'] = definition_hash
            trace['source_fact_refs'] = [source_fact]
            add_shared(assessment_id, document, trace)
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
            fact_cache[identity] = (None, None)
            return fact_cache[identity]

    def fact_condition(fact):
        """Return a catalog condition for one reusable fact Assessment.

        An unqualified fact still gets a condition without ``assessment``.
        That is an explicit RI applicability ERROR leaf, so a supported
        sibling in an OR/AND tree remains visible and can be decisive under
        the canonical four-state evaluator instead of collapsing the tree.
        """
        href = fact.get('href') or ''
        source_id = fact.get('id_ref') or ''
        if not href or not source_id:
            raise ValueError('source applicability fact requires href and id-ref')
        assessment_id, _ = fact_assessment(fact)
        key = (href, source_id, fact.get('source_xml_sha256'))
        if key in fact_condition_cache:
            return fact_condition_cache[key]
        condition_id = _slug(
            f'applicability-fact:{href}:{source_id}:{fact.get("source_xml_sha256", "")}',
            'platform-', '-condition')
        source = {
            'kind': 'converter_derived', 'id': source_id, 'idref': source_id,
            'href': href, 'sha256': fact.get('source_xml_sha256'),
        }
        value = {'source': source}
        if assessment_id is not None:
            value['assessment'] = assessment_id
        add_condition(condition_id, value)
        fact_condition_cache[key] = condition_id
        return condition_id

    def lower_logical(spec_id, logical, title):
        """Lower source CPE Boolean logic to a native applicability expression.

        Only canonical recursive operators are lowered here. A logical-test
        is not an Assessment: its fact Definitions remain reusable evidence
        Assessments and this function returns the Boolean expression consumed
        at the original Benchmark/Group/Rule level.
        """
        children = []
        operands = logical.get('operands')
        if operands is None:  # tolerate old in-memory records from callers
            operands = list(logical.get('facts', [])) + list(logical.get('children', []))
        for operand in operands:
            if 'id_ref' in operand:
                condition_id = fact_condition(operand)
                if condition_id is None:
                    raise ValueError('unqualified source applicability fact')
                children.append({'condition': condition_id})
            else:
                children.append(lower_logical(spec_id, operand, title))
        if not children:
            raise ValueError('empty applicability logical-test')
        operator = str(logical.get('operator', 'AND')).upper()
        if operator not in ('AND', 'OR'):
            raise ValueError(f'source logical-test operator {operator} has no lossless canonical applicability expression')
        expression = children[0] if len(children) == 1 else {
            'all_of' if operator == 'AND' else 'any_of': children}
        if _bool(logical.get('negate')):
            expression = {'not': expression}
        return expression

    def condition_for_ref(ref):
        if ref.startswith('#'):
            platform_id = ref[1:]
            spec = specifications.get(platform_id)
            if spec is None:
                reason = 'unresolved CPE platform specification: ' + platform_id
                unsupported.append({'kind': 'platform', 'identity': platform_id, 'reason': reason})
                condition_id = unsupported_condition(platform_id, 'Unsupported CPE platform specification', reason,
                                                     condition_key(ref))
                add_condition(condition_id, {'source': source_provenance(ref)})
                return {'condition': condition_id}
            semantic = _canonical(spec)
            semantic_cache_key = ('platform', platform_id, semantic)
            if semantic_cache_key in condition_cache:
                return condition_cache[semantic_cache_key]
            condition_id = condition_key(ref)
            try:
                logical_expressions = [lower_logical(platform_id, logical, spec['title'])
                                       for logical in spec['logical_tests']]
                if not logical_expressions or any(expr is None for expr in logical_expressions):
                    raise ValueError('unqualified CPE platform applicability')
                expression = (logical_expressions[0] if len(logical_expressions) == 1 else
                              {'all_of': logical_expressions})
                platform_expressions[condition_id] = {
                    'source': source_provenance(ref, spec),
                    'expression': expression,
                }
                condition_cache[semantic_cache_key] = expression
                return expression
            except ValueError as error:
                reason = f'unsupported CPE platform specification {platform_id}: {error}'
                unsupported.append({'kind': 'platform', 'identity': platform_id, 'reason': reason})
                # A failed CPE expression is a provenance-bearing applicability
                # ERROR condition, not a synthetic zero-Test Assessment.
                add_condition(condition_id, {'source': source_provenance(ref, spec)})
                condition_cache[semantic_cache_key] = {'condition': condition_id}
                return condition_cache[semantic_cache_key]
        reason = 'CPE identity has no established executable SCAP-NG applicability mapping: ' + ref
        unsupported.append({'kind': 'cpe_identity', 'identity': ref, 'reason': reason})
        condition_id = unsupported_condition(ref, 'Unsupported CPE identity', reason, condition_key(ref))
        add_condition(condition_id, {'source': source_provenance(ref)})
        return {'condition': condition_id}

    def refs_conditions(refs):
        result = []
        for ref in refs:
            cid = condition_for_ref(ref)
            if cid not in result:
                result.append(cid)
        return result

    def _scope_expression(expressions):
        if not expressions:
            return None
        if len(expressions) == 1:
            return expressions[0]
        return {'any_of': expressions}

    # Resolve every source Group independently of Rule admission. A Group
    # restriction is source content in its own right; blocked or filtered
    # children must not make it disappear from the serialized Benchmark.
    for source_group in source.benchmark.findall('.//' + f'{{{XCCDF}}}Group'):
        level = (source.applicability_level(source_group)
                 if hasattr(source, 'applicability_level') else None)
        if not level:
            continue
        refs = [condition.get('source_idref') for condition in level.get('conditions', [])]
        refs = [ref for ref in refs if ref]
        group_level_records[source_group.get('id')] = {
            'kind': level.get('kind'), 'source_id': level.get('id'),
            'conditions': refs_conditions(refs), 'source_platform_refs': refs,
        }

    for row in coverage.get('rules', []):
        if row.get('status') not in ('converted', 'manual_only'):
            continue
        rule_id = row.get('source_rule')
        if rule_ids is not None and rule_id not in rule_ids:
            continue
        rule = source.rules.get(rule_id)
        if rule is None:
            continue
        context = (source.applicability_context(rule)
                   if hasattr(source, 'applicability_context') else {'levels': []})
        levels = []
        rule_level = None
        for level in context.get('levels', []):
            refs = [condition.get('source_idref') for condition in level.get('conditions', [])]
            refs = [ref for ref in refs if ref]
            record = (group_level_records.get(level.get('id'))
                      if level.get('kind') == 'group' else None)
            if record is None:
                expressions = refs_conditions(refs)
                record = {'kind': level.get('kind'), 'source_id': level.get('id'),
                          'conditions': expressions, 'source_platform_refs': refs}
            levels.append(record)
            if level.get('kind') == 'rule':
                rule_level = record
        # Keep only Rule-local applicability on the Rule.  Benchmark and Group
        # restrictions remain on their own native nodes; the effective
        # predicate is the RI's AND of all ancestor levels plus this local one.
        rule_path = next((path for path in row.get('artifacts', [])
                          if '/rules/' in path and path in documents), None)
        if rule_path:
            if rule_level and rule_level['conditions']:
                documents[rule_path]['rule']['applicability'] = _scope_expression(rule_level['conditions'])
            else:
                documents[rule_path]['rule'].pop('applicability', None)
            row['applicability'] = {
                'levels': levels,
                'effective_operator': 'all_of',
                'unsupported': [item for item in unsupported
                                if item.get('identity') in
                                [ref for level in levels for ref in level['source_platform_refs']] or
                                (isinstance(item.get('identity'), dict) and
                                 item['identity'].get('id_ref') in
                                 [ref for level in levels for ref in level['source_platform_refs']])],
            }
            attached_rule_ids.add(rule_id)

    benchmark_refs = [child.get('idref') for child in
                      source.benchmark.findall(f'{{{XCCDF}}}platform')]
    benchmark_refs = [ref for ref in benchmark_refs if ref]
    # A direct CPE naming binding on the Benchmark is declarative platform
    # metadata under the approved 0.4.1 contract.  It must not become a scan
    # gate or an unresolved applicability ERROR.  CPE platform definitions
    # (``#id``) and non-CPE references still flow through the executable
    # applicability path below, preserving genuine source conditions.
    benchmark_condition_refs = [ref for ref in benchmark_refs
                                if _cpe_binding(ref) is None]
    benchmark_conditions = refs_conditions(benchmark_condition_refs)
    # Keep this initialized even when a caller is converting a partial
    # document graph without the generated Benchmark wrapper.  The trace is
    # still useful in that mode and must not depend on wrapper presence.
    expected_cpe_identities = []
    benchmark_path = 'authoring/direct-slice/benchmark.json'
    if benchmark_path in documents:
        wrapper = documents[benchmark_path]['benchmark']
        wrapper['applicability_catalog'] = applicability_native_id
        wrapper['platform']['id'] = platform_native_id
        wrapper['platform']['title'] = (
            'Source platform applicability; unresolved identities remain an explicit hold')
        if benchmark_conditions:
            wrapper['platform']['applicability'] = _scope_expression(benchmark_conditions)
        else:
            wrapper['platform'].pop('applicability', None)

        # Direct Benchmark CPE names are declarative metadata only.  Preserve
        # their exact source spelling and provenance; do not create an
        # Assessment, perform matching, or turn this field into a scan gate.
        expected_cpe_identities = []
        for ref in benchmark_refs:
            binding = _cpe_binding(ref)
            if binding is None:
                continue
            expected_cpe_identities.append({
                'value': ref,
                'binding': binding,
                'source': source_provenance(ref),
            })
        if expected_cpe_identities:
            wrapper['platform']['expected_cpe_identities'] = expected_cpe_identities
        else:
            wrapper['platform'].pop('expected_cpe_identities', None)

    # Replace the source-model's simple condition IDs on nested native Groups
    # with the exact CPE expression at the same source scope.  No Rule-level
    # duplication is needed for inherited Group applicability.
    benchmark_document = documents.get(benchmark_path, {}).get('benchmark', {})
    native_groups = benchmark_document.get('groups', [])

    def find_native_group(groups, identifier):
        for group in groups:
            if group.get('id') == identifier:
                return group
            found = find_native_group(group.get('groups', []), identifier)
            if found is not None:
                return found
        return None

    from ._v04_runtime.v04_direct_scap_source import native_identifier
    for source_group in source.benchmark.findall('.//' + f'{{{XCCDF}}}Group'):
        record = group_level_records.get(source_group.get('id'))
        if not record or not record['conditions']:
            continue
        native_group = find_native_group(native_groups,
                                          native_identifier(source_group, 'group'))
        if native_group is None:
            unsupported.append({'kind': 'group', 'identity': source_group.get('id'),
                                'reason': 'source Group applicability has no serialized native Group target'})
        else:
            native_group['applicability'] = _scope_expression(record['conditions'])

    catalog_path = 'authoring/direct-slice/applicability.json'
    documents[catalog_path] = {'applicability': {
        'id': applicability_native_id, 'conditions': dict(conditions)}}
    for assessment_id, document in shared.items():
        documents[f'authoring/direct-slice/assessments/{assessment_id}.json'] = document

    # Deduplicate diagnostics while retaining complete source identities.
    unsupported = list({(_canonical(item)): item for item in unsupported}.values())

    def expression_condition_ids(expression):
        if not isinstance(expression, dict):
            return set()
        if 'condition' in expression:
            return {expression['condition']}
        result = set()
        for key in ('all_of', 'any_of'):
            for child in expression.get(key, []):
                result.update(expression_condition_ids(child))
        if 'not' in expression:
            result.update(expression_condition_ids(expression['not']))
        return result

    # Qualified conditions must resolve to an emitted Assessment.  Conditions
    # without `assessment` are intentional provenance-bearing applicability
    # holds and are evaluated as ERROR by the RI, never as FALSE.
    emitted_ids = {doc['assessment']['id'] for path, doc in documents.items()
                   if '/assessments/' in path and 'assessment' in doc}
    unresolved = sorted({value['assessment'] for value in conditions.values()
                         if 'assessment' in value} - emitted_ids)
    if unresolved:
        raise ValueError('applicability catalog has unresolved Assessments: ' + ', '.join(unresolved))
    condition_ids = set(conditions)
    for path, document in documents.items():
        if '/rules/' in path and 'rule' in document:
            missing = sorted(expression_condition_ids(document['rule'].get('applicability')) - condition_ids)
            if missing:
                raise ValueError(f'Rule {path} has unresolved applicability conditions: {missing}')
    benchmark_document = documents.get('authoring/direct-slice/benchmark.json')
    if benchmark_document:
        missing = sorted(expression_condition_ids(
            benchmark_document['benchmark']['platform'].get('applicability')) - condition_ids)
        if missing:
            raise ValueError(f'Benchmark has unresolved applicability conditions: {missing}')

    trace = {
        'format': 'scap-ng-applicability/1', 'catalog': catalog_path,
        'catalog_id': applicability_native_id,
        'conditions': [{'id': key, **value} for key, value in conditions.items()],
        'platform_expressions': [{'id': key, **value}
                               for key, value in platform_expressions.items()],
        'shared_assessments': list(shared_traces.values()),
        'unsupported': unsupported,
        'source_platform_specifications': list(specifications.values()),
        'source_rule_count_attached': len(attached_rule_ids),
        'source_rule_count_with_conditions': sum(
            bool(row.get('applicability', {}).get('levels'))
            for row in coverage.get('rules', [])),
        'source_platform_ref_count_attached': sum(
            len(level.get('source_platform_refs', []))
            for row in coverage.get('rules', [])
            for level in row.get('applicability', {}).get('levels', [])),
        'catalog_condition_count': len(conditions),
        'shared_assessment_count': len(shared),
        'source_identity_preserved': True,
        'declared_benchmark_cpe_identities': expected_cpe_identities,
        'independent_semantic_proof': False,
        'scanner_runtime': False,
    }
    coverage['applicability'] = trace
    return documents, trace
