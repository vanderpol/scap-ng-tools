"""Complete, read-only source discovery, independent of conversion admission.

Edges retain component scope. Inventory follows unsupported nodes too: stopping
at an unfamiliar capability would hide the other capabilities a Rule requires.
This module describes source syntax, never lowers or evaluates it.
"""
from collections import Counter
import json
from pathlib import Path

from v04_direct_scap_source import OVAL, XCCDF, digest, local_name, xml_identity

X = '{' + XCCDF + '}'
REFERENCE_ATTRIBUTES = {'definition_ref': 'definition', 'test_ref': 'test',
                        'object_ref': 'object', 'state_ref': 'state', 'var_ref': 'variable'}


def node_kind(element):
    name = local_name(element)
    return next((kind for kind in ('definition', 'test', 'object', 'state', 'variable')
                 if name == kind or name.endswith('_' + kind)), None)


def issue(category, message, source_id, component=None):
    return {'category': category, 'message': message, 'source_id': source_id, 'component': component}


class SourceInventory:
    """One indexed dependency graph, then deterministic per-Rule graph walks."""
    def __init__(self, source):
        self.source, self.nodes = source, {}
        # Catalog names are descriptive inventory only, never admission authority.
        catalog = {}
        directory = Path(__file__).resolve().parents[1] / 'schema/v0.4.0/capability-mappings/supported'
        for path in sorted(directory.glob('*.json')):
            mapping = json.loads(path.read_text())
            for kind in ('test', 'object', 'state'):
                if mapping.get('source', {}).get(kind):
                    catalog['{' + mapping['source']['namespace'] + '}' + mapping['source'][kind]] = mapping['capability']
        for component, root in source.components.items():
            if root.tag != '{' + OVAL + '}oval_definitions':
                continue
            for identifier, element in source.nodes[component].items():
                kind = node_kind(element)
                if not kind:
                    continue
                edges, constructs = [], set()
                for descendant in element.iter():
                    constructs.add(local_name(descendant))
                    for attribute, target_kind in REFERENCE_ATTRIBUTES.items():
                        if attribute in descendant.attrib:
                            edges.append({'id': descendant.get(attribute), 'kind': target_kind})
                    if descendant.tag in ('{' + OVAL + '}filter', '{' + OVAL + '}object_reference'):
                        edges.append({'id': (descendant.text or '').strip(),
                                      'kind': 'state' if local_name(descendant) == 'filter' else 'object'})
                    if element.tag == '{' + OVAL + '#independent}variable_object' and descendant.tag == '{' + OVAL + '#independent}var_ref':
                        edges.append({'id': (descendant.text or '').strip(), 'kind': 'variable'})
                family = element.tag.rsplit('}', 1)[0][1:] if kind in ('test', 'object', 'state') else None
                self.nodes[component, identifier] = {'id': identifier, 'component': component,
                    'kind': kind, 'tag': element.tag, 'sha256': digest(xml_identity(element)),
                    'source_family': family,
                    'capability': catalog.get(element.tag, element.tag.rsplit('_', 1)[0]) if family else None,
                    'constructs': sorted(constructs), 'references': edges}

    def counts(self, rows):
        referenced = {(n['component'], n['id']): n for r in rows for n in r['dependencies']}
        return {'indexed_oval_nodes': dict(sorted(Counter(n['kind'] for n in self.nodes.values()).items())),
                'rule_referenced_unique_oval_nodes': dict(sorted(Counter(n['kind'] for n in referenced.values()).items())),
                'checks_by_system': dict(sorted(Counter(c['system'] for r in rows for c in r['checks']).items())),
                'checks_by_selector': dict(sorted(Counter(c['selector'] for r in rows for c in r['checks']).items())),
                'profiles': [{'id': p.get('id'), 'sha256': digest(xml_identity(p)),
                              'source_select_count': len(p.findall(X + 'select'))}
                             for p in self.source.benchmark.findall(X + 'Profile')]}

    def closure(self, component, identifier):
        visited, active, active_ids, found, problems = set(), [], set(), [], []
        # Exit frames retain the active path until all ordered edges are examined.
        pending = [(identifier, 'definition', False)]
        while pending:
            identifier, expected, exiting = pending.pop()
            if exiting:
                active.pop()
                active_ids.remove(identifier)
                continue
            key = component, identifier
            if identifier in active_ids:
                problems.append(issue('source-invalid', 'cyclic dependency: ' + ' -> '.join(active + [identifier]), identifier, component))
                continue
            node = self.nodes.get(key)
            if node is None or node['kind'] != expected:
                problems.append(issue('source-invalid', f'unresolved/wrong-kind {expected}: {identifier}', identifier, component))
                continue
            if key in visited:
                continue
            visited.add(key)
            found.append(node)
            active.append(identifier)
            active_ids.add(identifier)
            pending.append((identifier, expected, True))
            pending.extend((edge['id'], edge['kind'], False) for edge in reversed(node['references']))
        return sorted(found, key=lambda node: node['id']), problems

    def rules(self):
        rows = []
        profiles = self.source.benchmark.findall(X + 'Profile')
        for identifier, rule in sorted(self.source.rules.items()):
            checks, dependencies, problems = [], {}, []
            for check in rule.findall('.//' + X + 'check'):
                references = []
                for reference in check.findall(X + 'check-content-ref'):
                    href, target = reference.get('href'), reference.get('name')
                    component = self.source.catalog.get(href)
                    references.append({'href': href, 'name': target, 'component': component})
                    if check.get('system') == OVAL:
                        if component is None:
                            problems.append(issue('source-invalid', 'unresolved checklist catalog href: ' + str(href), identifier))
                        else:
                            nodes, errors = self.closure(component, target)
                            dependencies.update({(n['component'], n['id']): n for n in nodes})
                            problems.extend(errors)
                checks.append({'system': check.get('system'), 'selector': check.get('selector', ''),
                               'sha256': digest(xml_identity(check)), 'references': references})
            selections = {}
            for profile in [None] + profiles:
                name = profile.get('id') if profile is not None else 'default'
                try:
                    selections[name] = self.source.rule_selected(rule, profile)
                except ValueError as error:
                    selections[name] = None
                    problems.append(issue('unsupported-selection', str(error), name))
            nodes = sorted(dependencies.values(), key=lambda n: (n['component'], n['id']))
            ancestors, platforms = [], []
            item = rule
            while True:
                ancestors.append({'kind': local_name(item), 'id': item.get('id')})
                platforms.extend({'origin': item.get('id'), 'idref': p.get('idref'),
                                  'sha256': digest(xml_identity(p))} for p in item.findall(X + 'platform'))
                if item is self.source.benchmark:
                    break
                item = self.source.parents[item]
            rows.append({'source_rule': identifier, 'title': rule.findtext(X + 'title', ''),
                'source_rule_sha256': digest(xml_identity(rule)),
                'source': {'zip_sha256': self.source.zip_sha256, 'member': self.source.member,
                           'benchmark_component': self.source.benchmark_component, 'fragment': identifier},
                'checks': checks, 'selection': selections, 'dependencies': nodes,
                'unconverted_policy_context': {'ancestor_items': ancestors, 'platforms': platforms,
                    'original_rule_attributes': dict(rule.attrib),
                    'rule_children': [{'tag': c.tag, 'sha256': digest(xml_identity(c))} for c in rule
                                      if local_name(c) not in ('check', 'title', 'version', 'description')]},
                'needed_source_families': sorted({n['source_family'] for n in nodes if n['source_family']}),
                'needed_capabilities': sorted({n['capability'] for n in nodes if n['capability']}),
                'needed_constructs': sorted({c for n in nodes for c in n['constructs']}),
                'inventory_problems': problems,
                'omissions': ['platform/CPE execution', 'full policy metadata/scoring/remediation',
                             'manual execution and alternatives'],
                'status': 'inventoried', 'proof_level': 'none', 'artifacts': [], 'blockers': []})
        return rows


def summarize(rows):
    """Counts are per Rule, not per repeated diagnostic/dependency occurrence."""
    return {'source_rules': len(rows), 'statuses': dict(sorted(Counter(r['status'] for r in rows).items())),
            'proof_levels': dict(sorted(Counter(r['proof_level'] for r in rows).items())),
            'rules_by_capability': dict(sorted(Counter(c for r in rows for c in r['needed_capabilities']).items())),
            'rules_by_source_family': dict(sorted(Counter(f for r in rows for f in r['needed_source_families']).items())),
            'rules_by_blocker_category': dict(sorted(Counter(c for r in rows for c in {b['category'] for b in r['blockers']}).items())),
            'rules_by_blocker_message': dict(sorted(Counter(m for r in rows for m in {b['message'] for b in r['blockers']}).items()))}


def coverage_markdown(manifest):
    lines = ['# Original-source coverage (automated subset only)', '',
             'Conversion is not scanner execution or complete Benchmark/policy equivalence.', '',
             f"Source ZIP SHA-256: `{manifest['source_zip_sha256']}`", '',
             'The companion machine manifest retains full component/check/Profile/dependency links and hashes.', '',
             '| Original Rule | Rule SHA-256 | Needed capabilities | Status / proof level | Artifacts / blockers |',
             '| --- | --- | --- | --- | --- |']
    for row in manifest['rules']:
        detail = ', '.join(row['artifacts']) if row['artifacts'] else '; '.join(
            sorted({b['category'] + ': ' + b['message'] for b in row['blockers']}))
        lines.append('| ' + row['source_rule'] + ' | ' + row['source_rule_sha256'] + ' | ' +
                     ', '.join(row['needed_capabilities']).replace('|', '\\|') + ' | ' +
                     row['status'] + ' / ' + row['proof_level'] + ' | ' +
                     detail.replace('|', '\\|').replace('\n', ' ') + ' |')
    return '\n'.join(lines) + '\n'
