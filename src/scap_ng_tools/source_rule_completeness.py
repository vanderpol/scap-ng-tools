#!/usr/bin/env python3
"""Check a native Benchmark/package against original XCCDF Rule and Profile IDs."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile

XCCDF = '{http://checklists.nist.gov/xccdf/1.2}'
DS = '{http://scap.nist.gov/schema/scap/source/1.2}'
HREF = '{http://www.w3.org/1999/xlink}href'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def index(items, key, label):
    result = {}
    for item in items:
        ident = key(item)
        require(isinstance(ident, str) and ident and ident not in result,
                f'{label}: missing or duplicate identity {ident!r}')
        result[ident] = item
    return result


def same_ids(expected, actual, label):
    expected, actual = set(expected), set(actual)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    require(not (missing or extra), f'{label}: missing={missing}; unexpected={extra}')


def xml_hash(element):
    # Source-trace/manifest wire contract for normalized XML identity.
    def identity(node):
        children = [identity(child) for child in node]
        return [node.tag, sorted(node.attrib.items()), node.text if not children else None, children]

    return sha256(json.dumps(identity(element), ensure_ascii=False,
                             separators=(',', ':')).encode()).hexdigest()


def read_source(archive):
    archive = Path(archive)
    with ZipFile(archive) as source:
        members = [name for name in source.namelist() if name.endswith('.xml')]
        require(len(members) == 1, 'expected one original SCAP XML member')
        member, = members
        raw = source.read(member)
    root = ET.fromstring(raw)
    checklists = root.findall(f'{DS}data-stream/{DS}checklists/{DS}component-ref')
    require(len(checklists) == 1, 'expected one SCAP checklist reference')
    href = checklists[0].get(HREF, '')
    components = [element for element in root.findall(DS + 'component')
                  if '#' + element.get('id', '') == href]
    require(len(components) == 1, f'unresolved or ambiguous SCAP checklist {href!r}')
    component, = components
    benchmark = component.find(XCCDF + 'Benchmark')
    require(benchmark is not None, 'checklist is not an XCCDF 1.2 Benchmark')
    return benchmark, {
        'source_benchmark_component': component.get('id'),
        'source_member': member,
        'source_zip_sha256': sha256(archive.read_bytes()).hexdigest(),
        'source_xml_sha256': sha256(raw).hexdigest(),
    }


def profile_selections(source, profiles, identifier):
    # Selectors in the lineage replace item selection. A disabled enclosing
    # Group prevents its descendants from being selected in that Profile.
    overrides, seen = {}, set()
    cursor = identifier
    while cursor:
        require(cursor in profiles and cursor not in seen, f'invalid Profile lineage for {identifier}')
        seen.add(cursor)
        profile = profiles[cursor]
        for select in profile.findall(XCCDF + 'select'):
            selected = select.get('selected')
            require(selected in ('true', 'false', '1', '0'), f'invalid selection in Profile {cursor}')
            overrides.setdefault(select.get('idref'), selected in ('true', '1'))
        cursor = profile.get('extends')

    def walk(parent, enabled):
        for child in parent:
            if child.tag in (XCCDF + 'Group', XCCDF + 'Rule'):
                ident = child.get('id')
                selected = enabled and overrides.get(
                    ident, child.get('selected', 'true') in ('true', '1'))
                if child.tag == XCCDF + 'Rule':
                    yield ident, selected
                else:
                    yield from walk(child, selected)

    return dict(walk(source, True))


def check_native(source, source_rules, crosswalk, profile_trace, benchmark, rules, assessments):
    links = {original: row['native_rule'] for original, row in crosswalk.items()}
    same_ids(links.values(), rules, 'native Rule documents')
    require(len(benchmark['rules']) == len(set(benchmark['rules'])), 'duplicate Benchmark Rule reference')
    same_ids(links.values(), benchmark['rules'], 'Benchmark Rule references')
    require(benchmark['metadata']['source_benchmark_id'] == source.get('id'),
            'Benchmark source identity metadata mismatch')
    require(benchmark['metadata']['omitted_rule_count'] == len(source_rules) - len(links),
            'Benchmark omitted Rule count does not match source')

    pending = list(benchmark.get('groups', []))
    while pending:
        group = pending.pop()
        require(set(group.get('rules', [])) <= rules.keys(), f'Group {group["id"]} has a dangling Rule')
        pending.extend(group.get('groups', []))
    for original, native in links.items():
        rule = rules[native]
        choices = rule['assessment_choices']
        default = rule['default_assessment_choice']
        require(default in choices and choices[default]['assessment'] == crosswalk[original]['assessment'],
                f'default Assessment provenance mismatch for {original}')
        for choice in choices.values():
            require(choice['assessment'] in assessments,
                    f'{original} references missing Assessment {choice["assessment"]}')
        for alternative in crosswalk[original].get('manual_alternatives', []):
            require(any(choice['assessment'] == alternative['assessment'] for choice in choices.values()),
                    f'missing manual Assessment choice for {original}')

    original_profiles = index(source.findall(XCCDF + 'Profile'), lambda node: node.get('id'), 'source Profile')
    profile_links = index(profile_trace, lambda row: row.get('source_id'), 'Profile trace')
    same_ids(original_profiles, profile_links, 'source Profile provenance')
    native_profiles = index(benchmark.get('profiles', []), lambda row: row.get('id'), 'native Profile')
    profile_ids = index(profile_trace, lambda row: row.get('native_id'), 'native Profile trace')
    same_ids(profile_ids, native_profiles, 'native Profiles')
    for ident, row in profile_links.items():
        require(row['source_sha256'] == xml_hash(original_profiles[ident]), f'Profile hash mismatch for {ident}')
        selections = profile_selections(source, original_profiles, ident)
        require(row['selected'] == {original: selections[original] for original in links},
                f'Profile selection provenance mismatch for {ident}')
        disabled = native_profiles[row['native_id']]['disabled_rules']
        require(len(set(disabled)) == len(disabled), f'duplicate disabled Rule in {ident}')
        same_ids((native for original, native in links.items() if not selections[original]),
                 disabled, f'Profile {ident} disabled Rules')
    return len(native_profiles)


def read_json(path):
    return json.loads(path.read_bytes())


def check_catalog(benchmark, catalog, assessments):
    if 'applicability_catalog' not in benchmark:
        require(catalog is None, 'unexpected applicability catalog')
        return
    require(catalog is not None and catalog['id'] == benchmark['applicability_catalog'],
            'Benchmark applicability catalog reference mismatch')
    for ident, condition in catalog['conditions'].items():
        if 'assessment' in condition:
            require(condition['assessment'] in assessments,
                    f'applicability condition {ident} references missing Assessment')


def read_package(package, benchmark_id, provenance, crosswalk, omitted):
    manifest = read_json(package / 'manifest.json')
    require(manifest['benchmark_id'] == benchmark_id, 'manifest Benchmark identity mismatch')
    build = manifest['build_provenance']
    for key, expected in provenance.items():
        require(build[key] == expected, f'manifest {key} mismatch')
    rows = index(build['source_crosswalk'], lambda row: row.get('source_rule'), 'manifest source crosswalk')
    same_ids(crosswalk, rows, 'manifest source Rule crosswalk')
    for original, row in rows.items():
        for key in ('native_rule', 'source_rule_sha256', 'assessment'):
            require(row[key] == crosswalk[original][key], f'manifest {key} mismatch for {original}')
        definition = crosswalk[original].get('definition', '')
        if definition:
            require(row['component'] == crosswalk[original]['component']
                    and row['definition'] == definition
                    and row['definition_sha256'] == crosswalk[original]['dependencies'][definition]['sha256'],
                    f'manifest OVAL Definition provenance mismatch for {original}')

    require(build['source_rule_inventory'] == {
        'selected_count': len(crosswalk),
        'omitted_count': len(omitted),
        'total_count': len(crosswalk) + len(omitted),
        'omitted_source_rules': sorted(omitted),
    }, 'manifest source Rule inventory mismatch')
    rules, assessments = {}, set()
    paths = set()
    benchmark = catalog = None
    for ident, member in manifest['objects'].items():
        path = (package / member['path']).resolve()
        require(path.is_relative_to(package.resolve()) and path not in paths,
                f'invalid or aliased package member {ident}')
        paths.add(path)
        raw = path.read_bytes()
        require(len(raw) == member['size'] and sha256(raw).hexdigest() == member['sha256'],
                f'manifest member integrity mismatch for {ident}')
        kind = member['type']
        document = json.loads(raw)
        if kind == 'benchmark':
            require(benchmark is None and member['path'] == manifest['entrypoint'],
                    'manifest Benchmark entrypoint mismatch')
            benchmark = document['benchmark']
            require(benchmark['id'] == benchmark_id, 'packaged Benchmark identity mismatch')
        elif kind == 'rule':
            rule = document['rule']
            require(ident == 'rule:' + rule['id'], f'manifest Rule identity mismatch for {ident}')
            rules[rule['id']] = rule
        elif kind == 'assessment':
            assessment = document['assessment_document']['assessment']
            require(ident == 'assessment:' + assessment['id'],
                    f'manifest Assessment identity mismatch for {ident}')
            assessments.add(assessment['id'])
        elif kind == 'applicability_catalog':
            require(catalog is None, 'manifest has multiple applicability catalogs')
            catalog = document['applicability']
            require(ident == 'applicability_catalog:' + catalog['id'], 'manifest catalog identity mismatch')
    require(benchmark is not None, 'manifest lacks Benchmark entrypoint')
    check_catalog(benchmark, catalog, assessments)
    return benchmark, rules, assessments, catalog


def audit(archive, documents, trace, *, package=None, expected_omissions=()):
    source, provenance = read_source(archive)
    documents = tuple(documents)
    source_rules = index(source.iter(XCCDF + 'Rule'), lambda node: node.get('id'), 'XCCDF Rule')
    require(source_rules, 'source Benchmark has no Rules')
    for key, expected in provenance.items():
        require(trace[key] == expected, f'authoring trace {key} mismatch')
    require(trace['source_benchmark_id'] == source.get('id'), 'trace source Benchmark identity mismatch')
    crosswalk = index(trace['rules'], lambda row: row.get('source_rule'), 'source Rule trace')
    index(trace['rules'], lambda row: row.get('native_rule'), 'native Rule trace')
    admitted = set(source_rules) - set(expected_omissions)
    same_ids(admitted, crosswalk, 'original XCCDF Rules')
    omitted = sorted(set(source_rules) - admitted)
    require(sorted(expected_omissions) == omitted == sorted(trace['omitted_rules']),
            'source Rule omission ledger mismatch')
    for ident, row in crosswalk.items():
        require(row['source_rule_sha256'] == xml_hash(source_rules[ident]), f'Rule hash mismatch for {ident}')
        source_checks = [xml_hash(check) for check in source_rules[ident].findall(XCCDF + 'check')]
        require([check['sha256'] for check in row['source_checks']] == source_checks,
                f'check provenance mismatch for {ident}')
    if not admitted:
        require(not documents and package is None, 'unexpected authoring for empty admission')
        return {'source_rules': len(source_rules), 'native_rules': 0, 'profiles': 0, 'assessments': 0}

    benchmarks = [doc['benchmark'] for doc in documents if 'benchmark' in doc]
    require(len(benchmarks) == 1, 'expected one native Benchmark')
    benchmark, = benchmarks
    require(benchmark['id'] == trace['native_benchmark_id'], 'authoring Benchmark identity mismatch')
    rules = index((doc['rule'] for doc in documents if 'rule' in doc),
                  lambda rule: rule.get('id'), 'native Rule')
    assessments = index((doc['assessment'] for doc in documents if 'assessment' in doc),
                        lambda assessment: assessment.get('id'), 'native Assessment')
    catalogs = [doc['applicability'] for doc in documents if 'applicability' in doc]
    require(len(catalogs) <= 1, 'multiple authoring applicability catalogs')
    catalog = catalogs[0] if catalogs else None
    check_catalog(benchmark, catalog, assessments)
    count = check_native(source, source_rules, crosswalk, trace['profiles'],
                         benchmark, rules, assessments)
    if package is not None:
        packaged_benchmark, packaged_rules, packaged_assessments, packaged_catalog = read_package(
            Path(package), benchmark['id'], provenance, crosswalk, omitted)
        require(packaged_catalog == catalog, 'package changed applicability catalog')
        same_ids(assessments, packaged_assessments, 'packaged Assessments')
        check_native(source, source_rules, crosswalk, trace['profiles'],
                     packaged_benchmark, packaged_rules, packaged_assessments)
        for ident, rule in rules.items():
            for key in ('assessment_choices', 'default_assessment_choice'):
                require(packaged_rules[ident][key] == rule[key],
                        f'package changed {key} for {ident}')
    return {'source_rules': len(source_rules), 'native_rules': len(rules),
            'profiles': count, 'assessments': len(assessments)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='original SCAP ZIP')
    parser.add_argument('--authoring', type=Path, required=True, help='Tools conversion output directory')
    parser.add_argument('--package', type=Path, help='packaged output with manifest.json')
    args = parser.parse_args()
    try:
        documents = [read_json(path) for path in (args.authoring / 'authoring').rglob('*.json')]
        trace = read_json(args.authoring / 'source-trace.json')
        print(json.dumps(audit(args.source, documents, trace, package=args.package), sort_keys=True))
    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        parser.exit(1, f'Source Rule completeness failed: {error}\n')


if __name__ == '__main__':
    main()
