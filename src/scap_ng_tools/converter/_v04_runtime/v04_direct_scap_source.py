"""Read-only SCAP source model for the isolated direct-converter experiment.

Public contract: a pinned ZIP -> one XML tree, component-local indexes and
explicit automated-only XCCDF selection. This module emits no NG authoring.
"""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

DS = 'http://scap.nist.gov/schema/scap/source/1.2'
XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
OVAL = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
OCIL = 'http://scap.nist.gov/schema/ocil/2'
OCIL20 = 'http://scap.nist.gov/schema/ocil/2.0'
XLINK = '{http://www.w3.org/1999/xlink}href'


class UnsupportedSource(ValueError):
    """Integrity, reference or admitted-grammar failure; never a partial success."""


def ensure(condition, diagnostic):
    if not condition:
        raise UnsupportedSource(diagnostic)


def local_name(element):
    return element.tag.rsplit('}', 1)[-1]


def attributes(element, allowed):
    unexpected = set(element.attrib) - set(allowed)
    ensure(not unexpected, f'{local_name(element)}: unsupported attributes {sorted(unexpected)}')


def xml_identity(element):
    """Normalized XML identity, not signature canonicalization; ZIP bytes are pinned."""
    return [element.tag, sorted(element.attrib.items()), element.text if not len(element) else None,
            [xml_identity(child) for child in element]]


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def native_identifier(element, suffix, title=None):
    title = (title or element.get('comment') or element.findtext(f'{{{XCCDF}}}title') or
             element.findtext(f'{{{OVAL}}}metadata/{{{OVAL}}}title') or local_name(element))
    budget = 64 - len(suffix) - 1
    ensure(budget > 0 and re.fullmatch('[a-z]+', suffix), 'invalid native identifier suffix')
    stem = re.sub('[^a-z0-9]+', '-', title.lower()).strip('-')
    if not stem:
        # Some originals use punctuation-only comments. Keep a readable source
        # descriptor instead of emitting an invalid digest-only native name.
        values = ' '.join(c.text or '' for c in element if local_name(c) == 'value')
        descriptor = local_name(element).replace('_', ' ') + ' ' + values
        stem = re.sub('[^a-z0-9]+', '-', descriptor.lower()).strip('-')[:budget].rstrip('-')
    ensure(stem, 'source has no meaningful native identifier descriptor')
    if len(stem) > budget:
        # Drop grammatical boilerplate before shortening content-bearing words.
        # Negation, subject qualifiers and source version numbers are retained.
        filler = {'a', 'an', 'the', 'must', 'be', 'configured', 'to'}
        stem = '-'.join(word for word in stem.split('-') if word not in filler)
    if len(stem) > budget:
        # Keep both the subject and distinguishing end of a long title.
        # Prefix-only truncation merged separate Rules with shared boilerplate.
        left = stem[:budget // 2].rsplit('-', 1)[0]
        right = stem[-(budget - len(left) - 1):].split('-', 1)[-1]
        stem = left + '-' + right
    return f'{stem}-{suffix}'


class SourceModel:
    def __init__(self, archive_path: Path, expected_sha256: str, *, inventory_broken_references=False,
                 draft_compatibility=False):
        self.inventory_broken_references = inventory_broken_references
        self.draft_compatibility = draft_compatibility
        archive = Path(archive_path).read_bytes()
        ensure(sha256(archive).hexdigest() == expected_sha256, 'source ZIP SHA-256 mismatch')
        self.zip_sha256 = expected_sha256
        with zipfile.ZipFile(archive_path) as package:
            ensure(package.testzip() is None, 'source ZIP CRC failure')
            ensure(len(package.namelist()) == len(set(package.namelist())), 'duplicate ZIP member')
            members = [name for name in package.namelist() if name.endswith('.xml')]
            ensure(len(members) == 1, 'bounded input requires one complete SCAP XML member')
            self.member = members[0]
            raw_xml = package.read(self.member)
        self.xml_sha256 = sha256(raw_xml).hexdigest()
        try:
            self.root = ET.fromstring(raw_xml)  # The only source parse in an invocation.
        except ET.ParseError as error:
            raise UnsupportedSource(f'invalid source XML: {error}') from error
        self.parse_count = 1
        self.index()

    def index(self):
        """Build once; exposed for controlled fault injection in tests only."""
        ensure(self.root.tag == f'{{{DS}}}data-stream-collection', 'not a SCAP collection')
        self.components, self.nodes, self.component_hashes = {}, {}, {}
        self.object_references = Counter()
        for component in self.root.findall(f'{{{DS}}}component'):
            component_id = component.get('id')
            ensure(component_id and component_id not in self.components and len(component) == 1,
                   'duplicate or malformed SCAP component')
            self.components[component_id] = component[0]
            index = {}
            for element in component[0].iter():
                identifier = element.get('id')
                if identifier:
                    ensure(identifier not in index, f'duplicate ID inside component {component_id}: {identifier}')
                    index[identifier] = element
                if element.get('object_ref'):
                    self.object_references[component_id, element.get('object_ref')] += 1
                if element.tag == f'{{{OVAL}}}object_reference':
                    self.object_references[component_id, (element.text or '').strip()] += 1
            self.nodes[component_id] = index
            self.component_hashes[component_id] = digest(xml_identity(component[0]))
        streams = self.root.findall(f'{{{DS}}}data-stream')
        ensure(len(streams) == 1 and streams[0].get('scap-version') == '1.4', 'one SCAP 1.4 stream required')
        references = list(streams[0].iter(f'{{{DS}}}component-ref'))
        self.references = {reference.get('id'): reference for reference in references}
        ensure(all(self.references) and len(references) == len(self.references), 'duplicate/missing component-ref ID')
        checklists = streams[0].findall(f'{{{DS}}}checklists/{{{DS}}}component-ref')
        ensure(len(checklists) == 1, 'one checklist required')
        self.checklist = checklists[0]
        self.benchmark_component = self.component_for_reference(self.checklist.get('id'))
        self.benchmark = self.components[self.benchmark_component]
        ensure(self.benchmark.tag == f'{{{XCCDF}}}Benchmark', 'checklist does not resolve to XCCDF 1.2')
        # Decision21 is a diagnostic policy, independent of opt-in all_exist
        # or external-Input drafting. Follow only exact named original chains;
        # requested missing/ambiguous targets remain errors, never guessed.
        from v04_draft_compatibility import resolve_draft_catalog
        self.catalog, self.catalog_errors, self.catalog_warnings = resolve_draft_catalog(self)
        self.parents = {child: parent for parent in self.benchmark.iter() for child in parent}
        self.rules = {rule.get('id'): rule for rule in self.benchmark.iter(f'{{{XCCDF}}}Rule')}

    def object_uses(self, component, identifier, kind):
        """Count acquisition edges in one reachable Assessment, not the Benchmark.

        Visit each semantic node once: reusing a Test/Variable does not duplicate
        its acquisition. Distinct consumers and repeated Set operands do count.
        Filter States and their Variable dependencies participate in the walk.
        Identity is component + source ID, never equality of selector payloads.
        Conversion still diagnoses cycles, wrong kinds and unsupported syntax.
        """
        references = {'definition_ref': 'definition', 'test_ref': 'test',
                      'object_ref': 'object', 'state_ref': 'state', 'var_ref': 'variable'}
        counts, visited = Counter(), set()

        def visit(identifier, kind):
            if (kind, identifier) in visited:
                return
            visited.add((kind, identifier))
            node = self.node(component, identifier, kind)
            for child in node.iter():
                edges = [(child.get(attr), target) for attr, target in references.items() if attr in child.attrib]
                if child.tag in (f'{{{OVAL}}}object_reference', f'{{{OVAL}}}filter'):
                    edges.append(((child.text or '').strip(), 'object' if local_name(child) == 'object_reference' else 'state'))
                if node.tag == f'{{{OVAL}#independent}}variable_object' and child.tag == f'{{{OVAL}#independent}}var_ref':
                    edges.append(((child.text or '').strip(), 'variable'))
                for target, target_kind in edges:
                    if target_kind == 'object':
                        counts[target] += 1
                    visit(target, target_kind)

        if kind == 'object':
            counts[identifier] += 1  # A focused acquisition also has its caller.
        visit(identifier, kind)
        return counts

    def component_for_reference(self, reference_id):
        ensure(reference_id in self.references, f'unresolved component-ref: {reference_id}')
        href = self.references[reference_id].get(XLINK, '')
        ensure(href.startswith('#') and href[1:] in self.components, f'unresolved/nonlocal component href: {href}')
        return href[1:]

    def node(self, component_id, identifier, kind):
        ensure(identifier in self.nodes[component_id], f'unresolved {kind} in component {component_id}: {identifier}')
        element = self.nodes[component_id][identifier]
        ensure(local_name(element) == kind or local_name(element).endswith('_' + kind), f'wrong reference kind: {identifier}')
        return element

    def _component_for_check_href(self, href):
        """Resolve an XCCDF check-content-ref to its named SCAP component.

        OCIL references are not catalog entries in many signed streams.  The
        component-ref href is nevertheless a complete, local identity; match
        only that basename, and reject ambiguity rather than searching by
        source ID or namespace.
        """
        ensure(href, 'missing check-content-ref href')
        candidates = [identifier for identifier in self.components
                      if identifier == href or identifier.endswith('_' + href)]
        ensure(len(candidates) == 1, f'unresolved/ambiguous check component href: {href}')
        return candidates[0]

    def _ocil_details(self, check):
        """Return source-backed OCIL response material without lowering a workflow."""
        reference = check.find(f'{{{XCCDF}}}check-content-ref')
        ensure(reference is not None, 'OCIL check missing check-content-ref')
        attributes(reference, {'href', 'name'})
        component = self._component_for_check_href(reference.get('href'))
        questionnaire = self.nodes[component].get(reference.get('name'))
        ensure(questionnaire is not None and local_name(questionnaire) == 'questionnaire',
               f'unresolved OCIL questionnaire: {reference.get("name")}')
        question = None
        action = None
        for child in questionnaire.iter():
            if local_name(child) == 'test_action_ref' and (child.text or '').strip():
                action = self.nodes[component].get((child.text or '').strip())
                break
        if action is not None:
            question_ref = action.get('question_ref')
            if question_ref:
                question = self.nodes[component].get(question_ref)
        procedure = (check.findtext(f'{{{XCCDF}}}check-content') or '').strip()
        if not procedure and question is not None:
            procedure = (question.findtext(f'{{{OCIL20}}}question_text') or
                         question.findtext(f'{{{OCIL}}}question_text') or '').strip()
        if not procedure:
            procedure = (questionnaire.findtext(f'{{{OCIL20}}}description') or
                         questionnaire.findtext(f'{{{OCIL}}}description') or '').strip()
        ensure(procedure, f'OCIL questionnaire has no usable procedure: {reference.get("name")}')
        choices = []
        if action is not None:
            for when in action:
                if local_name(when) != 'when_choice':
                    continue
                choice_ref = (when.findtext(f'{{{OCIL20}}}choice_ref') or
                              when.findtext(f'{{{OCIL}}}choice_ref') or '').strip()
                choice = self.nodes[component].get(choice_ref)
                label = (choice.text or '').strip() if choice is not None else choice_ref
                result = (when.findtext(f'{{{OCIL20}}}result') or
                          when.findtext(f'{{{OCIL}}}result') or '').strip()
                outcome = {'PASS': 'true', 'FAIL': 'false', 'NOT_APPLICABLE': 'not_applicable',
                           'NOT_TESTED': 'not_evaluated'}.get(result, 'unknown')
                ensure(label and result, f'unsupported OCIL choice mapping: {reference.get("name")}')
                choices.append({'value': label, 'label': label, 'outcome': outcome,
                                'source_choice_ref': choice_ref, 'source_result': result})
        ensure(choices, f'OCIL questionnaire has no supported choice action: {reference.get("name")}')
        return {'system': check.get('system'), 'selector': check.get('selector', ''),
                'check_sha256': digest(xml_identity(check)), 'href': reference.get('href'),
                'name': reference.get('name'), 'component': component,
                'questionnaire_sha256': digest(xml_identity(questionnaire)),
                'questionnaire_id': questionnaire.get('id'),
                'test_action_sha256': digest(xml_identity(action)) if action is not None else None,
                'question_sha256': digest(xml_identity(question)) if question is not None else None,
                'procedure': procedure, 'choices': choices,
                'inline_content': check.find(f'{{{XCCDF}}}check-content') is not None}

    def manual_checks(self, rule):
        """Collect OCIL alternatives; OVAL selection remains authoritative."""
        return [self._ocil_details(check) for check in rule.findall(f'{{{XCCDF}}}check')
                if check.get('system') == OCIL and check.get('selector', '') in ('', 'manual')]

    def automated_check(self, rule, *, allow_manual=False):
        """Select the default OVAL check; optionally admit OCIL-only Rules manually."""
        ensure(not rule.findall(f'{{{XCCDF}}}complex-check'), 'XCCDF complex-check unsupported')
        choices, omitted, selectors, manuals = [], [], [], []
        for check in rule.findall(f'{{{XCCDF}}}check'):
            attributes(check, {'system', 'selector'})
            selector, system = check.get('selector', ''), check.get('system')
            if system != OVAL:
                ensure(system == OCIL and selector in ('', 'manual'),
                       'unsupported competing non-OVAL check/selector')
                detail = self._ocil_details(check) if allow_manual else None
                if detail is not None:
                    manuals.append(detail)
                omitted.append({'system': system, 'selector': selector,
                                'sha256': digest(xml_identity(check))})
                continue
            ensure(selector in ('', 'automated'), f'unsupported OVAL check selector: {selector}')
            ensure(selector not in selectors, 'duplicate OVAL selector unsupported')
            selectors.append(selector)
            references = check.findall(f'{{{XCCDF}}}check-content-ref')
            if self.draft_compatibility or getattr(self, 'native_recovery', False):
                ensure(len(references)==1 and all(c.tag in {f'{{{XCCDF}}}check-export',f'{{{XCCDF}}}check-content-ref'}
                       for c in check), 'OVAL check-import/result binding or complex check unsupported')
            else:
                ensure(len(check) == 1 and check[0].tag == f'{{{XCCDF}}}check-content-ref', 'OVAL check imports/exports unsupported')
            reference = references[0]
            attributes(reference, {'href', 'name'})
            ensure(reference.get('href') in self.catalog, 'unresolved checklist catalog href')
            choices.append((self.catalog[reference.get('href')], reference.get('name')))
        if not selectors:
            ensure(allow_manual and manuals, 'unsupported competing non-OVAL check/selector')
            return None, None, omitted, manuals
        ensure('' in selectors and len(set(choices)) == 1, 'unambiguous default OVAL check required')
        component_id, definition_id = choices[0]
        return component_id, definition_id, omitted, manuals

    def rule_selected(self, rule, profile=None):
        overrides = {}
        if profile is not None:
            attributes(profile, {'id'})
            for child in profile:
                ensure(child.tag in {f'{{{XCCDF}}}{name}' for name in ('title', 'description', 'select')}, 'Profile refinement/inheritance unsupported')
                if child.tag != f'{{{XCCDF}}}select':
                    continue
                attributes(child, {'idref', 'selected'})
                target = child.get('idref')
                ensure(target in self.nodes[self.benchmark_component], f'unresolved Profile idref: {target}')
                ensure(local_name(self.nodes[self.benchmark_component][target]) in ('Group', 'Rule'), 'Profile target is not an item')
                ensure(target not in overrides and child.get('selected') in ('true', 'false'), 'repeated/noncanonical Profile selection')
                overrides[target] = child.get('selected') == 'true'
        selected, item = True, rule
        while item is not self.benchmark:
            ensure(item.get('selected', 'true') in ('true', 'false'), 'noncanonical selected lexical unsupported')
            selected &= overrides.get(item.get('id'), item.get('selected', 'true') == 'true')
            item = self.parents[item]
        return selected
