"""Reject coordinated Rule omissions and damaged native package references."""
import copy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from scap_ng_tools.source_rule_completeness import audit


SOURCE = b'''<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2"
    xmlns:xlink="http://www.w3.org/1999/xlink">
  <data-stream scap-version="1.4">
    <checklists><component-ref id="ref" xlink:href="#component"/></checklists>
  </data-stream>
  <component id="component">
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="original-benchmark">
      <Profile id="parent"><select idref="g" selected="false"/></Profile>
      <Profile id="child" extends="parent"><select idref="g" selected="true"/></Profile>
      <Group id="g"><Rule id="original-a"><check system="urn:fixture"/></Rule></Group>
      <Rule id="original-b"/>
    </Benchmark>
  </component>
</data-stream-collection>'''

X = '{http://checklists.nist.gov/xccdf/1.2}'
CHECK = [X + 'check', [['system', 'urn:fixture']], None, []]
PARENT = [X + 'Profile', [['id', 'parent']], None,
          [[X + 'select', [['idref', 'g'], ['selected', 'false']], None, []]]]
CHILD = [X + 'Profile', [['extends', 'parent'], ['id', 'child']], None,
         [[X + 'select', [['idref', 'g'], ['selected', 'true']], None, []]]]


def hash_identity(expected):
    return sha256(json.dumps(expected, separators=(',', ':')).encode()).hexdigest()


class RuleCompleteness(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.archive = self.root / 'source.zip'
        with ZipFile(self.archive, 'w') as source:
            source.writestr('signed.xml', SOURCE)
        self.pins = {
            'source_zip_sha256': sha256(self.archive.read_bytes()).hexdigest(),
            'source_xml_sha256': sha256(SOURCE).hexdigest(),
            'source_member': 'signed.xml',
            'source_benchmark_component': 'component',
        }
        self.trace = dict(self.pins, source_benchmark_id='original-benchmark',
                          native_benchmark_id='native-benchmark', omitted_rules=[], rules=[], profiles=[])
        self.benchmark = {'id': 'native-benchmark', 'rules': ['native-a', 'native-b'],
                          'metadata': {'source_benchmark_id': 'original-benchmark',
                                       'omitted_rule_count': 0}, 'profiles': []}
        self.docs = [{'benchmark': self.benchmark}]
        for suffix in ('a', 'b'):
            original = 'original-' + suffix
            native, assessment = 'native-' + suffix, 'assessment-' + suffix
            has_check = suffix == 'a'
            self.trace['rules'].append({
                'source_rule': original, 'native_rule': native, 'assessment': assessment,
                'source_rule_sha256': hash_identity(
                    [X + 'Rule', [['id', original]], None, [CHECK] if has_check else []]),
                'source_checks': [{'sha256': hash_identity(CHECK)}] if has_check else [],
            })
            self.docs.extend([
                {'rule': {'id': native, 'default_assessment_choice': 'automated',
                          'assessment_choices': {'automated': {'assessment': assessment}}}},
                {'assessment': {'id': assessment}},
            ])
        for ident, source, enabled in [('parent', PARENT, False), ('child', CHILD, True)]:
            self.benchmark['profiles'].append({
                'id': 'native-' + ident, 'disabled_rules': [] if enabled else ['native-a']})
            self.trace['profiles'].append({
                'source_id': ident, 'source_sha256': hash_identity(source), 'native_id': 'native-' + ident,
                'selected': {'original-a': enabled, 'original-b': True},
            })

    def test_original_xml_detects_coordinated_omission(self):
        self.assertEqual(audit(self.archive, self.docs, self.trace),
                         {'source_rules': 2, 'native_rules': 2, 'profiles': 2, 'assessments': 2})
        self.trace['rules'].pop()
        self.trace['omitted_rules'] = ['original-b']
        self.benchmark['rules'].pop()
        self.benchmark['metadata']['omitted_rule_count'] = 1
        for row in self.trace['profiles']:
            del row['selected']['original-b']
        del self.docs[-2:]
        with self.assertRaisesRegex(ValueError, r'original XCCDF Rules: missing=.*original-b'):
            audit(self.archive, self.docs, self.trace)
        receipt = audit(self.archive, self.docs, self.trace, expected_omissions=['original-b'])
        self.assertEqual(receipt['native_rules'], 1)

    def test_detects_duplicate_reference_or_missing_assessment(self):
        self.benchmark['rules'].append('native-a')
        with self.assertRaisesRegex(ValueError, 'duplicate Benchmark Rule reference'):
            audit(self.archive, self.docs, self.trace)
        self.benchmark['rules'].pop()
        self.docs.pop()
        with self.assertRaisesRegex(ValueError, 'references missing Assessment assessment-b'):
            audit(self.archive, self.docs, self.trace)

    def test_detects_profile_loss_and_false_check_provenance(self):
        self.benchmark['profiles'][0]['disabled_rules'].clear()
        self.trace['profiles'][0]['selected']['original-a'] = True
        with self.assertRaisesRegex(ValueError, 'Profile selection provenance mismatch'):
            audit(self.archive, self.docs, self.trace)
        self.trace['rules'][0]['source_checks'].clear()
        with self.assertRaisesRegex(ValueError, 'check provenance mismatch'):
            audit(self.archive, self.docs, self.trace)

    def test_checks_manifest_and_packaged_profile_independently(self):
        members = {}
        for document in self.docs:
            kind, = document
            ident = document[kind]['id']
            path = 'benchmark.json' if kind == 'benchmark' else ident + '.json'
            payload = {'assessment_document': document} if kind == 'assessment' else document
            self.write_member(members, kind, ident, path, payload)
        build = dict(self.pins, source_crosswalk=copy.deepcopy(self.trace['rules']),
                     source_rule_inventory={'selected_count': 2, 'omitted_count': 0,
                                            'total_count': 2, 'omitted_source_rules': []})
        manifest = {'benchmark_id': 'native-benchmark', 'entrypoint': 'benchmark.json',
                    'objects': members, 'build_provenance': build}
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(manifest))
        self.assertEqual(audit(self.archive, self.docs, self.trace, package=self.root)['native_rules'], 2)
        valid_rule = (self.root / 'native-b.json').read_bytes()
        (self.root / 'native-b.json').write_bytes(valid_rule + b'\n')
        with self.assertRaisesRegex(ValueError, 'member integrity mismatch for rule:native-b'):
            audit(self.archive, self.docs, self.trace, package=self.root)
        (self.root / 'native-b.json').write_bytes(valid_rule)
        members.pop('rule:native-b')
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'native Rule documents: missing'):
            audit(self.archive, self.docs, self.trace, package=self.root)
        self.write_member(members, 'rule', 'native-b', 'native-b.json', self.docs[-2])
        benchmark = copy.deepcopy(self.benchmark)
        benchmark['profiles'][0]['disabled_rules'].clear()
        self.write_member(members, 'benchmark', 'native-benchmark', 'benchmark.json',
                          {'benchmark': benchmark})
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'Profile parent disabled Rules: missing'):
            audit(self.archive, self.docs, self.trace, package=self.root)

    def write_member(self, members, kind, ident, path, payload):
        raw = json.dumps(payload).encode()
        (self.root / path).write_bytes(raw)
        members[kind + ':' + ident] = {'type': kind, 'path': path, 'size': len(raw),
                                       'sha256': sha256(raw).hexdigest()}
