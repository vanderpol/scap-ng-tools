"""Owner-approved 0.4 Item grouping amendment; no altered scanner semantics."""

import json
import os
from pathlib import Path
import unittest

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource


class ItemRequirementContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not root:
            raise unittest.SkipTest('Set SCAP_NG_SCHEMA_ROOT to the canonical candidate')
        cls.root = Path(root)
        schema_dir = cls.root / 'schema'
        registry = Registry()
        documents = {}
        for path in schema_dir.glob('*.schema.json'):
            schema = json.loads(path.read_text())
            registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
            documents[path.name] = schema
        cls.schema = documents['assessment-language.schema.json']
        cls.validator = Draft202012Validator(documents['assessment.schema.json'], registry=registry)
        cls.require_validator = Draft202012Validator({
            '$ref': cls.schema['$id'] + '#/$defs/canonical_all_items_requirement'
        }, registry=registry)
        cls.presence_validator = Draft202012Validator({
            '$ref': cls.schema['$id'] + '#/$defs/item_presence_requirement'
        }, registry=registry)

    def test_all_current_examples_serialize_paired_item_requirement(self):
        examples = sorted((self.root / 'examples').glob('*.assessment.yaml'))
        self.assertEqual(len(examples), 4)
        for path in examples:
            assessment = yaml.safe_load(path.read_text())
            self.assertFalse(list(self.validator.iter_errors(assessment)), path.name)
            for test in assessment['assessment']['tests'].values():
                requirement = test['require']
                self.assertNotIn('items_found', requirement)
                self.assertNotIn('items_satisfying', requirement)
                self.assertEqual(list(requirement['item_requirement']),
                                 ['items_found', 'items_satisfying'])
                self.assertFalse(list(self.require_validator.iter_errors(requirement)))
                self.assertLess(path.read_text().index('item_requirement:'),
                                path.read_text().index('field_requirement:'))

    def test_old_layout_and_incomplete_pair_rejected(self):
        new = {'item_requirement': {'items_found': 'one_or_more',
                                    'items_satisfying': 'every'},
               'field_requirement': {'values_found': 'one_or_more',
                                     'values_matching': 'every'},
               'fields': {'flag': {'equals': True}}}
        self.assertFalse(list(self.require_validator.iter_errors(new)))
        legacy = {'items_found': 'one_or_more', 'items_satisfying': 'every',
                  'field_requirement': new['field_requirement'], 'fields': new['fields']}
        self.assertTrue(list(self.require_validator.iter_errors(legacy)))
        incomplete = {**new, 'item_requirement': {'items_found': 'one_or_more'}}
        self.assertTrue(list(self.require_validator.iter_errors(incomplete)))

    def test_existence_only_keeps_absence_of_matching(self):
        existence = {'item_requirement': {'items_found': 'one_or_more'}}
        self.assertFalse(list(self.presence_validator.iter_errors(existence)))
        self.assertTrue(list(self.presence_validator.iter_errors({'items_found': 'one_or_more'})))
        self.assertTrue(list(self.presence_validator.iter_errors({
            'item_requirement': {'items_found': 'one_or_more', 'items_satisfying': 'every'}})))


if __name__ == '__main__':
    unittest.main()
