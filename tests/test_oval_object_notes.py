"""OVAL Object notes are metadata, not acquisition selectors."""
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime


class OvalObjectNotes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_runtime()
        cls.namespace = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
        cls.mapping = {
            'capability': 'independent.environmentvariable',
            'source': {
                'namespace': cls.namespace,
                'object': 'environmentvariable58_object',
            },
            'native': {
                'test_source': {'kind': 'object'},
                'selector_map': {'name': 'name', 'pid': 'pid'},
                'field_datatypes': {'name': ['string'], 'pid': ['integer']},
                'state_field_map': {'name': 'name', 'pid': 'pid'},
            },
        }

    def convert(self, notes):
        object_id = 'obj-' + ('notes' if notes else 'plain')
        element = ET.fromstring(
            f'<environmentvariable58_object xmlns="{self.namespace}" '
            f'id="{object_id}" version="1">{notes}'
            '<pid datatype="int">123</pid><name>WINDIR</name>'
            '</environmentvariable58_object>')

        class Source:
            nodes = {'component': {object_id: element}}

        visitor = self.engine.AssessmentConverter(
            Source(), 'component', [self.mapping], native_recovery=True)
        visitor.object_uses = {object_id: 1}
        return visitor.convert_object(element), visitor.conversion_warnings

    def test_canonical_common_namespace_notes_are_not_selectors(self):
        native, warnings = self.convert(
            '<oval:notes xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">'
            '<oval:note>descriptive metadata</oval:note></oval:notes>')
        self.assertEqual(native, {
            'capability': 'independent.environmentvariable',
            'pid': {'equals': 123},
            'name': {'equals': 'WINDIR'},
        })
        self.assertEqual(warnings, [])

    def test_deprecated_definition_namespace_notes_are_admitted_with_warning(self):
        native, warnings = self.convert(
            '<oval-def:notes xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
            '<oval-def:note>descriptive metadata</oval-def:note></oval-def:notes>')
        self.assertEqual(native, {
            'capability': 'independent.environmentvariable',
            'pid': {'equals': 123},
            'name': {'equals': 'WINDIR'},
        })
        self.assertEqual([item['code'] for item in warnings], [
            'oval_deprecated_object_notes_ignored',
        ])


if __name__ == '__main__':
    unittest.main()
