"""Deprecated OVAL constructs remain explicit converter holds."""
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime


class DeprecatedOvalConstructs(unittest.TestCase):
    def test_deprecated_state_field_is_classified_before_generic_mapping_hold(self):
        engine = load_runtime()
        namespace = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows'
        state = ET.fromstring(
            f'<auditeventpolicysubcategories_state xmlns="{namespace}" id="state-1">'
            '<kerberos_ticket_events operation="pattern match">AUDIT_NONE</kerberos_ticket_events>'
            '</auditeventpolicysubcategories_state>')
        mapping = {
            'capability': 'windows.auditeventpolicysubcategories',
            'source': {'namespace': namespace, 'state': 'auditeventpolicysubcategories_state'},
            'native': {
                'state_field_map': {'credential_validation': 'credential_validation'},
                'field_datatypes': {'credential_validation': ['string']},
            },
            'migration_crosswalk': {
                'deprecated_state_fields': {
                    'kerberos_ticket_events': 'migration_error_deprecated',
                },
            },
        }
        visitor = engine.AssessmentConverter(None, None, [mapping], native_recovery=True)
        with self.assertRaisesRegex(ValueError, 'deprecated source State field: kerberos_ticket_events'):
            visitor.convert_state(state)


if __name__ == '__main__':
    unittest.main()
