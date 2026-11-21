"""Deprecated OVAL constructs remain explicit converter holds."""
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime


class DeprecatedOvalConstructs(unittest.TestCase):
    def test_deprecated_platform_tests_are_classified_before_generic_mapping_hold(self):
        engine = load_runtime()
        cases = [
            ('http://oval.mitre.org/XMLSchema/oval-definitions-5#ios', 'version_test'),
            ('http://oval.mitre.org/XMLSchema/oval-definitions-5#junos', 'xml_config_test'),
        ]
        for namespace, local_name in cases:
            with self.subTest(local_name=local_name):
                element = ET.fromstring(
                    f'<{local_name} xmlns=\"{namespace}\" id=\"test-1\"/>')
                visitor = engine.AssessmentConverter(None, None, [], native_recovery=True)
                with self.assertRaisesRegex(ValueError, 'deprecated source capability'):
                    visitor.capability(element, 'test')

    def test_owner_scoped_solaris_reinstatement_matches_expanded_element_namespace(self):
        engine = load_runtime()
        namespace = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#solaris'
        for source_name, capability in (('package_test', 'solaris.package'),
                                        ('package511_test', 'solaris.package.ips')):
            with self.subTest(source_name=source_name):
                mapping = {
                    'capability': capability,
                    'source': {'namespace': namespace, 'test': source_name},
                }
                element = ET.fromstring(
                    f'<{source_name} xmlns="{namespace}" id="test-1"/>')
                visitor = engine.AssessmentConverter(None, None, [mapping], native_recovery=True)

                self.assertIs(visitor.capability(element, 'test'), mapping)
                self.assertEqual(visitor.conversion_warnings, [{
                    'code': 'oval_deprecated_source_reinstated_scope',
                    'source_capability': source_name,
                    'source_schema_status': 'deprecated_in_5.12.3',
                    'reinstatement': 'OVAL 6 PR #226',
                    'reinstatement_commit': 'bdb6d94090b056b1b9b4b736326c3ca6ae0e6aca',
                    'scope': 'owner-directed Self-Assertion witness qualification only',
                    'scanner_evaluated': False,
                }])

    def test_unlisted_deprecated_source_still_fails_closed(self):
        engine = load_runtime()
        namespace = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#ios'
        element = ET.fromstring(
            f'<version_test xmlns="{namespace}" id="test-1"/>')
        mapping = {
            'capability': 'ios.version',
            'source': {'namespace': namespace, 'test': 'version_test'},
        }
        visitor = engine.AssessmentConverter(None, None, [mapping], native_recovery=True)
        with self.assertRaisesRegex(ValueError, 'deprecated source capability: version_test'):
            visitor.capability(element, 'test')

    def test_deprecated_environment_variable_object_is_not_a_generic_gap(self):
        engine = load_runtime()
        namespace = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
        element = ET.fromstring(
            f'<environmentvariable_object xmlns=\"{namespace}\" id=\"object-1\"/>')
        visitor = engine.AssessmentConverter(None, None, [], native_recovery=True)
        with self.assertRaisesRegex(ValueError, 'deprecated source capability: environmentvariable_object'):
            visitor.capability(element, 'object')

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
