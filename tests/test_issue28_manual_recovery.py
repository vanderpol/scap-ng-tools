"""Source-backed OCIL selection recovery for Issue #28."""
from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / '.issue28-sources'
SCHEMA = Path('/home/u1239716047117002/Documents/scap-ng/scap-ng/.worktrees/issue8-native-discovery')

AD = SOURCES / 'U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip'
IE = SOURCES / 'U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip'
AD_RULE = 'xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-243468r959010_rule'
IE_RULE = 'xccdf_mil.disa.fso_rule_SV-223017r961089_rule'


class ManualSelectionRecovery(unittest.TestCase):
    def _source(self, path):
        from scap_ng_tools.converter.direct04 import load_runtime
        return load_runtime().SourceModel(path, sha256(path.read_bytes()).hexdigest())

    def test_ocil_only_is_not_silently_promoted_to_automation(self):
        if not AD.is_file():
            self.skipTest('Issue #28 pinned source ZIPs are not present')
        source = self._source(AD)
        with self.assertRaisesRegex(ValueError, 'non-OVAL'):
            source.automated_check(source.rules[AD_RULE])
        component, definition, omitted, manual = source.automated_check(
            source.rules[AD_RULE], allow_manual=True)
        self.assertIsNone(component)
        self.assertIsNone(definition)
        self.assertEqual(len(manual), 2)
        self.assertEqual(manual[0]['name'], 'ocil:navy.navwar.niwcatlantic.scc.sql.server:questionnaire:501')
        self.assertTrue(manual[0]['procedure'])
        self.assertEqual({choice['outcome'] for choice in manual[0]['choices']},
                         {'true', 'false', 'not_applicable', 'not_evaluated'})
        self.assertTrue(any(item['inline_content'] for item in manual))

    def test_oval_remains_default_and_ocil_is_a_preserved_alternative(self):
        if not IE.is_file() or not SCHEMA.is_dir():
            self.skipTest('Issue #28 sources or accepted schema snapshot are not present')
        from scap_ng_tools.converter.direct04 import convert_focused
        source_hash = sha256(IE.read_bytes()).hexdigest()
        documents, trace = convert_focused(
            schema_root=SCHEMA, source=IE, sha256_pin=source_hash,
            rule_ids=[IE_RULE], native_recovery=True, recover_manual=True)
        rule = next(document['rule'] for path, document in documents.items() if '/rules/' in path)
        self.assertEqual(rule['default_assessment_choice'], 'automated')
        self.assertEqual(set(rule['assessment_choices']), {'automated', 'manual'})
        manual = next(document['assessment'] for path, document in documents.items()
                      if '/assessments/' in path and document['assessment']['mode'] == 'manual')
        self.assertEqual(manual['response']['type'], 'ocil-choice')
        self.assertTrue(manual['procedure'])
        binding = trace['rules'][0]
        self.assertEqual(binding['manual_checks'][0]['name'],
                         'ocil:navy.navwar.niwcatlantic.scc.ie:questionnaire:501')
        self.assertEqual(binding['conversion_status'], 'CONVERTED_UNVERIFIED')


if __name__ == '__main__':
    unittest.main()
