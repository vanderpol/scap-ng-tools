"""Command mentions versus invocations, source authority and retained obligations."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import yaml

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'scripts'))
from cross_reference_rhel9_commands import extract_commands,invokes,shape_flags,command_stages
from review_rhel9_audit_patterns import fold_constant
from audit_rhel9_complexity import metrics

ROOT=BASE/'audits/rhel9-check-command-crosswalk'

class CommandCrosswalk(unittest.TestCase):
    def test_auditctl_file_arguments_are_not_invocations(self):
        for text in ('$ stat -c "%a" /sbin/auditctl','$ grep auditctl /etc/aide.conf'):
            self.assertFalse(invokes(extract_commands(text),'auditctl'))
        command=extract_commands('$ sudo -u root auditctl -l | grep execve')
        self.assertTrue(invokes(command,'auditctl'))
        self.assertEqual([s['utility'] for s in command[0]['stages']],['auditctl','grep'])

    def test_config_output_and_probe_safety_are_not_silently_approved(self):
        self.assertEqual(extract_commands('/etc/rsyslog.conf:$ActionSendStreamDriverMode 1'),[])
        self.assertEqual(extract_commands('$ActionSendStreamDriverMode 1'),[])
        config=extract_commands('# StopIdleSessionSec=infinity')
        self.assertEqual(config[0]['kind'],'configuration_or_empty')
        probe=extract_commands('$ logger -p local0.info "probe"')
        self.assertIn('state_changing_probe',probe[0]['shape_flags'])
        unknown=extract_commands('$ new-utility --query')
        self.assertEqual(unknown[0]['kind'],'unclassified_prompt_needs_review')

    def test_recursive_search_flags_do_not_confuse_long_options(self):
        for command,expected in [('grep --color=never x /fixed',False),('grep -ir x /fixed',True),('grep --recursive x /fixed',True)]:
            stages,error=command_stages(command);self.assertIsNone(error)
            self.assertEqual('recursive_search' in shape_flags(command,stages),expected)

    def test_only_constant_strings_can_be_folded(self):
        v={'v':{'expression':{'concat':[{'literal':{'datatype':'string','value':r'^\s*'}},
                                       {'literal':{'datatype':'string','value':'-a'}}]}}}
        self.assertEqual(fold_constant({'variable':'v'},v),r'^\s*-a')
        with self.assertRaises(ValueError):fold_constant({'literal':{'datatype':'integer','value':'2'}},{})
        with self.assertRaises(ValueError):fold_constant({'values':{'object':'runtime-input'}},{})
        with self.assertRaisesRegex(ValueError,'cyclic'):
            fold_constant({'variable':'v'},{'v':{'expression':{'variable':'v'}}})

    def test_complete_crosswalk_retains_prior_native_and_source_identities(self):
        x=json.loads((ROOT/'crosswalk.json').read_text());s=x['summary']
        self.assertEqual((len(x['rows']),s['native_automated'],s['manual_only_excluded'],s['automated_without_native']),(445,415,27,3))
        self.assertEqual((s['auditctl_mentions'],s['auditctl_invocation_checks'],s['auditctl_persistent_file_targets'],s['auditctl_already_shellcommand']),(54,50,49,1))
        self.assertTrue(s['all_normalized_manual_checks_identical'])
        previous={r['source_rule']:r for r in json.loads((BASE/'audits/rhel9-shellcommand/inventory.json').read_text())['rows']}
        for row in x['rows']:
            if row['native']:
                old=previous[row['source_rule']]
                self.assertEqual(row['source_rule_sha256'],old['source_rule_sha256'])
                self.assertEqual(row['native']['yaml_sha256'],old['yaml_sha256'])
                self.assertEqual(row['native']['score'],old['score'])
            else:self.assertNotIn(row['source_rule'],previous)

    def test_all_regex_obligations_are_preserved_in_both_review_sketches(self):
        r=json.loads((ROOT/'pattern-review/pattern-review.json').read_text())
        self.assertEqual(r['summary']['source_pattern_tests_checked'],133)
        self.assertEqual(r['summary']['rules_checked'],49);self.assertTrue(r['summary']['all_printed_example_patterns_match'])
        for sketch in r['sketches']:
            doc=yaml.safe_load((ROOT/'pattern-review'/sketch['directory']/'proposed-UNAPPROVED.yaml').read_text())['assessment']
            test,=doc['tests'].values()
            actual=[p['fields'].get('text',p['fields'].get('stdout_line',{})).get('matches_regex') for p in test['require']['and']]
            actual=[p for p in actual if p is not None]
            self.assertEqual(actual,[p['effective_regex'] for p in sketch['raw_regex_mapping']])
            self.assertEqual(len(actual),24);self.assertEqual(metrics(doc)['score'],sketch['after_score'])
            self.assertEqual(sketch['native_scanner_equivalence'],'UNPROVED')
            self.assertEqual(sketch['original_regex_obligations_after'],24)

    def test_complete_snapshot_examples_are_component_proofs_only(self):
        r=json.loads((ROOT/'pattern-review/pattern-review.json').read_text())
        cases={c['case']:c for c in r['controlled_snapshot_fixtures']}
        self.assertTrue(cases['positive']['result']);self.assertFalse(cases['negative_missing_b32']['result'])
        self.assertFalse(cases['empty']['result']);self.assertTrue(cases['malformed_line_split']['result'])
        self.assertTrue(cases['duplicate']['result']);self.assertTrue(cases['conflicting_extra_line']['result'])
        self.assertTrue(all(c['same_component_result'] for c in cases.values()))
        self.assertEqual(r['summary']['full_scanner_equivalence_proofs'],0)
        self.assertIn('permission denied',r['status_cases_requiring_native_runtime'])

if __name__=='__main__':unittest.main()
