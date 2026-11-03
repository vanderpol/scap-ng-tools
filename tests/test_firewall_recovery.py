"""Pinned Firewall whole-Rule DRAFT accounting and source-derived manual choices."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.recovery04 import recover_benchmark, _identifier
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter.ocil_manual import manual_assessment, O

FILENAME='U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip'
PIN='d16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca'


class FirewallRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema=os.environ.get('SCAP_NG_SCHEMA_ROOT');fixtures=os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not fixtures:raise unittest.SkipTest('Exact public schema and signed fixtures required')
        cls.schema=Path(schema);cls.source=Path(fixtures)/FILENAME
        cls.docs,cls.trace,cls.ledger=recover_benchmark(schema_root=cls.schema,source=cls.source,sha256_pin=PIN)
        load_runtime()
        from v04_direct_scap_source import SourceModel,XCCDF,OCIL
        cls.model=SourceModel(cls.source,PIN)
        cls.X='{'+XCCDF+'}';cls.OCIL=OCIL

    def test_all_21_rules_20_automated_and_21_manual_choices(self):
        self.assertEqual(sha256(self.source.read_bytes()).hexdigest(),PIN)
        self.assertEqual(self.ledger['summary']['statuses'],{'AUTOMATED_DRAFT':20,'MANUAL':1})
        self.assertEqual(self.ledger['summary']['manual_choices'],21)
        self.assertEqual(len(self.docs),64)
        self.assertEqual(len(self.trace['source_rule_records']),21)
        rules=[d['rule'] for d in self.docs.values() if 'rule' in d]
        self.assertEqual(len(rules),21)
        for rule in rules:
            self.assertIn('manual',rule['assessment_choices'])
            self.assertIn(rule['default_assessment_choice'],rule['assessment_choices'])
        manual_only=next(r for r in self.ledger['rules'] if 'SV-242009' in r['source_rule'])
        rule=next(r for r in rules if 'sv-242009' in r['id'])
        self.assertEqual(set(rule['assessment_choices']),{'manual'})
        self.assertEqual(rule['default_assessment_choice'],'manual')
        self.assertEqual(manual_only['status'],'MANUAL')
        self.assertFalse(any(r['blockers'] for r in self.ledger['rules']))
        self.assertFalse(any(r['compiled'] or r['scanner_execution'] or r['independent_source_proof'] for r in self.ledger['rules']))

    def test_original_choice_labels_question_text_and_explicit_mapping(self):
        manuals=[d['assessment'] for d in self.docs.values() if d.get('assessment',{}).get('mode')=='manual']
        self.assertEqual(len(manuals),21)
        for a in manuals:
            self.assertNotIn('tests',a);self.assertNotIn('evaluate',a)
            self.assertEqual([(c['label'],c['outcome']) for c in a['response']['choices']],
                [('Finding','false'),('Not a Finding','true'),('Not Applicable','not_applicable'),('Not Reviewed','not_evaluated')])
            ref=a['references'][0];root=self.model.nodes[ref['source_component']]
            q=root[ref['source_questionnaire']]
            action=root[q.findtext(O+'actions/'+O+'test_action_ref')]
            question=root[action.get('question_ref')]
            self.assertEqual(a['procedure'],question.findtext(O+'question_text'))
            self.assertNotIn('default',a['response'])
        for binding in self.trace['rules']:
            self.assertTrue(binding['manual_choices'])
            self.assertTrue(all(p['default_answer_applied'] is False for p in binding['manual_choices']))

    def test_publisher_and_controlled_organization_binding(self):
        docs,trace,ledger=recover_benchmark(schema_root=self.schema,source=self.source,sha256_pin=PIN,organization_parameters=True)
        self.assertEqual(ledger['summary'],self.ledger['summary'])
        benchmark=next(d['benchmark'] for d in docs.values() if 'benchmark' in d)
        publisher=next(d['benchmark'] for d in self.docs.values() if 'benchmark' in d)
        self.assertEqual(len(benchmark['parameters']),20)
        self.assertEqual(len({p['id'] for p in benchmark['parameters']}),20)
        self.assertTrue(all(p['resolution']=='organization' and 'value' not in p for p in benchmark['parameters']))
        self.assertTrue(all(p['resolution']=='publisher' and 'value' in p for p in publisher['parameters']))
        for doc in docs.values():
            if 'rule' not in doc or 'automated' not in doc['rule']['assessment_choices']:continue
            discovery=doc['rule']['organizational_input_requirements']['automated']
            self.assertTrue(discovery)
            self.assertTrue(all(u['kind']=='value' and u['source_path'].endswith('/input') for r in discovery for u in r['uses']))
        self.assertEqual(sha256(self.source.read_bytes()).hexdigest(),PIN)

    def test_manual_unsupported_or_dishonest_workflows_reject(self):
        from v04_direct_scap_source import OCIL
        rule=next(r for k,r in self.model.rules.items() if 'SV-242009' in k)
        check=next(c for c in rule.findall(self.X+'check') if c.get('system')==OCIL)
        component=self.model.catalog[check[0].get('href')]
        qid=check[0].get('name')
        for kind in ('unknown-result','missing-choice','compound','unknown-default','conflicting-inline'):
            model=deepcopy(self.model);alter=deepcopy(check);nodes=model.nodes[component]
            questionnaire=nodes[qid];action=nodes[questionnaire.findtext(O+'actions/'+O+'test_action_ref')]
            question=nodes[action.get('question_ref')]
            if kind=='unknown-result':action.find(O+'when_choice/'+O+'result').text='UNDEFINED'
            elif kind=='missing-choice':action.remove(action.findall(O+'when_choice')[-1])
            elif kind=='compound':ET.SubElement(questionnaire.find(O+'actions'),O+'test_action_ref').text='missing-action'
            elif kind=='unknown-default':question.set('default_answer_ref','missing-choice')
            else:ET.SubElement(alter,self.X+'check-content').text='Contradictory procedure'
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                manual_assessment(model,alter,assessment_id='firewall-manual',title='Firewall')

    def test_external_value_incompatible_default_blocks_without_losing_rule_accounting(self):
        model=deepcopy(self.model)
        value=next(model.benchmark.iter(self.X+'Value'))
        value.find(self.X+'value').text='999'
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'controlled.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr(model.member,ET.tostring(model.root))
            _,_,ledger=recover_benchmark(schema_root=self.schema,source=p,sha256_pin=sha256(p.read_bytes()).hexdigest())
        self.assertEqual(ledger['summary']['source_rules'],21)
        row=next(r for r in ledger['rules'] if 'SV-241989' in r['source_rule'])
        self.assertEqual(row['status'],'BLOCKED')
        self.assertTrue(any('default violates' in b for b in row['blockers']))

    def test_naming_is_stable_readable_and_detects_normalization_collisions(self):
        from v04_direct_scap_source import XCCDF
        original=deepcopy(self.model)
        values=list(original.benchmark.iter(self.X+'Value'))
        names=[_identifier(original,v,'parameter') for v in values]
        self.assertEqual(len(set(names)),len(values))
        self.assertTrue(all(len(n)<=64 for n in names))
        other=deepcopy(self.model)
        self.assertEqual(names,list(reversed([_identifier(other,v,'parameter') for v in reversed(values)])))
        first=ET.Element('thing',id='a-b',comment='same')
        second=ET.Element('thing',id='a_b',comment='same')
        _identifier(original,first,'test')
        with self.assertRaisesRegex(ValueError,'ambiguous source-derived'):_identifier(original,second,'test')

    def test_active_directory_followup_preserves_all_manual_choices(self):
        path=self.source.parent/'U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip'
        docs,trace,ledger=recover_benchmark(schema_root=self.schema,source=path,
            sha256_pin='94740b7929dd868043ab1b476c3b568712fc26d045a4d450359cea90effbfa1c')
        self.assertEqual(ledger['summary']['statuses'],{'AUTOMATED_DRAFT':17,'MANUAL':19})
        self.assertEqual(ledger['summary']['manual_choices'],36)
        self.assertEqual(len(docs),91)
        self.assertFalse(any(row['blockers'] for row in ledger['rules']))
        self.assertEqual(len(trace['source_rule_records']),36)

    def test_focused_recovery_keeps_original_denominator_and_profiles(self):
        rid=next(r for r in self.model.rules if 'SV-241989' in r)
        docs,trace,ledger=recover_benchmark(schema_root=self.schema,source=self.source,sha256_pin=PIN,rule_ids=[rid])
        self.assertEqual(ledger['original_source_rules'],21)
        self.assertEqual(ledger['summary']['source_rules'],1)
        self.assertEqual(ledger['summary']['statuses'],{'AUTOMATED_DRAFT':1})
        self.assertEqual(len(docs),5)
        self.assertTrue(all(set(p['selected'])=={rid} for p in trace['profiles']))
        with self.assertRaisesRegex(ValueError,'distinct resolved'):
            recover_benchmark(schema_root=self.schema,source=self.source,sha256_pin=PIN,rule_ids=[rid,rid])

    def test_unknown_selector_is_explicitly_blocked(self):
        model=deepcopy(self.model)
        rule=next(r for k,r in model.rules.items() if 'SV-241989' in k)
        check=next(c for c in rule.findall(self.X+'check') if c.get('selector')=='automated')
        check.set('selector','unapproved-selector')
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'controlled.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr(model.member,ET.tostring(model.root))
            _,_,ledger=recover_benchmark(schema_root=self.schema,source=p,sha256_pin=sha256(p.read_bytes()).hexdigest())
        row=next(r for r in ledger['rules'] if 'SV-241989' in r['source_rule'])
        self.assertEqual(row['status'],'BLOCKED')
        self.assertTrue(any('selector' in b for b in row['blockers']))

    def test_source_exemplar_keeps_explicit_test_counts_and_integer_default(self):
        from v04_direct_scap_source import OVAL
        binding=next(r for r in self.trace['rules'] if 'SV-241989' in r['source_rule'])
        assessment=next(d['assessment'] for d in self.docs.values()
                        if d.get('assessment',{}).get('id')==binding['assessment'])
        names={r['source_id']:r['native_id'] for r in binding['authoring_contract_migration']['native_identity_sources'] if r['kind']=='test'}
        found={'at_least_one_exists':'one_or_more','none_exist':'none','only_one_exists':'exactly_one'}
        matching={'all':'every','at least one':'one_or_more','none satisfy':'none','only one':'exactly_one'}
        for source_id,native_id in names.items():
            original=self.model.nodes[binding['component']][source_id]
            counts=assessment['tests'][native_id]['require']['item_requirement']
            self.assertEqual(counts['items_found'],found[original.get('check_existence','at_least_one_exists')])
            if original.findall('{'+OVAL+'#windows}state'):
                self.assertEqual(counts['items_satisfying'],matching[original.get('check')])
            else:self.assertNotIn('items_satisfying',counts)
        parameter,=binding['policy_parameters'].values()
        self.assertEqual(parameter['datatype'],'integer')
        self.assertIs(type(parameter['value']),int)
        self.assertEqual(parameter['value'],1)
        self.assertTrue(names)
        # This is a bounded source-control assertion, not complete OVAL proof.
        self.assertFalse(self.trace['qualification']['independent_source_proof'])

    def test_wrong_source_pin_rejects(self):
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
            recover_benchmark(schema_root=self.schema,source=self.source,sha256_pin='0'*64)

if __name__=='__main__':unittest.main()
