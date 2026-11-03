"""Pinned absence witnesses and exact existing Oracle correction; no scanner."""
from collections import Counter,defaultdict
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest

from test_float_investigation import script
from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter.recovery04 import _classes,recover_benchmark
from scap_ng_tools.converter.approved_absence import oracle_visitor,RULE,PIN,NODES

BASE=Path(__file__).resolve().parents[1]


class AbsenceStatusWitnesses(unittest.TestCase):
    def test_independent_official_status_table_and_unresolved_empty_value_aggregate(self):
        root=os.environ.get('SCAP_NG_OVAL_ROOT')
        if not root:self.skipTest('Pinned official OVAL source required')
        result=script('absence_witnesses').witnesses(root)
        self.assertEqual(len(result['population_cases']),81)
        examples={(r['exists'],r['does_not_exist'],r['error'],r['not_collected']):r['existence_piece'] for r in result['population_cases']}
        self.assertEqual(examples[(0,0,0,0)],'true')
        self.assertEqual(examples[(0,1,0,0)],'true')
        self.assertEqual(examples[(1,0,1,1)],'false')
        self.assertEqual(examples[(0,0,1,1)],'error')
        self.assertEqual(examples[(0,0,0,1)],'unknown')
        self.assertEqual(result['empty_all_value_aggregate'],'NO_ROW_IN_PINNED_NORMATIVE_CHART')
        for row in result['lexical_cases']:
            self.assertTrue(row['universal_pattern_matches'])
            self.assertEqual(row['none_exist_piece'],'false')
        self.assertFalse(result['source_semantic_proof'] or result['scanner_execution'])


class SourceAbsenceReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema=os.environ.get('SCAP_NG_SCHEMA_ROOT');sources=os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not sources:raise unittest.SkipTest('Original eight signed cases and schema required')
        cls.snapshot=FrozenSchemaSnapshot(schema);cls.sources=Path(sources);cls.engine=load_runtime()
        cls.pins=json.loads((BASE/'tests/fixtures/issue14-absence-pins.json').read_text())
        cls.before,cls.probes=script('investigate_absence_cases').investigate(schema,sources)
        groups=defaultdict(list)
        for row in cls.pins:groups[row['filename']].append(row)
        cls.after=[]
        for filename,rows in groups.items():
            docs,trace,ledger=recover_benchmark(schema_root=schema,source=cls.sources/filename,
                sha256_pin=rows[0]['sha256'],rule_ids=[r['source_rule'] for r in rows],approved_oracle_absence=True)
            cls.after.append((docs,trace,ledger))

    def test_all_original_source_cases_are_exact_and_default_profile_stays_strict(self):
        self.assertEqual(len(self.before['cases']),8)
        self.assertEqual(len(self.probes['assessments']),8)
        self.assertFalse(self.probes['production_admitted'])
        for row in self.before['cases']:
            self.assertEqual(row['status_before'],'BLOCKED')
            self.assertTrue(row['manual_preserved'])
            self.assertEqual(len(row['absence_fields']),1)
            field=row['absence_fields'][0]
            self.assertEqual(field['attributes'],{'check_existence':'none_exist','operation':'pattern match'})
            self.assertEqual(field['lexical_value'],'.*')
            self.assertIn(field['parsed_node'][0].rsplit('}',1)[-1],('stdout_line','stderr_line'))
            self.assertFalse(row['source_semantic_proof'] or row['scanner_execution'])

    def test_only_existing_owner_corrected_oracle_case_is_admitted_and_manual_hashes_match(self):
        from v04_direct_scap_source import digest
        old={r['source_rule']:r for r in self.before['cases']};statuses=Counter()
        for docs,trace,ledger in self.after:
            for row in ledger['rules']:
                statuses[row['status']]+=1
                prior=old[row['source_rule']]
                manual=next(d for d in docs.values() if d.get('assessment',{}).get('id')==prior['manual_assessment'])
                self.assertEqual(digest(manual),prior['manual_document_sha256'])
                self.assertFalse(row['compiled'] or row['independent_source_proof'] or row['scanner_execution'])
                if row['source_rule']==RULE:
                    self.assertEqual(row['status'],'AUTOMATED_DRAFT')
                    rule=next(d['rule'] for d in docs.values() if 'rule' in d)
                    self.assertEqual(rule['default_assessment_choice'],'automated')
                    self.assertEqual(set(rule['assessment_choices']),{'manual','automated'})
                    warning=next(w for b in trace['rules'] for w in b.get('conversion_warnings',[])
                                 if w['code']=='approved_oracle_absence_20261024')
                    self.assertTrue(warning['source_correction'])
                    self.assertEqual(warning['source_entity'][2],'.*')
                    self.assertEqual(warning['native_predicate'],{'values_found':'none'})
                    self.assertEqual(warning['independent_static_proof'],'UNPROVED')
                else:
                    self.assertEqual(row['status'],'BLOCKED')
                    self.assertFalse(row['rule_emitted'])
        self.assertEqual(statuses,{'AUTOMATED_DRAFT':1,'BLOCKED':7})

    def source(self):
        Source,Visitor=_classes(self.engine);row=next(r for r in self.pins if r['source_rule']==RULE)
        model=Source(self.sources/row['filename'],PIN,inventory_broken_references=True,draft_compatibility=True)
        cid,_,_=model.automated_check(model.rules[RULE])
        return model,cid,Visitor

    def test_pin_rule_and_every_source_closure_node_are_mandatory(self):
        for ident in NODES:
            model,cid,Visitor=self.source();model.nodes[cid][ident].set('unapproved','changed')
            with self.subTest(node=ident),self.assertRaisesRegex(ValueError,'source node changed'):
                oracle_visitor(Visitor,model,RULE)
        model,cid,Visitor=self.source();model.rules[RULE].set('weight','2')
        with self.assertRaisesRegex(ValueError,'Rule changed'):oracle_visitor(Visitor,model,RULE)
        model,cid,Visitor=self.source();model.zip_sha256='0'*64
        self.assertIs(oracle_visitor(Visitor,model,RULE),Visitor)
        self.assertIs(oracle_visitor(Visitor,model,'another-rule'),Visitor)

    def test_context_and_post_attestation_mutation_never_widen_exception(self):
        model,cid,Visitor=self.source();Enabled=oracle_visitor(Visitor,model,RULE)
        visitor=Enabled(model,cid,self.snapshot.supported_mappings(self.engine.CAPABILITIES))
        parent=model.nodes[cid][next(k for k in NODES if ':ste:' in k)];field=parent[0]
        mapping=visitor.capability(parent,'state')
        for options in ({'selector':True},{'record_field':True}):
            with self.assertRaises(ValueError):visitor.predicate(field,mapping,**options)
        for text in ('^.*$','.+','unexpected'):
            changed=deepcopy(field);changed.text=text
            with self.assertRaises(ValueError):visitor.predicate(changed,mapping)
        field.text='.+'
        with self.assertRaisesRegex(ValueError,'source node changed'):visitor.predicate(field,mapping)


if __name__=='__main__':unittest.main()
