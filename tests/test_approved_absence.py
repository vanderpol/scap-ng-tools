"""Bounded owner corrections, source guards and preserved manual methods."""
from collections import defaultdict
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter.recovery04 import _classes,recover_benchmark
from scap_ng_tools.converter.approved_absence import approved_visitor,RULE
from scap_ng_tools.converter.approved_absence_cases import CASES

BASE=Path(__file__).resolve().parents[1]


class ApprovedAbsence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema=os.environ.get('SCAP_NG_SCHEMA_ROOT');sources=os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not sources:raise unittest.SkipTest('Pinned schema and original signed sources required')
        cls.snapshot=FrozenSchemaSnapshot(schema);cls.sources=Path(sources);cls.engine=load_runtime()
        cls.pins=json.loads((BASE/'tests/fixtures/issue14-absence-pins.json').read_text())
        cls.before={r['source_rule']:r for r in json.loads((BASE/'docs/evidence/issue14-absence/investigation.json').read_text())['cases']}
        cls.Source,cls.Visitor=_classes(cls.engine);groups=defaultdict(list);cls.models={};cls.results=[]
        for row in cls.pins:groups[row['filename']].append(row)
        for filename,rows in groups.items():
            source=cls.sources/filename;pin=rows[0]['sha256']
            cls.models[pin]=cls.Source(source,pin,inventory_broken_references=True,draft_compatibility=True)
            cls.results.append(recover_benchmark(schema_root=schema,source=source,sha256_pin=pin,
                rule_ids=[r['source_rule'] for r in rows],approved_absence_corrections=True))

    def test_exact_seven_case_authorization_manifest_matches_prior_independent_inventory(self):
        self.assertEqual(set(CASES),set(self.before)-{RULE})
        for rid,case in CASES.items():
            old=self.before[rid]
            self.assertEqual(case['source_zip_sha256'],old['source_zip_sha256'])
            self.assertEqual(case['source_rule_sha256'],old['source_rule_sha256'])
            self.assertEqual((case['component'],case['definition']),(old['component'],old['definition']))
            self.assertEqual(case['source_nodes'],{k:v['parsed_node_sha256'] for k,v in old['closure'].items()})
            self.assertEqual(case['field_sha256'],old['absence_fields'][0]['parsed_node_sha256'])

    def test_eight_corrected_drafts_preserve_manuals_defaults_provenance_and_unproved_flags(self):
        from v04_direct_scap_source import digest
        seen=[]
        for docs,trace,ledger in self.results:
            self.assertTrue(trace['approved_absence_corrections_enabled'])
            self.assertTrue(ledger['approved_absence_corrections_enabled'])
            for row in ledger['rules']:
                rid=row['source_rule'];old=self.before[rid];seen.append(rid)
                self.assertEqual(row['status'],'AUTOMATED_DRAFT');self.assertTrue(row['owner_normalized'])
                self.assertFalse(row['compiled'] or row['independent_source_proof'] or row['scanner_execution'])
                manual=next(d for d in docs.values() if d.get('assessment',{}).get('id')==old['manual_assessment'])
                self.assertEqual(digest(manual),old['manual_document_sha256'])
                binding=next(b for b in trace['rules'] if b['source_rule']==rid)
                warnings=[w for w in binding['conversion_warnings'] if w.get('source_correction')]
                self.assertEqual(len(warnings),1);warning=warnings[0]
                self.assertEqual(json.loads(json.dumps(warning['source_entity'])),old['absence_fields'][0]['parsed_node'])
                self.assertEqual(warning['native_predicate'],{'values_found':'none'})
                self.assertEqual(warning['independent_static_proof'],'UNPROVED')
                rule=next(d['rule'] for d in docs.values() if d.get('rule',{}).get('id')==binding['native_rule'])
                self.assertEqual(rule['default_assessment_choice'],'automated')
                self.assertEqual(set(rule['assessment_choices']),{'automated','manual'})
        self.assertCountEqual(seen,list(self.before))

    def test_every_rule_and_closure_node_is_rechecked_after_attestation(self):
        for rid,case in CASES.items():
            for ident in case['source_nodes']:
                model=deepcopy(self.models[case['source_zip_sha256']]);cid=case['component']
                Enabled=approved_visitor(self.Visitor,model,rid)
                visitor=Enabled(model,cid,self.snapshot.supported_mappings(self.engine.CAPABILITIES))
                state=model.nodes[cid][case['state']];field=state[0];mapping=visitor.capability(state,'state')
                model.nodes[cid][ident].set('unapproved','changed')
                with self.subTest(rule=rid,node=ident),self.assertRaisesRegex(ValueError,'source node changed'):
                    visitor.predicate(field,mapping)
                with self.assertRaises(ValueError):approved_visitor(self.Visitor,model,rid)
            model=deepcopy(self.models[case['source_zip_sha256']]);model.rules[rid].set('weight','2')
            with self.assertRaisesRegex(ValueError,'Rule changed'):approved_visitor(self.Visitor,model,rid)

    def test_unapproved_pins_rules_contexts_and_similar_fields_never_activate(self):
        for rid,case in CASES.items():
            model=deepcopy(self.models[case['source_zip_sha256']]);model.zip_sha256='0'*64
            self.assertIs(approved_visitor(self.Visitor,model,rid),self.Visitor)
            model=self.models[case['source_zip_sha256']]
            self.assertIs(approved_visitor(self.Visitor,model,'unapproved-rule'),self.Visitor)
            cid=case['component'];state=model.nodes[cid][case['state']];field=state[0]
            visitor=approved_visitor(self.Visitor,model,rid)(model,cid,self.snapshot.supported_mappings(self.engine.CAPABILITIES))
            mapping=visitor.capability(state,'state')
            for options in ({'selector':True},{'record_field':True}):
                with self.subTest(rule=rid,options=options),self.assertRaises(ValueError):
                    visitor.predicate(field,mapping,**options)
            changed=deepcopy(field);changed.text='.+'
            with self.assertRaises(ValueError):visitor.predicate(changed,mapping)

    def test_oracle_documents_and_warning_stay_identical_with_both_explicit_profiles(self):
        old=self.before[RULE]
        args=dict(schema_root=self.snapshot.schema_root,source=self.sources/old['filename'],
                  sha256_pin=old['source_zip_sha256'],rule_ids=[RULE])
        docs,trace,_=recover_benchmark(**args,approved_oracle_absence=True)
        combined,combined_trace,_=recover_benchmark(**args,approved_oracle_absence=True,approved_absence_corrections=True)
        self.assertEqual(docs,combined)
        self.assertEqual(trace['rules'],combined_trace['rules'])


if __name__=='__main__':unittest.main()
