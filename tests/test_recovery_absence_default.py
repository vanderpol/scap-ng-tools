"""Pinned exact OVAL default projection; every broader absence remains strict."""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest
from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter.recovery04 import _classes,recover_benchmark


class AbsenceDefault(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema=os.environ.get('SCAP_NG_SCHEMA_ROOT');sources=os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not sources:raise unittest.SkipTest('Exact signed fixtures and canonical schema required')
        cls.snapshot=FrozenSchemaSnapshot(schema);cls.sources=Path(sources);cls.engine=load_runtime()
        cls.Source,cls.Visitor=_classes(cls.engine)
        cls.rows=json.loads((Path(__file__).parent/'fixtures/issue14-boundary-witnesses.json').read_text())
        cls.models={}
        for r in cls.rows.values():
            if r['filename'] not in cls.models:
                cls.models[r['filename']]=cls.Source(cls.sources/r['filename'],r['source_zip_sha256'],inventory_broken_references=True,draft_compatibility=True)

    def witness(self,name):
        from v04_direct_scap_source import digest,xml_identity
        row=self.rows[name];model=self.models[row['filename']];parent=model.nodes[row['component']][row['parent_id']]
        self.assertEqual(digest(xml_identity(parent)),row['parent_sha256'])
        node=parent[row['child_index']];self.assertEqual(json.loads(json.dumps(xml_identity(node))),row['node']);self.assertEqual(digest(xml_identity(node)),row['node_sha256'])
        visitor=self.Visitor(model,row['component'],self.snapshot.supported_mappings(self.engine.CAPABILITIES))
        return visitor,parent,node

    def test_pinned_upstream_base_type_explicitly_defaults_operation_to_equals(self):
        import xml.etree.ElementTree as ET
        oval=os.environ.get('SCAP_NG_OVAL_ROOT')
        self.assertTrue(oval,'Pinned official OVAL source is required for this default witness')
        root=ET.parse(Path(oval)/'oval-schemas/oval-definitions-schema.xsd').getroot()
        x={'x':'http://www.w3.org/2001/XMLSchema'}
        attribute=root.find("x:attributeGroup[@name='EntityAttributeGroup']/x:attribute[@name='operation']",x)
        self.assertIsNotNone(attribute)
        self.assertEqual(attribute.get('default'),'equals')
        self.assertEqual(attribute.get('use'),'optional')

    def test_real_empty_implicit_and_explicit_equals_have_same_ast_without_source_edits(self):
        for name in ('absence-positive','absence-equals-positive'):
            visitor,parent,node=self.witness(name);before=deepcopy(node)
            result=visitor.predicate(node,visitor.capability(parent,'state'))
            self.assertEqual(result,{'values_found':'none'});self.assertEqual(node.attrib,before.attrib);self.assertEqual(node.text,before.text)
            if name=='absence-equals-positive':
                self.assertEqual(visitor.conversion_warnings[-1]['source_attributes'],{'check_existence':'none_exist','operation':'equals'})
                self.assertEqual(visitor.conversion_warnings[-1]['independent_static_proof'],'UNPROVED')

    def test_exact_source_pattern_absence_and_float_remain_rejected_integer_projection_works(self):
        for name,message in [('pattern-absence-negative','comparator-bearing absence'),('float-negative','integer source datatype')]:
            visitor,parent,node=self.witness(name)
            with self.assertRaisesRegex(ValueError,message):visitor.predicate(node,visitor.capability(parent,'state'))
        visitor,parent,node=self.witness('integer-positive')
        self.assertEqual(visitor.predicate(node,visitor.capability(parent,'object'),selector=True),{'greater_than_or_equal':1})

    def test_deprecated_md5_mapping_error_is_not_a_free_alias(self):
        visitor,parent,node=self.witness('rpm-negative');mapping=visitor.capability(parent,'state')
        self.assertEqual(mapping['migration_crosswalk']['deprecated']['md5_differs'],'migration_error_replaced_by_filedigest_differs')
        with self.assertRaisesRegex(ValueError,'unsupported State field'):visitor.convert_state(parent)

    def test_extra_attributes_values_variables_selector_and_record_context_are_not_elided(self):
        visitor,parent,node=self.witness('absence-equals-positive');mapping=visitor.capability(parent,'state')
        for kind in ('text','datatype','entity-check','variable','pattern','selector','record'):
            wrong=deepcopy(node);options={}
            if kind=='text':wrong.text='unexpected'
            elif kind=='datatype':wrong.set('datatype','string')
            elif kind=='entity-check':wrong.set('entity_check','all')
            elif kind=='variable':wrong.set('var_ref','missing-variable')
            elif kind=='pattern':wrong.set('operation','pattern match');wrong.text='.*'
            elif kind=='selector':options['selector']=True
            else:options['record_field']=True
            with self.subTest(case=kind),self.assertRaises(ValueError):visitor.predicate(wrong,mapping,**options)

    def test_complete_rule_keeps_real_manual_choice_and_default_with_no_proof_upgrade(self):
        row=self.rows['absence-equals-positive']
        docs,trace,ledger=recover_benchmark(schema_root=self.snapshot.schema_root,source=self.sources/row['filename'],
            sha256_pin=row['source_zip_sha256'],rule_ids=['xccdf_mil.disa.stig_rule_SV-224994r958484_rule'])
        self.assertEqual(ledger['summary']['statuses'],{'AUTOMATED_DRAFT':1});self.assertEqual(len(docs),5)
        rule=next(d['rule'] for d in docs.values() if 'rule' in d)
        self.assertEqual(rule['default_assessment_choice'],'automated');self.assertEqual(set(rule['assessment_choices']),{'manual','automated'})
        a=next(d['assessment'] for d in docs.values() if d.get('assessment',{}).get('mode')=='automated')
        self.assertEqual(len(a['tests']),1)
        self.assertTrue(any(w['code']=='explicit_absence_equals_default' for w in trace['rules'][0]['conversion_warnings']))
        self.assertFalse(ledger['rules'][0]['compiled']);self.assertFalse(ledger['rules'][0]['independent_source_proof'])
        self.assertFalse(ledger['rules'][0]['scanner_execution'])
