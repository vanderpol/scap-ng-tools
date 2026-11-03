"""Three pinned real OVAL subgraphs, separate from whole-Rule admission."""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET
from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter.recovery04 import _classes
from scap_ng_tools.converter._v04_semantic import selected_schema
from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import assessment_variable_expressions


class SourceFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema=os.environ.get('SCAP_NG_SCHEMA_ROOT');root=os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not root:raise unittest.SkipTest('Exact public schema and signed sources required')
        cls.snapshot=FrozenSchemaSnapshot(schema);cls.root=Path(root);cls.engine=load_runtime()
        cls.pins=json.loads((Path(__file__).parent/'fixtures/function-source-pins.json').read_text())
        cls.Source,cls.Visitor=_classes(cls.engine)

    def visitor(self, row):
        model=self.Source(self.root/row['filename'],row['sha256'],inventory_broken_references=True,draft_compatibility=True)
        cid=next(cid for cid,nodes in model.nodes.items() if row['variable'] in nodes)
        return self.Visitor(model,cid,self.snapshot.supported_mappings(self.engine.CAPABILITIES)),model.nodes[cid][row['variable']][0]

    def test_original_options_order_dynamic_objects_and_complete_subgraph_types(self):
        for row in self.pins:
            with self.subTest(function=row['function']):
                visitor,element=self.visitor(row);original=ET.tostring(element)
                expr=visitor.function(element);fn=expr['function']
                self.assertEqual(fn['name'],row['function'])
                expected={k:int(v) if k.startswith('substring_') else v for k,v in element.attrib.items()}
                self.assertEqual(fn['options'],expected)
                self.assertEqual(len(fn['arguments']),len(element))
                for child,arg in zip(element,fn['arguments']):
                    self.assertIn('values',arg)
                    self.assertEqual(arg['values']['field'],child.get('item_field'))
                variables={**visitor.variables,'projected-function-variable':{'kind':'local',
                    'datatype':row['projection_datatype'],'expression':expr}}
                with selected_schema(self.snapshot):assessment_variable_expressions({'variables':variables,'shared_objects':visitor.shared_objects})
                self.assertEqual(ET.tostring(element),original)
                self.assertEqual(visitor.conversion_warnings[-1]['independent_static_proof'],'UNPROVED')
                if row['function']=='arithmetic':
                    # Original local_variable declares string; numeric-only new
                    # result cannot silently acquire its legacy lexical cast.
                    variables['projected-function-variable']['datatype']='string'
                    with selected_schema(self.snapshot),self.assertRaises(ValueError):
                        assessment_variable_expressions({'variables':variables,'shared_objects':visitor.shared_objects})

    def test_bad_source_options_arities_and_namespace_reject(self):
        visitor,_=self.visitor(self.pins[0])
        namespace='http://oval.mitre.org/XMLSchema/oval-definitions-5'
        for text in ('<arithmetic arithmetic_operation="divide"><literal_component datatype="int">1</literal_component><literal_component datatype="int">2</literal_component></arithmetic>',
                     '<arithmetic arithmetic_operation="add"><literal_component datatype="int">1</literal_component></arithmetic>',
                     '<substring substring_start="2147483648" substring_length="1"><literal_component>x</literal_component></substring>',
                     '<substring substring_start="1.0" substring_length="1"><literal_component>x</literal_component></substring>',
                     '<split><literal_component>x</literal_component></split>',
                     '<split delimiter="," flags="g"><literal_component>x</literal_component></split>'):
            element=ET.fromstring(text)
            for node in element.iter():node.tag='{'+namespace+'}'+node.tag
            with self.subTest(source=text),self.assertRaises(ValueError):visitor.function(element)
        element=ET.fromstring('<split xmlns="urn:wrong" delimiter=","/>')
        with self.assertRaisesRegex(ValueError,'namespace'):visitor.function(element)

    def test_direct_input_function_composition_stays_blocked(self):
        visitor,_=self.visitor(self.pins[0])
        visitor.reference=lambda *args:{'input':'unapproved-input'}
        element=ET.fromstring('<split xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" delimiter=","><variable_component var_ref="source"/></split>')
        with self.assertRaisesRegex(ValueError,'Input function composition'):visitor.function(element)
