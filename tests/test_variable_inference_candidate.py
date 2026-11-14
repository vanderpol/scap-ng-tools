"""Owner-approved native Variable datatype inference (pre-release schema candidate).

These tests exercise the semantic core without falsely claiming that the
still-pinned old converter schema pack has already been regenerated.
"""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from scap_ng_tools.converter import direct04
from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic


class _CandidateSchema:
    # The coordinated canonical PR removes declaration-level datatype;
    # these tests isolate semantic inference from the old pinned schema files.
    def iter_errors(self, declaration):
        return iter(())


class VariableInference(unittest.TestCase):
    def infer(self, variables):
        with patch.object(semantic, 'declaration_validator', return_value=_CandidateSchema()):
            return semantic.assessment_variable_expressions({'variables': variables})

    def test_function_results_and_aliases_are_typed_by_expression(self):
        variables = {
            'count-variable': {'kind':'local','expression':{'count':{'literal':['a','a','b']}}},
            'alias-variable': {'kind':'local','expression':{'variable':'count-variable'}},
            'split-variable': {'kind':'local','expression':{'split':{
                'delimiter':',','value':{'literal':'a,b'}}}},
            'sum-variable': {'kind':'local','expression':{'arithmetic':{
                'arithmetic_operation':'add','values':[{'literal':1},{'literal':1.5}]}}},
            'unique-variable': {'kind':'local','expression':{'unique':{'literal':[1,1,2]}}},
            'string-variable': {'kind':'constant','expression':{'literal':'001'}},
            'zero-count-variable': {'kind':'local','expression':{'count':{'literal':[]}}},
        }
        values = self.infer(variables)
        self.assertEqual(values['count-variable'],'integer')
        self.assertEqual(values['alias-variable'],'integer')
        self.assertEqual(values['split-variable'],'string')
        self.assertEqual(values['sum-variable'],'float')
        self.assertEqual(values['unique-variable'],'integer')
        self.assertEqual(values['string-variable'],'string')
        self.assertEqual(values['zero-count-variable'],'integer')

    def test_ambiguous_empty_requires_typed_payload(self):
        with self.assertRaisesRegex(ValueError,'ambiguous/empty'):
            self.infer({'empty-variable':{'kind':'constant','expression':{'literal':[]}}})
        self.assertEqual(self.infer({'empty-variable':{
            'kind':'constant','expression':{'literal':{'datatype':'string','value':[]}}
        }})['empty-variable'],'string')

    def test_values_use_collected_item_domain_not_oval_state_domain(self):
        # OVAL shellcommand State stdout_line accepts AnySimple comparison
        # datatypes, but the collected Item stdout_line is always string.
        # Variable inference must use the latter and must not use the source
        # declaration as a cast.
        from types import SimpleNamespace
        from unittest.mock import patch
        fake_schema = SimpleNamespace(schema_root=Path('.'))
        generated = {'fields': {'stdout_line': ['string', 'integer']},
                     'records': [], 'selectors': {}, 'native': {}}
        mapping = {'native': {'field_datatypes': {'stdout_line': ['string']}}}
        values_object = {'capability': 'independent.shellcommand', 'command': 'printf x'}
        variables = {'line': {'kind': 'local', 'expression': {'values': {
            'object': values_object, 'field': 'stdout_line'}}}}
        with patch.object(semantic, 'declaration_validator', return_value=_CandidateSchema()), \
             patch.object(semantic, 'snapshot', return_value=fake_schema), \
             patch.object(semantic, 'contract', return_value=(generated['fields'], set(), {}, generated['native'])), \
             patch.object(semantic, 'capability_contract', return_value=(mapping, generated)), \
             patch('scap_ng_tools.converter._v04_semantic.v04_object_contract.object_validator',
                   return_value=SimpleNamespace(iter_errors=lambda _: iter(()))):
            self.assertEqual(self.infer(variables)['line'], 'string')

    def test_values_do_not_guess_unknown_item_domain(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        generated = {'fields': {'value': ['string', 'integer']}, 'records': [],
                     'selectors': {}, 'native': {}}
        mapping = {'native': {'field_datatypes': {}}}
        variables = {'value': {'kind': 'local', 'expression': {'values': {
            'object': {'capability': 'windows.registry'}, 'field': 'value'}}}}
        with patch.object(semantic, 'declaration_validator', return_value=_CandidateSchema()), \
             patch.object(semantic, 'snapshot', return_value=SimpleNamespace(schema_root=Path('.'))), \
             patch.object(semantic, 'contract', return_value=(generated['fields'], set(), {}, generated['native'])), \
             patch.object(semantic, 'capability_contract', return_value=(mapping, generated)), \
             patch('scap_ng_tools.converter._v04_semantic.v04_object_contract.object_validator',
                   return_value=SimpleNamespace(iter_errors=lambda _: iter(()))):
            with self.assertRaisesRegex(ValueError, 'lacks an explicit Item datatype'):
                self.infer(variables)

    def test_no_numeric_lexical_guess_or_implicit_cast(self):
        with self.assertRaisesRegex(ValueError,'numeric operands'):
            self.infer({'bad-variable':{'kind':'local','expression':{'arithmetic':{
                'arithmetic_operation':'add','values':[{'literal':'001'},{'literal':1}]}}}})
        with self.assertRaisesRegex(ValueError,'cyclic'):
            self.infer({'a-variable':{'kind':'local','expression':{'variable':'b-variable'}},
                        'b-variable':{'kind':'local','expression':{'variable':'a-variable'}}})
        with self.assertRaisesRegex(ValueError,'unresolved'):
            self.infer({'a-variable':{'kind':'local','expression':{'variable':'missing-variable'}}})

    def test_converter_omits_native_declaration_datatype(self):
        engine = direct04.load_runtime()
        element = ET.fromstring(
            '<local_variable xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" datatype="int">'
            '<count><literal_component datatype="string">a</literal_component></count></local_variable>')
        visitor = engine.AssessmentConverter(None,'test-component',[])
        visitor.native_variable_datatype_required = False
        visitor.native_name = lambda node,kind: 'count-variable'
        visitor.function = lambda node: {'count':{'literal':['a','a']}}
        result = visitor.convert_variable(element)
        self.assertEqual(result,{'variable':'count-variable'})
        self.assertEqual(visitor.variables['count-variable'],{
            'kind':'local','expression':{'count':{'literal':['a','a']}}})
        self.assertNotIn('datatype',visitor.variables['count-variable'])

    def test_versioned_snapshot_and_declared_grammar_are_explicit(self):
        root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not root:
            self.skipTest('Generate and pass the pinned 0.4.1 schema pack')
        from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot
        snapshot = Pinned041SchemaSnapshot(root)
        self.assertEqual(snapshot.manifest()['schema_version'], '0.4.1')
        self.assertEqual(snapshot.manifest()['supported_capability_count'], 100)
        declaration = json.loads((snapshot.schema_root / 'variable-expression.schema.json').read_text())['$defs']['declaration']
        self.assertNotIn('datatype', declaration['properties'])
        self.assertEqual(direct04.load_pinned_snapshot(root).manifest()['schema_version'], '0.4.1')
        schema=json.loads((Path(root)/'variable-expression.schema.json').read_text())
        self.assertEqual(schema['$id'], 'https://scap-ng.dev/schema/v0.4.1/variable-expression.schema.json')
        self.assertEqual(schema['$defs']['declaration']['required'], ['kind','expression'])

    def test_exact_canonical_candidate_schema_accepts_converter_output(self):
        # Separate cross-repo CI pins the exact owner-approved candidate. The
        # historical 0.4 snapshot remains fully qualified by the old gate.
        root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not root:
            self.skipTest('Set SCAP_NG_SCHEMA_ROOT for cross-repo candidate validation')
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        schema_root = Path(root)
        resources = {}
        for path in schema_root.glob('*.schema.json'):
            document = json.loads(path.read_text())
            resource = Resource.from_contents(document)
            resources[document['$id']] = resource
            resources['https://scap-ng.dev/schema/v0.4.1/' + path.name] = resource
        declaration_schema = json.loads((schema_root / 'variable-expression.schema.json').read_text())
        validator = Draft202012Validator(declaration_schema,
                                         registry=Registry().with_resources(resources.items()))
        engine = direct04.load_runtime()
        element = ET.fromstring(
            '<local_variable xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" datatype="int">'
            '<count><literal_component datatype="string">a</literal_component></count></local_variable>')
        class Source:
            native_variable_datatype_required = False
        visitor = engine.AssessmentConverter(Source(),'test-component',[])
        visitor.native_name = lambda node,kind: 'count-variable'
        visitor.function = lambda node: {'count':{'literal':['a','a']}}
        visitor.convert_variable(element)
        validator.validate(visitor.variables['count-variable'])
        self.assertEqual(visitor.variables['count-variable']['kind'], 'local')
        self.assertNotIn('datatype', visitor.variables['count-variable'])
        with self.assertRaises(Exception):
            validator.validate({'kind':'local','datatype':'integer',
                                'expression':{'count':{'literal':['a','a']}}})

    def test_native_declaration_keeps_inferred_shape(self):
        engine = direct04.load_runtime()
        element = ET.fromstring(
            '<local_variable xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" datatype="int">'
            '<count><literal_component datatype="string">a</literal_component></count></local_variable>')
        visitor = engine.AssessmentConverter(None,'test-component',[])
        visitor.native_name = lambda node,kind: 'count-variable'
        visitor.function = lambda node: {'count':{'literal':['a']}}
        visitor.convert_variable(element)
        self.assertEqual(visitor.variables['count-variable'],{
            'kind':'local',
            'expression':{'count':{'literal':['a']}}})

    def test_source_typed_constants_remain_typed_literal_payloads(self):
        engine = direct04.load_runtime()
        element = ET.fromstring(
            '<constant_variable xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" datatype="string"/>')
        class Source:
            def node(self,*args):
                return element
        visitor = engine.AssessmentConverter(Source(),'test-component',[])
        visitor.native_variable_datatype_required = False
        visitor.renamed_enum_projection=lambda _:False
        visitor.reference=lambda *args: ['001','002']
        visitor.native_name=lambda node,kind:'constant-variable'
        self.assertEqual(visitor.named_variable('source-id'),'constant-variable')
        self.assertEqual(visitor.variables['constant-variable'],{
            'kind':'constant','expression':{'literal':{
                'datatype':'string','value':['001','002']}}})


if __name__=='__main__':
    unittest.main()
