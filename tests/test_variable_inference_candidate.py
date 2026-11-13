"""Owner-approved native Variable datatype inference (pre-release schema candidate).

These tests exercise the semantic core without falsely claiming that the
still-pinned old converter schema pack has already been regenerated.
"""
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

    def test_historical_schema_keeps_original_declaration_shape(self):
        engine = direct04.load_runtime()
        element = ET.fromstring(
            '<local_variable xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" datatype="int">'
            '<count><literal_component datatype="string">a</literal_component></count></local_variable>')
        visitor = engine.AssessmentConverter(None,'test-component',[])
        visitor.native_name = lambda node,kind: 'count-variable'
        visitor.function = lambda node: {'count':{'literal':['a']}}
        visitor.convert_variable(element)
        self.assertEqual(visitor.variables['count-variable'],{
            'kind':'local','datatype':'integer',
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
