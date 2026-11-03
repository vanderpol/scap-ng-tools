"""Function signature/collection boundaries; no runtime evaluation."""
from copy import deepcopy
import unittest
import os
from pathlib import Path
from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter._v04_semantic import selected_schema
from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import assessment_variable_expressions



def call(name, args, **options):
    return {'function': {'name': name, 'arguments': args, 'options': options}}


def declaration(expr, datatype='string', kind='local'):
    return dict(kind=kind, datatype=datatype, expression=expr)


class FunctionTypes(unittest.TestCase):
    def check(self, expr, datatype='string', additions=None, valid=True):
        variables={'example-variable':declaration(expr,datatype), **(additions or {})}
        before=deepcopy(variables)
        schema=os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not schema:self.skipTest('Exact public schema snapshot required')
        with selected_schema(FrozenSchemaSnapshot(schema)):
            if valid:assessment_variable_expressions({'variables':variables})
            else:
                with self.assertRaises(ValueError):assessment_variable_expressions({'variables':variables})
        self.assertEqual(before,variables)

    def test_cartesian_arrays_preserved_not_folded_or_zipped(self):
        self.check(call('arithmetic', [{'literal':[1,2]}, {'literal':[3,4,5]}], arithmetic_operation='add'),'integer')
        self.check(call('arithmetic', [{'variable':'empty-variable'}, {'literal':2}], arithmetic_operation='multiply'),'integer',
                   {'empty-variable':declaration({'literal':[]},'integer','constant')})
        self.check(call('arithmetic', [{'literal':1}, {'literal':2.5}], arithmetic_operation='multiply'),'float')
        self.check(call('arithmetic', [{'literal':1}, {'literal':2.5}], arithmetic_operation='multiply'),'integer',valid=False)

    def test_domains_no_boolean_text_or_record_coercion(self):
        for value in (True,'2',{'datatype':'record','value':{'function':'data'}}):
            self.check(call('arithmetic', [{'literal':1}, {'literal':value}], arithmetic_operation='add'),'integer',valid=False)
        for value in (1,False,{'datatype':'record','value':{'literal':'opaque'}}):
            self.check(call('split',[{'literal':value}],delimiter=':'),valid=False)
        self.check(call('substring',[{'variable':'number-variable'}],substring_start=1,substring_length=1),
                   additions={'number-variable':declaration({'literal':1},'integer','constant')},valid=False)

    def test_empty_strings_duplicates_literal_delimiter_and_negative_options_remain(self):
        self.check(call('split',[{'literal':['-a-a-','---','']}],delimiter='-'))
        self.check(call('split',[{'literal':'a.*b'}],delimiter='.*'))
        self.check(call('substring',[{'literal':['abcdefg','']}],substring_start=0,substring_length=-1))
        self.check(call('substring',[{'literal':'x'}],substring_start=2147483647,substring_length=-2147483648))
        # Out-of-range starts cannot be statically fabricated into empty/zero:
        # the unchanged AST is dispatched for runtime error handling.

    def test_nested_legacy_expressions_and_opaque_record_data(self):
        self.check({'unique':call('split',[{'concat':[{'literal':'-a'},{'literal':'-a-'}]}],delimiter='-')})
        self.check({'literal':{'datatype':'record','value':{'function':{'name':'count','arguments':[]}}}},'record')
        self.check(call('split',[{'input':'unapproved-input'}],delimiter=','),valid=False)
        self.check(call('count',[{'literal':'x'}]),valid=False)
        self.check(call('substring',[{'literal':'x'}],substring_start=True,substring_length=1),valid=False)


class FunctionInventory(unittest.TestCase):
    def test_ast_paths_and_literal_opacity(self):
        from scap_ng_tools.authoring.native_functions import function_inventory
        expr={'unique':call('split',[call('substring',[{'literal':'-a-a-'}],substring_start=0,substring_length=-1)],delimiter='-')}
        a={'variables':{'paths-variable':declaration(expr), 'opaque-variable':declaration(
            {'literal':{'datatype':'record','value':{'function':{'name':'count'}}}},'record')}}
        before=deepcopy(a);rows=function_inventory(a)
        self.assertEqual([r['name'] for r in rows],['split','substring'])
        self.assertEqual(rows[1]['source_path'],'/variables/paths-variable/expression/unique/function/arguments/0')
        self.assertEqual(a,before)
