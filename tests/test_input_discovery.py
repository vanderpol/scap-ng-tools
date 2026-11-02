"""Pure native discovery index; no validation/scanner claim from derivation alone."""
from copy import deepcopy
import unittest
from scap_ng_tools.authoring.input_discovery import derive_choice,input_locations


class NativeInputDiscovery(unittest.TestCase):
    def test_real_refs_guards_escaped_fields_and_literal_data(self):
        for name in ('a/b~c','description','constraints','title','literal','input','input_provided'):
            a={'inputs':{'value-input':{'required':False}},
               'tests':{'record-test':{'require':{'fields':{'value':{'record':{'fields':{name:{'equals':{'input':'value-input'}}}}}}}}},
               'variables':{'data-variable':{'expression':{'literal':{'datatype':'record','value':{'input':'not-a-reference-input'}}}}},
               'evaluate':{'if':{'input_provided':'value-input'}}}
            before=deepcopy(a);rows=derive_choice(a,{'value-input':'parameter'},{'parameter':{'resolution':'organization'}})
            self.assertEqual(a,before);self.assertEqual(len(rows),1);self.assertFalse(rows[0]['required'])
            self.assertEqual(len(rows[0]['uses']),2)
            path='/tests/record-test/require/fields/value/record/fields/'+name.replace('~','~0').replace('/','~1')+'/equals/input'
            self.assertIn({'kind':'value','source_path':path},rows[0]['uses'])
            self.assertEqual(len(input_locations(a)),2)

    def test_shared_parameter_requirement_and_publisher_exclusion(self):
        a={'inputs':{'first-input':{'required':False},'second-input':{'required':True}},
           'evaluate':{'if':{'input_provided':'first-input'},'then':{'input_provided':'second-input'}}}
        row=derive_choice(a,{'first-input':'parameter','second-input':{'parameter':'parameter'}},{'parameter':{'resolution':'organization'}})[0]
        self.assertTrue(row['required']);self.assertEqual(len(row['uses']),2)
        self.assertEqual(derive_choice(a,{'first-input':'parameter'},{'parameter':{'resolution':'publisher'}}),[])


if __name__=='__main__':unittest.main()
