"""Independent small graph expectations and committed audit integrity."""
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import unittest
import yaml

BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rhel9_metric',BASE/'scripts/audit_rhel9_complexity.py')
metric=importlib.util.module_from_spec(spec);spec.loader.exec_module(metric)

class ComplexityMetric(unittest.TestCase):
    def test_presentation_and_grouping_do_not_create_complexity(self):
        a={'tests':{'one':{'capability':'unix.file','object':{'full_path':{'equals':'/fixed'}},
            'require':{'items_found':'one_or_more'}}},'evaluate':{'test':'one'}}
        self.assertEqual(metric.metrics(a)['score'],4) # Test + equals + capability + existence.
        b=deepcopy(a);b['tests']['one']['test_title']='Object title is not a semantic operation'
        b['tests']['one']['object']['object_title']='metadata'
        req=b['tests']['one']['require'];req['item_requirement']={'items_found':req.pop('items_found')}
        self.assertEqual(metric.metrics(a),metric.metrics(b))

    def test_boolean_depth_is_not_test_count(self):
        a={'tests':{'a':{},'b':{},'c':{}},'evaluate':{'and':[{'test':'a'},{'or':[{'test':'b'},{'not':{'test':'c'}}]}]}}
        m=metric.metrics(a);self.assertEqual(m['boolean_depth'],3)
        self.assertEqual(m['parts']['boolean_nodes'],3);self.assertEqual(m['parts']['boolean_depth_excess'],2)

    def test_shared_collection_variable_chain_and_cross_test_coupling(self):
        a={'shared_objects':{'fixed':{'capability':'unix.file','full_path':{'equals':'/fixed'}}},
            'variables':{'v':{'expression':{'function':{'name':'count','arguments':[{'values':{'object':'fixed','field':'full_path'}}]}}}},
            'tests':{'producer':{'object':'fixed'},'consumer':{'variable':'v'}}}
        m=metric.metrics(a);self.assertEqual(m['collection_references'],2);self.assertEqual(m['unique_collections'],1)
        self.assertEqual(m['parts']['repeated_collections'],1);self.assertEqual(m['parts']['functions'],1)
        self.assertEqual(m['variable_function_chain_depth'],2)
        self.assertEqual(m['cross_test_edges'],[['producer','consumer','variable_collection_coupling']])

    def test_sets_filters_and_cycles_remain_visible(self):
        a={'tests':{'t':{'object':{'set':{'operator':'union','operands':[]},'filters':[{'exclude':{}},{'include':{}}]}}}}
        m=metric.metrics(a);self.assertEqual(m['set_count'],1);self.assertEqual(m['filter_count'],2)
        bad={'variables':{'v':{'expression':{'variable':'v'}}}}
        with self.assertRaisesRegex(ValueError,'cyclic'):metric.metrics(bad)

    def test_committed_complete_inventory_and_ten_byte_identified_pairs(self):
        root=BASE/'audits/rhel9-shellcommand'
        if not root.exists():self.skipTest('Audit artifacts not yet generated')
        inv=json.loads((root/'inventory.json').read_text());cases=json.loads((root/'candidates.json').read_text())['candidates']
        self.assertEqual(len(inv['rows']),415);self.assertEqual(len({r['id'] for r in inv['rows']}),415)
        self.assertEqual(len(cases),10);self.assertEqual(sum(inv['distribution'].values()),415)
        for c in cases:
            d=root/c['directory'];raw=(d/'original.yaml').read_bytes();proposed=(d/'proposed-UNAPPROVED.yaml').read_bytes()
            self.assertEqual(sha256(raw).hexdigest(),c['original_yaml_sha256'])
            self.assertEqual(sha256(proposed).hexdigest(),c['proposed_yaml_sha256'])
            self.assertEqual(metric.metrics(yaml.safe_load(raw)['assessment'])['score'],c['before_score'])
            self.assertEqual(metric.metrics(yaml.safe_load(proposed)['assessment'])['score'],c['after_score'])
            self.assertFalse(c['runtime_equivalence_proved']);self.assertEqual(c['disposition'],'REJECT_REPLACEMENT_SKETCH')
            self.assertTrue(c['manual_check_normalized_identical'])

if __name__=='__main__':unittest.main()
