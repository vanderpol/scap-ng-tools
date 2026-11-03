"""Admit only Value operators already expressed by every real OVAL consumer."""
import os
from pathlib import Path
import unittest
from scap_ng_tools.converter.recovery04 import recover_benchmark
from scap_ng_tools.authoring.input_discovery import input_locations

PINS=[('U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip',
       'ecba937d43efc0a72037eefb501b46a2e417158088b2f2699f2c86b68bd1de9c',14,'SV-226330'),
      ('U_MS_Windows_2012_and_2012_R2_MS_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip',
       '3ad256b29d6f85fe69ba9a14b18502a6f50e923faea2880d9ce10246f780a50a',15,'SV-225507'),
      ('U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip',
       '76cf6a14fefd077136d9a23a6ba4a30c82a0b254adc8cf2abd88592dc30776a8',5,None)]


class RedundantValueOperators(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema=os.environ.get('SCAP_NG_SCHEMA_ROOT');root=os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not root:raise unittest.SkipTest('Pinned public schema and original signed fixtures required')
        import json
        selected=json.loads((Path(__file__).parent/'fixtures/recovery-value-operator-rule-pins.json').read_text())
        cls.results=[]
        for filename,pin,admitted,conflict in PINS:
            source=Path(root)/filename
            ids=selected[filename]
            docs,trace,ledger=recover_benchmark(schema_root=schema,source=source,sha256_pin=pin,rule_ids=ids)
            cls.results.append((docs,trace,ledger,admitted,conflict))

    def test_34_source_rules_retain_actual_predicate_operator_and_scope(self):
        total=0
        native_ops={'greater than or equal':'greater_than_or_equal','less than or equal':'less_than_or_equal'}
        for docs,trace,ledger,admitted,conflict in self.results:
            self.assertEqual(ledger['summary']['automated_draft'],admitted)
            total+=admitted
            assessments={d['assessment']['id']:d['assessment'] for d in docs.values() if 'assessment' in d}
            for binding in trace['rules']:
                a=assessments[binding['assessment']]
                for warning in binding.get('conversion_warnings',[]):
                    op=warning.get('source_value_operator','equals')
                    if op=='equals':continue
                    self.assertEqual(warning['operator_validation'],'exact_actual_consumer_agreement')
                    sites=[s for s in input_locations(a) if s['input']==warning['input']]
                    self.assertTrue(sites)
                    self.assertTrue(all(s['source_path'].endswith('/'+native_ops[op]+'/input') for s in sites))
            self.assertFalse(ledger['summary']['scanner_executed'])
            self.assertFalse(ledger['summary']['independently_source_proved'])
        self.assertEqual(total,34)

    def test_two_disagreements_stay_blocked_without_changing_source_default(self):
        count=0
        for docs,trace,ledger,admitted,conflict in self.results:
            if conflict is None:continue
            row=next(r for r in ledger['rules'] if conflict in r['source_rule'])
            self.assertEqual(row['status'],'BLOCKED')
            self.assertFalse(row['rule_emitted'])
            self.assertTrue(row['manual'])
            self.assertTrue(any('disagrees with actual OVAL consumers' in e for e in row['blockers']))
            self.assertTrue(any('source default choice unavailable' in e for e in row['blockers']))
            self.assertTrue(any(d.get('assessment',{}).get('id')==conflict.lower()+'-manual-assessment' for d in docs.values()))
            count+=1
        self.assertEqual(count,2)

if __name__=='__main__':unittest.main()
