"""The published active-candidate pair is one exact, reasoned candidate."""
import gzip, hashlib, json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence/issue28'

class Issue28PublicationPins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads((EVIDENCE/'ACTIVE-CANDIDATE-LEDGER.json').read_text())
        with gzip.open(EVIDENCE/'ACTIVE-CANDIDATE-RULES.json.gz','rt',encoding='utf-8') as stream:
            cls.rules = json.load(stream)
    def test_pair_has_one_exact_candidate_pin_and_digest(self):
        self.assertEqual(self.ledger['candidate'], self.rules['candidate'])
        core = {k:self.rules[k] for k in ('format','scope','rules')}
        digest = hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()+b'\n').hexdigest()
        self.assertEqual(digest, self.ledger['candidate']['candidate_digest'])
        self.assertEqual(self.ledger['candidate']['source_commit'], '8c8e5dff860af6b1290ee9273a282db24278f8d5')
        self.assertEqual(self.ledger['candidate']['schema_commit'], '919732d4c570b521edf82196a7694dfd8c27fe50')
        self.assertEqual(self.ledger['candidate']['schema_family_sha256'], '6bf2fa369fd7b9a0153899ac25109af3e3f9aa59c0f4aa6bb3be1aebd5b14fa0')
    def test_all_excluded_and_blocked_rules_have_explicit_reasons(self):
        self.assertEqual(len(self.ledger['blocked_rule_reasons']), 108)
        self.assertEqual(len(self.ledger['excluded_rule_reasons']), 209)
        for row in self.rules['rules']:
            if row['status'] in ('blocked','intentionally_excluded'):
                self.assertTrue(row.get('disposition_reason'), row['source_rule'])
    def test_candidate_counts_remain_mutually_exclusive(self):
        self.assertEqual(self.ledger['classification'], {'automated_converted_proved':0,'automated_converted_unproved':6479,'manual_only':1403,'genuinely_blocked':108,'intentionally_excluded':209})
        self.assertEqual(len(self.rules['rules']),8199)

if __name__=='__main__': unittest.main()
