"""Current source-first crosswalk pins and honest proof boundary."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CurrentSourceCrosswalkReceipt(unittest.TestCase):
    def test_current_pins_and_dispositions_are_explicit(self):
        receipt = json.loads((ROOT / 'docs/evidence/issue83/source-crosswalk-current-20261122.json').read_text())
        self.assertEqual(receipt['source']['archives'], 65)
        self.assertEqual(receipt['source']['rules'], 8892)
        self.assertEqual(receipt['canonical']['commit'], 'f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2')
        self.assertEqual(receipt['canonical']['schema_family_sha256'],
                         '11b5ae735dd0a7a1db496b421e0d12f757c027f734da688c2b1d96940f4c47dc')
        self.assertEqual(receipt['oval']['commit'], '2f140ee5c5dd1ed9606fcd5afc301f6baeb48706')
        self.assertEqual(receipt['oval']['unclassified_declarations'], 0)
        self.assertEqual(receipt['oval']['unresolved_schema_references'], 0)
        self.assertEqual(receipt['oval']['unresolved_schema_dependencies'], 0)
        self.assertEqual(receipt['xccdf']['malformed_publisher_payload_rules'], 25)
        self.assertEqual(receipt['proof'],
                         'schema/XCCDF inventory and source identity only; no structural conversion, RI execution, or independent OVAL equivalence claim')
