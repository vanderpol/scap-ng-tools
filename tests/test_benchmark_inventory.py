"""Source-backed read-only inventory parity; no conversion/proof admission."""

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scap_ng_tools.converter import inventory_benchmark


PINS = [
    {
        'filename': 'server2025-signed.zip', 'count': 291,
        'sha': '2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0',
        'trace': '0558217d6c90a39bf7f0e9b9bf8f8235f391df4152be639968ac1d3e132f41ff',
        'manifest': 'b8e006eceeaca1d1e669e88d2f9336ea3ad165323409a2ff49f80e0641e9b238',
    },
    {
        'filename': 'U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip',
        'count': 36,
        'sha': '94740b7929dd868043ab1b476c3b568712fc26d045a4d450359cea90effbfa1c',
        'trace': 'a904fa7e88ff40bdea90825aac5d8b102a28fbd89d24b7c43b78aebe3b790824',
        'manifest': '9335f772f3cc5a1952c46d66b1087f17dbd2105ce975b4f9156f29fc96d8d719',
    },
    {
        'filename': 'U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip',
        'count': 187,
        'sha': '88cc35f98c9ff96c567110c284c06e6adfc556fd59967019bdec6fd1cc5a204f',
        'trace': 'af1acfc9a2a7454153f629e2e1a88823f794bfa99e5cc4b4aef2cba980c7f4e1',
        'manifest': '6b3cdccfda5097f549f7372ae95c661f88b03d2097e9ebce366c4d99e31d0823',
    },
    {
        'filename': 'U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip',
        'count': 21,
        'sha': 'd16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca',
        'trace': 'fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc',
        'manifest': 'f0ba480d3e3d2c61600e68cc1e34daecfc8fe90804912bde5b4484f4440921b4',
    },
]

PUBLIC_WINDOWS_NAME = ('U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_'
                       'Benchmark-enhancedV1-signed.zip')


def stable_digest(value):
    return sha256(json.dumps(value, sort_keys=True).encode('utf-8')).hexdigest()


class BenchmarkInventoryParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        primary = os.environ.get('SCAP_NG_SOURCE_FIXTURE')
        others = os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not all((schema, primary, others)):
            raise unittest.SkipTest('Select schema, original and three extra pinned source fixtures')
        cls.schema = Path(schema)
        cls.files = [Path(primary)] + [Path(others) / row['filename'] for row in PINS[1:]]

    def test_full_benchmark_inventories_match_pinned_original(self):
        count = 0
        for path, pin in zip(self.files, PINS):
            with self.subTest(source=path.name):
                if pin['filename'] == 'server2025-signed.zip':
                    self.assertIn(path.name, (pin['filename'], PUBLIC_WINDOWS_NAME))
                else:
                    self.assertEqual(path.name, pin['filename'])
                self.assertEqual(sha256(path.read_bytes()).hexdigest(), pin['sha'])
                trace, inventory = inventory_benchmark(
                    schema_root=self.schema, source=path, sha256_pin=pin['sha'])
                self.assertEqual(inventory['mode'], 'inventory')
                self.assertEqual(inventory['summary']['source_rules'], pin['count'])
                # Count source records before hash assertions so a stale trace
                # reports the observed 535-record total rather than 0.
                count += pin['count']
                self.assertEqual(stable_digest(trace), pin['trace'])
                self.assertEqual(stable_digest(inventory), pin['manifest'])
                self.assertIs(inventory['scanner_evaluated'], False)
        self.assertEqual(count, 535)

    def test_cli_inventory_has_no_native_assessment_or_proof(self):
        with tempfile.TemporaryDirectory(prefix='scapng-readonly-inventory-') as temp:
            output = Path(temp) / 'inventory'
            args = [sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                    '--schema-root', str(self.schema), str(self.files[0]),
                    '--sha256', PINS[0]['sha'], '--inventory-only', '--output', str(output)]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['native_documents'], 0)
            self.assertEqual(sorted(p.name for p in output.iterdir()),
                             ['coverage.json', 'coverage.md', 'source-trace.json'])
            self.assertEqual(stable_digest(json.loads((output / 'coverage.json').read_text())),
                             PINS[0]['manifest'])


if __name__ == '__main__':
    unittest.main()
