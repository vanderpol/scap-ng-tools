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
        'trace': '2350f42616db168fd7984af6f28fea19e3538bb91e0c2dd6fa477e6f2f5d1126',
        'manifest': 'b8e006eceeaca1d1e669e88d2f9336ea3ad165323409a2ff49f80e0641e9b238',
    },
    {
        'filename': 'U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip',
        'count': 36,
        'sha': '94740b7929dd868043ab1b476c3b568712fc26d045a4d450359cea90effbfa1c',
        'trace': '19f8df8e2e7d714bee02bb03334323ef4e19087e0d28d9e8cb0621e9f96bebfb',
        'manifest': '9335f772f3cc5a1952c46d66b1087f17dbd2105ce975b4f9156f29fc96d8d719',
    },
    {
        'filename': 'U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip',
        'count': 187,
        'sha': '88cc35f98c9ff96c567110c284c06e6adfc556fd59967019bdec6fd1cc5a204f',
        'trace': '3f82c57c8a34a5055a342993dfa496d62e653d1d83f159dc721799b50f576786',
        'manifest': '6b3cdccfda5097f549f7372ae95c661f88b03d2097e9ebce366c4d99e31d0823',
    },
    {
        'filename': 'U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip',
        'count': 21,
        'sha': 'd16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca',
        'trace': '5a9c179c112065435380c84fcd79fe83830d215e2f3f72550094777feb72fe9c',
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
                self.assertEqual(stable_digest(trace), pin['trace'])
                self.assertEqual(stable_digest(inventory), pin['manifest'])
                self.assertIs(inventory['scanner_evaluated'], False)
                count += pin['count']
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
