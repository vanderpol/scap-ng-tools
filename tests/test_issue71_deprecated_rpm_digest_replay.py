"""Pinned signed OVAL source replay: deprecated RPM digest naming is not a capability gap.

Original authoring/structural evidence only; runtime outcome parity is separate.
Both source files are pinned by the CI checkout commit, never fetched as moving
"latest" content.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest

from scap_ng_tools.converter.direct04 import convert_focused

CORPUS = (
    (
        "U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip",
        "xccdf_mil.disa.stig_rule_SV-221653r1015161_rule",
    ),
    (
        "U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip",
        "xccdf_mil.disa.stig_rule_SV-214799r991589_rule",
    ),
)

class DeprecatedRpmDigestSourceReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = os.environ.get("SCAP_NG_Q3_SIGNED_ROOT")
        schema = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        if not root or not schema:
            raise unittest.SkipTest("Explicit pinned Q3 source and schema are required")
        cls.archive = Path(root) / "Archive" / "2026_Q3"
        cls.schema = Path(schema)

    def test_rpm_digest_aliases_recover_from_immutable_signed_sources(self):
        for filename, rule in CORPUS:
            with self.subTest(rule=rule):
                source = self.archive / filename
                self.assertTrue(source.is_file(), str(source))
                source_hash = sha256(source.read_bytes()).hexdigest()
                documents, trace = convert_focused(
                    schema_root=self.schema,
                    source=source,
                    sha256_pin=source_hash,
                    rule_ids=[rule],
                    native_recovery=True,
                )
                self.assertTrue(documents)
                assessments = [doc["assessment"] for doc in documents.values()
                               if isinstance(doc, dict) and "assessment" in doc]
                self.assertTrue(assessments, "No native Assessment created")
                # The original source's deprecated "md5_differs" is an
                # RPM state filter, not an MD5-specific native capability.
                for assessment in assessments:
                    encoded = json.dumps(assessment, sort_keys=True)
                    self.assertNotIn('"md5_differs"', encoded)
                    self.assertNotIn('"nomd5"', encoded)
                self.assertIn("rules", trace)
                print(json.dumps({
                    "source": filename,
                    "source_sha256": source_hash,
                    "rule": rule,
                    "assessments": len(assessments),
                    "semantic_proof": "NOT_RUN",
                    "scanner_evaluated": False,
                }, sort_keys=True))

if __name__ == "__main__":
    unittest.main()
