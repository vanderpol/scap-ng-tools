"""Tools #122 source-derived Benchmark identity regression coverage."""
import hashlib
import os
from pathlib import Path
import re
import unittest

from scap_ng_tools.converter.direct04 import load_pinned_snapshot, load_runtime
from scap_ng_tools.converter.applicability import build_applicability

_runtime = load_runtime()
assemble_subset = _runtime.assemble_subset
SourceModel = _runtime.SourceModel
source_native_identifier = _runtime.source_native_identifier


UBUNTU_BENCHMARKS = (
    ("U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip",
     "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_18-04_STIG"),
    ("U_CAN_Ubuntu_20-04_LTS_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip",
     "xccdf_mil.disa.stig_benchmark_Canonical_Ubuntu_20-04_LTS_STIG"),
    ("U_CAN_Ubuntu_22-04_LTS_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV11-signed.zip",
     "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_22-04_LTS_STIG"),
    ("U_CAN_Ubuntu_24-04_LTS_V1R6_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip",
     "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG"),
)


class Issue122IdentityTests(unittest.TestCase):
    def test_source_native_identity_is_bounded_stable_and_collision_resistant(self):
        values = ["source/Ubuntu 24.04", "source/ubuntu-24.04", "source/Ubuntu 24.04"]
        ids = [source_native_identifier(value, "benchmark-") for value in values]
        self.assertEqual(ids[0], ids[2])
        self.assertNotEqual(ids[0], ids[1])
        for identifier in ids:
            self.assertLessEqual(len(identifier), 64)
            self.assertRegex(identifier, r"^[a-z][a-z0-9-]*$")

    def test_four_authentic_ubuntu_benchmarks_publish_source_derived_identities(self):
        root = os.environ.get("SCAP_NG_UBUNTU_FIXTURES_ROOT")
        if not root:
            self.skipTest("set SCAP_NG_UBUNTU_FIXTURES_ROOT for authentic Ubuntu archive regression")
        root = Path(root)
        schema_root = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        if not schema_root:
            schema_root = str(Path(root).parent.parent / "scap-ng" / "schema")
        snapshot = load_pinned_snapshot(schema_root)
        mappings = snapshot.supported_mappings(_runtime.CAPABILITIES)
        outputs = []
        for filename, source_id in UBUNTU_BENCHMARKS:
            archive = root / filename
            if not archive.is_file():
                self.skipTest(f"missing authentic archive: {archive}")
            source = SourceModel(archive, hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(source.benchmark.get("id"), source_id)
            source_rule = next(iter(source.rules))
            documents, trace = assemble_subset(
                source, {}, [{"source_rule": source_rule, "native_rule": "fixture-rule"}], [],
            )
            wrapper = documents["authoring/direct-slice/benchmark.json"]["benchmark"]
            catalog = documents["authoring/direct-slice/applicability.json"]["applicability"]
            self.assertEqual(wrapper["id"], source_native_identifier(source_id, "benchmark-"))
            self.assertEqual(wrapper["applicability_catalog"], catalog["id"])
            self.assertEqual(wrapper["platform"]["id"], source_native_identifier(source_id + "\x00platform", "platform-"))
            self.assertNotIn("direct-slice", wrapper["id"])
            self.assertNotIn("fixture-", wrapper["platform"]["id"])
            self.assertNotIn("fixture-", catalog["id"])
            self.assertNotIn("[AUTOMATED PROTOTYPE SUBSET]", wrapper["title"][0]["text"])
            self.assertTrue(wrapper["metadata"]["partial_conversion"])
            self.assertEqual(wrapper["metadata"]["source_benchmark_id"], source_id)
            self.assertEqual(trace["source_benchmark_id"], source_id)
            documents, applicability_trace = build_applicability(
                source, documents, {"rules": [{"source_rule": source_rule,
                    "status": "converted", "artifacts": []}]}, mappings)
            condition_rows = applicability_trace["conditions"]
            self.assertEqual(len(condition_rows), 1)
            self.assertEqual(len(applicability_trace["shared_assessments"]), 1)
            fact = applicability_trace["shared_assessments"][0]["source_fact_refs"][0]
            self.assertEqual(fact["id_ref"],
                             "oval:mil.disa.stig.ubuntu%sos:def:1" % source_id.split("Ubuntu_")[1].split("_")[0].replace("-", ""))
            self.assertEqual(fact["cpe_name"], condition_rows[0]["source"]["idref"])
            self.assertEqual(len(fact["cpe_item_sha256"]), 64)
            outputs.append((wrapper["id"], wrapper["platform"]["id"], catalog["id"]))
        self.assertEqual(len({row[0] for row in outputs}), 4)
        self.assertEqual(len({row[1] for row in outputs}), 4)
        self.assertEqual(len({row[2] for row in outputs}), 4)
