"""Canonical native-domain adaptation for converted Debian EVR predicates."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).parents[1] / "src" / "scap_ng_tools" / "converter" / "native041_function_lowering.py"
spec = importlib.util.spec_from_file_location("native041_function_lowering_issue99", MODULE)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class DpkgEVRMappingTests(unittest.TestCase):
    def test_oval_evr_string_uses_debian_domain_only_for_dpkg(self):
        document = {"assessment": {"variables": {}, "tests": {
            "dpkg-test": {"capability": "linux.dpkginfo", "require": {
                "fields": {"evr": {"rpm_evr_greater_than": "0"}}}}
        }}}
        self.assertTrue(mod.lower_assessment_inplace(document))
        predicate = document["assessment"]["tests"]["dpkg-test"]["require"]["fields"]["evr"]
        self.assertEqual(predicate, {"debian_evr_greater_than": "0"})

    def test_other_capabilities_are_not_rewritten(self):
        document = {"assessment": {"variables": {}, "tests": {
            "rpm-test": {"capability": "linux.rpminfo", "require": {
                "fields": {"evr": {"rpm_evr_greater_than": "0"}}}}
        }}}
        self.assertFalse(mod.lower_assessment_inplace(document))
        self.assertEqual(document["assessment"]["tests"]["rpm-test"]["require"]["fields"]["evr"],
                         {"rpm_evr_greater_than": "0"})
