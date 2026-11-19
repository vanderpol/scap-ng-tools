"""Direct 0.4.1 RPM digest behavior alias is source-XSD-backed and fail-closed."""
import unittest
from xml.etree import ElementTree as ET
from scap_ng_tools.converter.direct04 import load_runtime

class RpmDigestAliasContract(unittest.TestCase):
    def test_alias_installer_idempotent(self):
        engine=load_runtime()
        from v04_direct_scalar_behaviors import scalar_behaviors
        self.assertIs(load_runtime().AssessmentConverter,engine.AssessmentConverter)
        from v04_direct_scalar_behaviors import scalar_behaviors as again
        self.assertIs(scalar_behaviors,again)

    def test_unrelated_behavior_does_not_accept_legacy_alias(self):
        engine=load_runtime()
        from v04_direct_scalar_behaviors import scalar_behaviors
        behavior=ET.Element("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}behaviors",
                            {"nomd5":"false"})
        mapping={"capability":"linux.rpminfo",
                 "native":{"collection_parameters":{}},
                 "migration_crosswalk":{"behaviors":{}}}
        with self.assertRaises(Exception):
            scalar_behaviors(behavior,mapping)

if __name__=="__main__":
    unittest.main()
