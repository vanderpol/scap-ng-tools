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


    def test_deprecated_boolean_alias_preserves_values_and_rejects_conflicts(self):
        from unittest.mock import patch
        load_runtime()
        import v04_direct_scalar_behaviors as helper
        mapping={
            "capability":"linux.rpmverifyfile",
            "source":{"definitions_schema":"official-pinned-linux-xsd",
                      "object":"rpmverifyfile_object"},
            "native":{"collection_parameters":{
                "skip_file_digest":{"type":"boolean","required":True}}},
            "migration_crosswalk":{
                "behaviors":{"nofiledigest":"object.skip_file_digest"},
                "deprecated":{"nomd5":"migration_error_replaced_by_nofiledigest"}}}
        declarations={
            "nomd5":{"type":"xsd:boolean","default":"false"},
            "nofiledigest":{"type":"xsd:boolean","default":"false"}}
        with patch.object(helper,"original_attributes",return_value=declarations):
            for source_value,expected in (("false",False),("true",True),
                                          ("0",False),("1",True)):
                node=ET.Element("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}behaviors",
                                {"nomd5":source_value})
                original=dict(node.attrib)
                self.assertEqual(helper.scalar_behaviors(node,mapping),
                                 {"skip_file_digest":expected})
                self.assertEqual(node.attrib,original)
            conflicting=ET.Element("behaviors",{
                "nomd5":"true","nofiledigest":"false"})
            with self.assertRaises(Exception):
                helper.scalar_behaviors(conflicting,mapping)
            malformed=ET.Element("behaviors",{"nomd5":"not-a-boolean"})
            with self.assertRaises(Exception):
                helper.scalar_behaviors(malformed,mapping)

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
