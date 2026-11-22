"""Static Input-expression semantic overlay: Input types never silently cast."""
import unittest
from scap_ng_tools.converter.native041_input_semantics import project_assessment

def assessment(expression, *, dtype="string", required=True, cardinality="exactly_one"):
    return {"inputs":{"required-input":{"datatype":dtype,
                                         "required":required,"cardinality":cardinality}},
            "variables":{"local-variable":{"kind":"local","expression":expression}}}

class InputSemanticProjection(unittest.TestCase):
    def test_input_and_to_integer_do_not_modify_original_authoring(self):
        source=assessment({"to_integer":{"substring":{"substring_start":1,
                         "substring_length":1,"value":{"input":"required-input"}}}})
        projected, probes, seen=project_assessment(source)
        self.assertEqual(source["variables"]["local-variable"]["expression"]["to_integer"]
                         ["substring"]["value"],{"input":"required-input"})
        self.assertEqual(projected["variables"]["local-variable"]["expression"],
                         {"literal":{"datatype":"integer","value":0}})
        self.assertEqual(probes[0]["substring"]["value"],
                         {"literal":{"datatype":"string","value":"0"}})
        self.assertEqual(seen,{"input","to_integer"})

    def test_undeclared_optional_and_untyped_inputs_fail(self):
        for candidate in (
            assessment({"input":"missing-input"}),
            assessment({"input":"required-input"},required=False),
            assessment({"input":"required-input"},dtype="record"),
        ):
            with self.subTest(candidate=candidate),self.assertRaises(ValueError):
                project_assessment(candidate)

    def test_required_multivalue_input_is_a_valid_dynamic_operand(self):
        projected, probes, seen = project_assessment(
            assessment({"input":"required-input"}, cardinality="one_or_more"))
        self.assertEqual(projected["variables"]["local-variable"]["expression"],
                         {"literal": {"datatype": "string", "value": "0"}})
        self.assertEqual(probes, [])
        self.assertEqual(seen, {"input"})

    def test_non_input_variables_are_unmodified(self):
        candidate=assessment({"arithmetic":{"arithmetic_operation":"add",
                             "values":[{"literal":1},{"literal":2}]}})
        projected, probes, seen=project_assessment(candidate)
        self.assertEqual(projected,candidate)
        self.assertEqual(probes,[])
        self.assertEqual(seen,set())

if __name__=="__main__":
    unittest.main()
