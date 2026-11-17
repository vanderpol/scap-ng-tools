"""Focused XCCDF Profile inheritance -> independent 0.4.1 Profile witnesses."""
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter._v04_runtime.v04_direct_scap_source import (
    SourceModel, UnsupportedSource, XCCDF,
)
from scap_ng_tools.converter.direct04 import load_runtime


def source_from_benchmark(benchmark):
    source = SourceModel.__new__(SourceModel)
    source.benchmark = benchmark
    source.benchmark_component = "source"
    source.parents = {child: parent for parent in benchmark.iter() for child in parent}
    source.nodes = {"source": {
        node.get("id"): node for node in benchmark.iter() if node.get("id")
    }}
    source.rules = {
        rule.get("id"): rule for rule in benchmark.iter(f"{{{XCCDF}}}Rule")
    }
    return source


class SourceProfileFlatteningTests(unittest.TestCase):
    def setUp(self):
        benchmark = ET.fromstring(f"""<Benchmark xmlns="{XCCDF}" id="bench">
          <Group id="group-a">
            <Rule id="rule-a"/>
            <Rule id="rule-b"/>
          </Group>
          <Group id="group-b"><Rule id="rule-c"/></Group>
          <Profile id="baseline">
            <title>Baseline</title>
            <select idref="group-a" selected="false"/>
            <select idref="rule-c" selected="false"/>
          </Profile>
          <Profile id="specialized" extends="baseline">
            <title>Specialized</title>
            <select idref="group-a" selected="true"/>
            <select idref="rule-b" selected="false"/>
          </Profile>
          <Profile id="restored" extends="specialized">
            <title>Restored</title>
            <select idref="rule-b" selected="true"/>
            <select idref="rule-c" selected="true"/>
          </Profile>
          <Profile id="isolated">
            <title>Isolated</title>
            <select idref="rule-a" selected="false"/>
          </Profile>
        </Benchmark>""")
        self.source = source_from_benchmark(benchmark)
        self.links = {"rule-a": "native-a", "rule-b": "native-b", "rule-c": "native-c"}

    def test_inherited_group_and_rule_selects_are_fully_flattened(self):
        profiles, traces = load_runtime().render_profiles(
            self.source, list(self.links), self.links)
        by_name = {trace["source_id"]: (native, trace)
                   for native, trace in zip(profiles, traces)}
        expected = {
            "baseline": ["native-a", "native-b", "native-c"],
            "specialized": ["native-b", "native-c"],
            "restored": [],
            "isolated": ["native-a"],
        }
        for name, disabled in expected.items():
            native, trace = by_name[name]
            self.assertEqual(native["disabled_rules"], disabled, name)
            self.assertNotIn("extends", native)
            self.assertNotIn("enabled_rules", native)
            self.assertNotIn("groups", native)
            self.assertEqual(trace["source_id"], name)
            self.assertEqual(len(trace["source_sha256"]), 64)
        self.assertEqual([entry["source_id"] for entry in by_name["restored"][1]["source_profile_chain"]],
                         ["baseline", "specialized", "restored"])
        self.assertTrue(all(len(entry["source_sha256"]) == 64
                            for entry in by_name["restored"][1]["source_profile_chain"]))
        # Group disablement is an original XCCDF selection, never a native Group selector.
        for name in expected:
            self.assertEqual(set(by_name[name][0]), {"id", "title", "disabled_rules"})

    def test_unselected_ancestor_group_cannot_be_bypassed_by_rule_select(self):
        group = self.source.benchmark.find(f"{{{XCCDF}}}Group")
        profile = self.source.benchmark.find(f"{{{XCCDF}}}Profile")
        ET.SubElement(profile, f"{{{XCCDF}}}select",
                      {"idref": "rule-a", "selected": "true"})
        self.assertFalse(self.source.rule_selected(self.source.rules["rule-a"], profile))
        group.set("selected", "false")
        self.assertFalse(self.source.rule_selected(self.source.rules["rule-a"], profile))

    def test_no_profile_preserves_default_rule_selection(self):
        self.assertTrue(all(self.source.rule_selected(rule)
                            for rule in self.source.rules.values()))

    def test_source_cycles_missing_and_invalid_selectors_are_holds(self):
        profile = self.source.benchmark.findall(f"{{{XCCDF}}}Profile")[0]
        profile.set("extends", "restored")
        with self.assertRaisesRegex(UnsupportedSource, "Profile inheritance cycle"):
            self.source.profile_lineage(profile)
        profile.set("extends", "not-present")
        with self.assertRaisesRegex(UnsupportedSource, "extends missing Profile"):
            self.source.profile_lineage(profile)
        profile.attrib.pop("extends")
        ET.SubElement(profile, f"{{{XCCDF}}}select",
                      {"idref": "missing-rule", "selected": "true"})
        with self.assertRaisesRegex(UnsupportedSource, "unresolved Profile idref"):
            self.source.rule_selected(self.source.rules["rule-a"], profile)

    def test_duplicate_local_selectors_rejected_but_child_override_allowed(self):
        profile = self.source.benchmark.findall(f"{{{XCCDF}}}Profile")[0]
        ET.SubElement(profile, f"{{{XCCDF}}}select",
                      {"idref": "group-a", "selected": "true"})
        with self.assertRaisesRegex(UnsupportedSource, "repeated/noncanonical"):
            self.source.rule_selected(self.source.rules["rule-a"], profile)

    def test_refinement_does_not_silently_disappear(self):
        profile = self.source.benchmark.findall(f"{{{XCCDF}}}Profile")[0]
        ET.SubElement(profile, f"{{{XCCDF}}}refine-value",
                      {"idref": "organization", "selector": "active"})
        with self.assertRaisesRegex(UnsupportedSource, "refinement/unsupported"):
            self.source.rule_selected(self.source.rules["rule-a"], profile)


if __name__ == "__main__":
    unittest.main()
