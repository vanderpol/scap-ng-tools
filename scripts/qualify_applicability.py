#!/usr/bin/env python3
"""Reproducible SCAP 1.4 applicability qualification harness.

The harness downloads one immutable OpenSCAP XCCDF test source, applies a
small deterministic hierarchy overlay (Benchmark platform + nested Group and
Profile) because the upstream regression source has no nested Group, then
runs the draft converter's native hierarchy/catalog lowering.  The overlay is
recorded separately from the real source digest; this is not corpus content or
scanner qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
XCCDF = "http://checklists.nist.gov/xccdf/1.2"
CPE = "http://cpe.mitre.org/language/2.0"
X = "{" + XCCDF + "}"

def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def digest_xml(node: ET.Element) -> str:
    def identity(item):
        return [item.tag, sorted(item.attrib.items()),
                item.text if not len(item) else None,
                [identity(child) for child in item]]
    return sha256(json.dumps(identity(node), sort_keys=True, separators=(",", ":")).encode())

def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()

def derive_source(base: ET.Element) -> ET.Element:
    """Add only deterministic qualification structure; preserve base content."""
    benchmark = base
    ET.SubElement(benchmark, f"{X}platform", {"idref": "cpe:/a:true"})
    profile = ET.SubElement(benchmark, f"{X}Profile", {"id": "qualification-profile-disabled"})
    ET.SubElement(profile, f"{X}title").text = "Qualification profile with one disabled Rule"
    groups = benchmark.findall(f"{X}Group")
    if len(groups) < 2:
        raise ValueError("real source must contain at least two Groups")
    # Wrap one existing real Rule in each of two real Groups. The original
    # Rule platform restrictions remain untouched; only containment is added.
    for outer, platform, marker in ((groups[0], "cpe:/a:true", "true"),
                                    (groups[1], "cpe:/a:false", "false")):
        rule = outer.find(f"{X}Rule")
        if rule is None:
            raise ValueError("selected real source Group has no Rule")
        outer.remove(rule)
        inner = ET.Element(f"{X}Group", {"id": f"qualification-inner-{marker}"})
        ET.SubElement(inner, f"{X}platform", {"idref": platform})
        inner.append(rule)
        outer.append(inner)
        if marker == "true":
            ET.SubElement(profile, f"{X}select", {"idref": rule.get("id"), "selected": "false"})
    return benchmark

def adapter(benchmark):
    from scap_ng_tools.converter._v04_runtime.v04_direct_scap_source import SourceModel
    source = SimpleNamespace(
        root=benchmark, benchmark=benchmark,
        parents={child: parent for parent in benchmark.iter() for child in parent},
        rules={rule.get("id"): rule for rule in benchmark.iter(f"{X}Rule")},
        catalog={},
    )
    for name in ("applicability_condition_id", "applicability_level",
                 "applicability_context", "cpe_platform_expression"):
        setattr(source, name, getattr(SourceModel, name).__get__(source))
    return source

def qualify(source_url: str, source_sha: str | None, output: Path, ri_results: Path | None = None) -> dict:
    base_raw = fetch(source_url)
    actual = sha256(base_raw)
    if source_sha and actual != source_sha:
        raise ValueError(f"source SHA mismatch: {actual} != {source_sha}")
    base = ET.fromstring(base_raw)
    if base.tag != f"{X}Benchmark":
        raise ValueError("selected source must be a direct XCCDF 1.2 Benchmark")
    derived = derive_source(base)
    derived_raw = ET.tostring(derived, encoding="utf-8", xml_declaration=True)
    source = adapter(derived)
    runtime = __import__("scap_ng_tools.converter.direct04", fromlist=["load_runtime"]).load_runtime()
    converter = runtime
    rule_links = {rid: "native-" + sha256(rid.encode())[:16] for rid in source.rules}
    groups = [converter.native_group(source, group, rule_links)
              for group in source.benchmark.findall(f"{X}Group")]
    documents = {
        "authoring/direct-slice/benchmark.json": {"benchmark": {
            "id": "applicability-qualification",
            "platform": {"id": "source-platform", "title": "source Benchmark platform"},
            "groups": groups,
            "rules": list(rule_links.values()),
            "profiles": [{"id": "qualification-profile-disabled",
                          "disabled_rules": [rule_links[next(iter(source.rules))]]}],
        }},
    }
    coverage = {"rules": []}
    for rid, native_id in rule_links.items():
        path = f"authoring/direct-slice/rules/{native_id}.json"
        documents[path] = {"rule": {"id": native_id}}
        coverage["rules"].append({"source_rule": rid, "status": "converted",
                                   "artifacts": [path]})
    from scap_ng_tools.converter.applicability import build_applicability
    documents, trace = build_applicability(source, documents, coverage, mappings=[])
    selected_rule = next(iter(source.rules))
    levels = source.applicability_context(source.rules[selected_rule])["levels"]
    catalog = documents["authoring/direct-slice/applicability.json"]["applicability"]
    receipt = {
        "format": "scap-ng/applicability-qualification/1",
        "qualification_status": "SOURCE_HIERARCHY_CONVERTED_RI_PENDING",
        "source": {"url": source_url, "sha256": actual,
                   "derived_overlay_sha256": sha256(derived_raw),
                   "derived_overlay_reason": "adds Benchmark/Profile and nested Group containment; base is immutable public OpenSCAP test content"},
        "pins": {
            "schema_commit": "fcb2c220c05a933665477a6504586b9f47f83177",
            "schema_aggregate_sha256": "65ad62d207e39488eba670d0ab9cad740e66bbec1f4fc19737582363e2165a54",
            "converter_commit": "654d6481d6d86f47e9b648bc31b992990ad67213",
            "ri_commit": "32e59aa24769056aa00e8938487bbc9a380b591b",
        },
        "source_platform_levels": levels,
        "native": {"benchmark": documents["authoring/direct-slice/benchmark.json"]["benchmark"],
                    "rules": {path: doc for path, doc in documents.items() if path.startswith("authoring/direct-slice/rules/")},
                    "applicability_catalog": catalog},
        "qualified_cpe_mappings": [],
        "unqualified_holds": trace["unsupported"],
        "ri_results": {"true": "pending", "false": "pending", "unknown": "pending", "error": "pending",
                       "profile_disabled": "not_evaluated", "not_applicable": "pending"},
        "semantic_differences": [
            "The upstream public regression source has no nested Group; the deterministic overlay is separately hashed and is not source provenance.",
            "Direct CPE URI references have no qualified native mapping in this converter and remain explicit RI ERROR holds, never FALSE.",
            "RI execution and TRUE/FALSE/UNKNOWN results require the coordinated RI harness; this receipt does not claim scanner equivalence.",
        ],
        "converter_trace": trace,
    }
    # These are qualified RI truth-table probes, deliberately separate from
    # the source CPE catalog: the source's direct CPE URIs remain holds.
    ri_input = {"format": "scap-ng/applicability-ri-probes/1", "cases": [
        {"id": "true", "expression": {"condition": "probe-true"},
         "conditions": {"probe-true": {"outcome": "true", "source": {"kind": "probe", "id": "true"}}}},
        {"id": "false", "expression": {"condition": "probe-false"},
         "conditions": {"probe-false": {"outcome": "false", "source": {"kind": "probe", "id": "false"}}}},
        {"id": "unknown", "expression": {"condition": "probe-unknown"},
         "conditions": {"probe-unknown": {"outcome": "unknown", "source": {"kind": "probe", "id": "unknown"}}}},
        {"id": "error", "expression": {"condition": "source-hold"},
         "conditions": {"source-hold": {"source": {"kind": "cpe_platform", "id": "cpe:/a:unqualified"}}}},
        {"id": "not_applicable", "expression": {"condition": "probe-false"},
         "conditions": {"probe-false": {"outcome": "false"}}},
        {"id": "profile_disabled", "profile_disabled": True,
         "expression": {"condition": "probe-true"}, "conditions": {}}]}
    receipt["ri_probe_input"] = ri_input
    output.mkdir(parents=True, exist_ok=True)
    (output / "derived-source.xccdf.xml").write_bytes(derived_raw)
    (output / "native.json").write_text(json.dumps(documents, sort_keys=True, indent=2) + "\n")
    (output / "ri-input.json").write_text(json.dumps(ri_input, sort_keys=True, indent=2) + "\n")
    if ri_results is not None:
        result = json.loads(Path(ri_results).read_text())
        receipt["ri_results"] = {item["id"]: item["outcome"] for item in result["results"]}
        receipt["ri_result_details"] = result
        receipt["qualification_status"] = "SOURCE_HIERARCHY_CONVERTED_RI_PROBES_EXECUTED_WITH_SOURCE_HOLDS"
    (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-url", default="https://raw.githubusercontent.com/OpenSCAP/openscap/38e6d9fd84d337f0f558a7d3b95b54bf4c6c6cef/tests/API/XCCDF/applicability/test_platform_inheritance.xccdf.xml")
    parser.add_argument("--source-sha256", default=None)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ri-results", type=Path, default=None)
    args = parser.parse_args()
    receipt = qualify(args.source_url, args.source_sha256, args.output, args.ri_results)
    print(json.dumps({"receipt": str(args.output / "receipt.json"), "source_sha256": receipt["source"]["sha256"], "derived_sha256": receipt["source"]["derived_overlay_sha256"]}, sort_keys=True))

if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "src"))
    main()
