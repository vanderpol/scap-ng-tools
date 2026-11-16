#!/usr/bin/env python3
"""Audit and optionally convert one immutable real SCAP 1.4 source archive.

This deliberately reports missing hierarchy levels as a gate failure. It never
adds synthetic Groups or promotes a source CPE identity to an executable
Assessment. The companion qualification harness is separate and labels any
deterministic overlay explicitly.
"""
from __future__ import annotations
import argparse, hashlib, json, urllib.request, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

X = "{http://checklists.nist.gov/xccdf/1.2}"
CPE = "{http://cpe.mitre.org/language/2.0}"

def sha(raw): return hashlib.sha256(raw).hexdigest()
def stable(value): return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r: return r.read()
def source_tree(raw):
    with zipfile.ZipFile(__import__('io').BytesIO(raw)) as z:
        members = [n for n in z.namelist() if n.lower().endswith('.xml')]
        for member in members:
            root = ET.fromstring(z.read(member))
            if root.tag == f"{X}Benchmark": return member, root
            found = root.find(f".//{X}Benchmark")
            if found is not None: return member, found
    raise ValueError("no XCCDF 1.2 Benchmark in source archive")
def audit(raw, url, expected, schema_root=None, output=None):
    actual = sha(raw)
    if expected and actual != expected: raise ValueError(f"source SHA mismatch: {actual} != {expected}")
    member, benchmark = source_tree(raw)
    groups = benchmark.findall(f".//{X}Group")
    rules = benchmark.findall(f".//{X}Rule")
    group_platforms = [g for g in groups if g.findall(f"{X}platform")]
    nested_groups = [g for g in groups if g.findall(f"{X}Group")]
    rule_platforms = [r for r in rules if r.findall(f"{X}platform")]
    cpe_specs = list(benchmark.iter(f"{CPE}platform"))
    result = {
      "format": "scap-ng/real-source-applicability-audit/1",
      "qualification_status": "BLOCKED_MISSING_REAL_SOURCE_LEVELS",
      "source": {"url": url, "sha256": actual, "member": member},
      "pins": {"schema_commit": "fcb2c220c05a933665477a6504586b9f47f83177", "schema_aggregate_sha256": "65ad62d207e39488eba670d0ab9cad740e66bbec1f4fc19737582363e2165a54", "converter_commit": "fec71c60ba8c0f0bb0eed099d731e448962980d0", "converter_pr_original_head": "654d6481d6d86f47e9b648bc31b992990ad67213", "ri_commit": "32e59aa24769056aa00e8938487bbc9a380b591b"},
      "source_structure": {"benchmark_platforms": [x.get("idref") for x in benchmark.findall(f"{X}platform")], "groups": len(groups), "nested_groups": len(nested_groups), "group_platforms": len(group_platforms), "rules": len(rules), "rule_platforms": len(rule_platforms), "profiles": len(benchmark.findall(f"{X}Profile")), "cpe_platform_specifications": len(cpe_specs)},
      "converter": {"executed": False},
      "gate": {"requires_benchmark_group_nested_group_rule_platforms": True, "missing": [], "synthetic_overlay_allowed": False},
      "semantic_differences": ["This real SCAP 1.4 source has no nested Groups and no Group-local platform restrictions; it cannot prove those inheritance levels.", "No source-level CPE mapping is promoted by this audit.", "A separate RI probe receipt proves TRUE/FALSE/UNKNOWN/ERROR and profile-disabled/not_evaluated distinctions only."],
    }
    if not benchmark.findall(f"{X}platform"): result["gate"]["missing"].append("Benchmark platform")
    if not group_platforms: result["gate"]["missing"].append("Group-local platform")
    if not nested_groups: result["gate"]["missing"].append("nested Group")
    if not rule_platforms: result["gate"]["missing"].append("Rule-local platform")
    if schema_root:
        from scap_ng_tools.converter import convert_benchmark
        path = Path(output or '/tmp/scap-ng-real-source')
        path.mkdir(parents=True, exist_ok=True)
        source_path = path / 'source.zip'; source_path.write_bytes(raw)
        documents, trace, coverage = convert_benchmark(schema_root=Path(schema_root), source=source_path, sha256_pin=actual, include_applicability=True)
        result["converter"] = {"executed": True, "document_count": len(documents), "native_documents_sha256": stable(documents), "coverage_summary": coverage.get("summary"), "applicability": {k: trace.get("applicability", {}).get(k) for k in ("catalog_condition_count", "shared_assessment_count", "source_rule_count_attached", "source_identity_preserved", "independent_semantic_proof", "scanner_runtime")}}
    return result

def main():
    p=argparse.ArgumentParser(); p.add_argument('--source-url',default='https://raw.githubusercontent.com/OVAL-Community/SCAP-Self-Assertion/ce3ebe88c98bceaab9c1bd3fc7af056b60822634/SCAP_1.4/SCAP_Test_Content/R700/U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'); p.add_argument('--source-sha256',default='e4b8d55b58aa80124bd0974977af4c7f7bde35c748e2940e02857419292d8c3d'); p.add_argument('--schema-root'); p.add_argument('--output',type=Path,required=True); a=p.parse_args(); raw=fetch(a.source_url); result=a.output; result.mkdir(parents=True,exist_ok=True); receipt=audit(raw,a.source_url,a.source_sha256,a.schema_root,result); (result/'real-source-audit.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n'); print(json.dumps({'receipt':str(result/'real-source-audit.json'),'source_sha256':receipt['source']['sha256'],'status':receipt['qualification_status']},sort_keys=True))
if __name__=='__main__': main()
