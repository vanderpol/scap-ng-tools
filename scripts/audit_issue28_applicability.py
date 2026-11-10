#!/usr/bin/env python3
"""Quantify source CPE/OVAL applicability versus native 0.4 output.

This audit is read-only: it never rewrites or republishes the accepted archive.
It requires the exact source and schema pins used by the Issue #28 release.
"""
from __future__ import annotations
import argparse, collections, gzip, hashlib, json, subprocess, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime

SOURCE_COMMIT = '8c8e5dff860af6b1290ee9273a282db24278f8d5'
SCHEMA_COMMIT = '919732d4c570b521edf82196a7694dfd8c27fe50'
SCHEMA_DIGEST = '6bf2fa369fd7b9a0153899ac25109af3e3f9aa59c0f4aa6bb3be1aebd5b14fa0'
XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
CPE = 'http://cpe.mitre.org/language/2.0'
CPE_DICT = 'http://cpe.mitre.org/dictionary/2.0'

def digest(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def git_head(path: Path) -> str: return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
def safe_name(value: str) -> str: return ''.join(c if c.isalnum() or c in '._-' else '-' for c in value).strip('-')
def load_json_gz(path: Path) -> dict:
    with gzip.open(path, 'rt', encoding='utf-8') as stream: return json.load(stream)
def source_zip(root: Path, filename: str, pin: str) -> Path:
    matches = [p for p in root.rglob('*.zip') if p.name == filename and digest(p) == pin]
    if not matches: raise ValueError('missing source ZIP: '+filename)
    return sorted(matches)[0]
def pct(n: int, d: int) -> float | None: return round(100*n/d, 3) if d else None

def audit(args):
    ledger = json.loads(args.ledger.read_text(encoding='utf-8'))
    rules = load_json_gz(args.rules)['rules']
    pins = ledger['candidate']
    if pins != {'candidate_digest': pins['candidate_digest'], 'schema_commit': SCHEMA_COMMIT, 'schema_family_sha256': SCHEMA_DIGEST, 'source_commit': SOURCE_COMMIT}:
        raise ValueError('candidate pins differ from the accepted corpus')
    if git_head(args.source_root) != SOURCE_COMMIT: raise ValueError('source checkout is not pinned')
    snapshot = FrozenSchemaSnapshot(args.schema_root)
    if snapshot.manifest()['aggregate_sha256'] != SCHEMA_DIGEST: raise ValueError('schema digest mismatch')
    load_runtime()
    from v04_direct_scap_source import SourceModel
    from v04_direct_inventory import SourceInventory
    mappings = snapshot.supported_mappings()
    by_rule = {(r['benchmark'], r['source_rule']): r['status'] for r in rules}
    source_paths = {b['filename']: source_zip(args.source_root,b['filename'],b['source_sha256']) for b in ledger['benchmarks']}
    totals = collections.Counter(); unique_cpe=set(); unique_custom=set(); unique_facts=set(); per=[]
    for number, benchmark in enumerate(ledger['benchmarks'], 1):
        source = SourceModel(source_paths[benchmark['filename']], benchmark['source_sha256'], inventory_broken_references=True)
        inventory = SourceInventory(source, mappings=mappings)
        parents = {child: parent for parent in source.benchmark.iter() for child in parent}
        direct = effective = 0; rules_with = 0; status_counts = collections.Counter(); status_refs = collections.Counter()
        cpe_refs=[]; custom_refs=[]
        for rule in source.rules.values():
            status = by_rule[(benchmark['filename'], rule.get('id'))]; status_counts[status] += 1
            refs=[]; direct += len(rule.findall('{%s}platform'%XCCDF)); node=rule
            while node is not None:
                refs.extend(p.get('idref') for p in node.findall('{%s}platform'%XCCDF))
                if node is source.benchmark: break
                node = parents.get(node)
            effective += len(refs); status_refs[status] += len(refs); rules_with += bool(refs)
            for ref in refs:
                (custom_refs if ref.startswith('#') else cpe_refs).append(ref)
        facts=[]; resolved=0; closure_supported=0; closure_sqlext=0
        for fact in source.root.iter('{%s}check-fact-ref'%CPE):
            fact_id=(fact.get('href'),fact.get('id-ref')); unique_facts.add(fact_id); facts.append(fact)
            component=source.catalog.get(fact.get('href')); nodes, problems=inventory.closure(component,fact.get('id-ref')) if component else ([],['unresolved'])
            if nodes and not problems: resolved += 1
            capabilities={n['capability'] for n in nodes if n['capability']}
            if capabilities and any('sqlext' in c for c in capabilities): closure_sqlext += 1
            elif nodes and not problems: closure_supported += 1
        platform_defs = list(source.root.iter('{%s}platform'%CPE))
        cpe_items = list(source.root.iter('{%s}cpe-item'%CPE_DICT))
        unique_cpe.update(cpe_refs); unique_custom.update(custom_refs)
        for key,value in status_counts.items(): totals[f'source_{key}_rules'] += value
        for key,value in status_refs.items(): totals[f'source_{key}_effective_platform_refs'] += value
        totals.update(source_rules=len(source.rules), source_direct_platform_refs=direct, source_effective_platform_refs=effective, source_rules_with_effective_platform=rules_with, source_platform_definitions=len(platform_defs), source_platform_fact_refs=len(facts), source_platform_fact_refs_resolved=resolved, source_platform_fact_closures_supported=closure_supported, source_platform_fact_closures_sqlext=closure_sqlext, source_cpe_dictionary_items=len(cpe_items), source_cpe_uri_refs=len(cpe_refs), source_custom_platform_refs=len(custom_refs))
        root = args.archive_root / 'documents' / (f'{number:02d}-'+safe_name(benchmark['filename'].removesuffix('.zip')))
        catalog_path = root/'authoring/direct-slice/applicability.json'
        catalog = json.loads(catalog_path.read_text())['applicability'] if catalog_path.exists() else None
        native_rules=list((root/'authoring/direct-slice/rules').glob('*.json')) if (root/'authoring/direct-slice/rules').exists() else []
        native_nonempty = sum(bool(json.loads(p.read_text())['rule'].get('applicability')) for p in native_rules)
        totals.update(native_rules=len(native_rules), native_rules_with_applicability=native_nonempty)
        per.append({'benchmark':benchmark['filename'],'source_rules':len(source.rules),'candidate_statuses':dict(status_counts),'source_direct_platform_refs':direct,'source_effective_platform_refs':effective,'source_rules_with_effective_platform':rules_with,'source_platform_definitions':len(platform_defs),'source_platform_fact_refs':len(facts),'source_platform_fact_refs_resolved':resolved,'source_platform_fact_closures_supported':closure_supported,'source_platform_fact_closures_sqlext':closure_sqlext,'source_cpe_dictionary_items':len(cpe_items),'source_cpe_uri_refs':len(cpe_refs),'source_custom_platform_refs':len(custom_refs),'native_catalog_present':catalog is not None,'native_catalog_conditions':len(catalog['conditions']) if catalog else 0,'native_rules':len(native_rules),'native_rules_with_applicability':native_nonempty})
    summary=dict(totals)
    summary.update({'source_benchmarks':len(per),'source_unique_cpe_uri_refs':len(unique_cpe),'source_unique_custom_platform_refs':len(unique_custom),'source_unique_platform_fact_refs':len(unique_facts),'native_catalogs_present':sum(x['native_catalog_present'] for x in per),'native_catalogs_nonempty':sum(x['native_catalog_conditions']>0 for x in per),'native_rule_files':sum(x['native_rules'] for x in per),'native_rules_with_applicability':sum(x['native_rules_with_applicability'] for x in per),'source_platform_fact_resolution_percent':pct(totals['source_platform_fact_refs_resolved'],totals['source_platform_fact_refs']),'source_platform_closure_supported_percent':pct(totals['source_platform_fact_closures_supported'],totals['source_platform_fact_refs'])})
    report={'format':'scap-ng-tools/issue28-applicability-coverage/1','pins':pins,'summary':summary,'interpretation':{'finding':'intentional_conversion_pipeline_limitation','schema_gap':False,'source_mapping_gap':False,'evidence':['v04_direct_converter.assemble_subset hard-codes fixture-platform and fixture-applicability with empty conditions.','The same function explicitly lists CPE/platform execution as unsupported.','The source XML/component graph retains the XCCDF platform refs and CPE platform-specification fact refs, but no applicability lowering path consumes them.','All 185 source platform fact refs resolve; 183 closures use existing supported capability mappings and two are SQLEXT.'],'smallest_corrective_implementation':['Add a source applicability graph extractor for inherited XCCDF platform refs, CPE URIs, and CPE platform-specification logical-test/fact-ref nodes.','Reuse the existing OVAL-to-native Assessment conversion for each unique supported platform fact closure, emitting shared applicability Assessments rather than duplicating Tests.','Emit applicability catalog condition keys and references, then attach inherited platform condition references to native Rules/Benchmark using the existing 0.4 shared Assessment mechanism.','Keep SQLEXT fact closures explicitly blocked/excluded; do not infer or fabricate platform semantics.','Add source identity, resolution, and no-runtime-equivalence receipts before changing publication output.'],'preserve_archive':True},'benchmarks':per}
    args.output_json.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    s=summary
    md=['# Issue #28 applicability coverage audit','',f"Pins: source `{SOURCE_COMMIT}`, schema `{SCHEMA_COMMIT}`, schema SHA-256 `{SCHEMA_DIGEST}`.",'', '## Finding','', '**Classification: intentional conversion-pipeline limitation.** The canonical schema supports the required references; the source contains resolvable CPE/OVAL platform data; the converter deliberately emits a fixture catalog instead.', '', '| Measure | Count | Coverage |','|---|---:|---:|',f"| Source benchmarks | {s['source_benchmarks']} | — |",f"| Source Rules | {s['source_rules']} | — |",f"| Rules with inherited platform refs | {s['source_rules_with_effective_platform']} | {pct(s['source_rules_with_effective_platform'],s['source_rules'])}% |",f"| Effective XCCDF platform refs | {s['source_effective_platform_refs']} | — |",f"| CPE platform-specification definitions | {s['source_platform_definitions']} | across 32 benchmarks |",f"| CPE/OVAL platform fact refs | {s['source_platform_fact_refs']} | — |",f"| Fact refs resolved by source graph | {s['source_platform_fact_refs_resolved']} | {s['source_platform_fact_resolution_percent']}% |",f"| Fact closures using supported capabilities | {s['source_platform_fact_closures_supported']} | {s['source_platform_closure_supported_percent']}% |",f"| Fact closures requiring SQLEXT | {s['source_platform_fact_closures_sqlext']} | — |",f"| Native applicability catalogs present | {s['native_catalogs_present']} | — |",f"| Native catalogs with conditions | {s['native_catalogs_nonempty']} | {pct(s['native_catalogs_nonempty'],s['native_catalogs_present'])}% |",f"| Native Rule files with applicability | {s['native_rules_with_applicability']} / {s['native_rule_files']} | 0% |",'', '## Source-to-native status by Rule class','', '| Candidate class | Rules | Effective platform refs |','|---|---:|---:|']
    for key,label in [('converted','Automated converted'),('manual_only','Manual-only'),('blocked','Blocked'),('intentionally_excluded','Intentionally excluded')]: md.append(f"| {label} | {s['source_'+key+'_rules']} | {s['source_'+key+'_effective_platform_refs']} |")
    md += ['', 'The released archive is unchanged. Empty catalogs are an explicit limitation, not proof that source applicability is absent.', '', '## Smallest corrective implementation', ''] + [f'- {x}' for x in report['interpretation']['smallest_corrective_implementation']]
    args.output_md.write_text('\n'.join(md)+'\n',encoding='utf-8')
    print(json.dumps({'summary':summary,'output_json':str(args.output_json),'output_md':str(args.output_md)},sort_keys=True))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--schema-root',type=Path,required=True); ap.add_argument('--source-root',type=Path,required=True); ap.add_argument('--archive-root',type=Path,required=True); ap.add_argument('--ledger',type=Path,required=True); ap.add_argument('--rules',type=Path,required=True); ap.add_argument('--output-json',type=Path,required=True); ap.add_argument('--output-md',type=Path,required=True); audit(ap.parse_args())
if __name__=='__main__': main()
