#!/usr/bin/env python3
"""Build a deterministic, schema-validated Issue #28 Assessment corpus archive.

The source ZIPs and schema are explicit inputs. The command fails closed on
SHA-256, source/schema/candidate pin, status, artifact, or schema drift. It
uses the PR #33 owner-review ``--recover-native`` path; this is authoring
validation only, not compiler/scanner/runtime equivalence.
"""
from __future__ import annotations
import argparse, gzip, hashlib, json, os, shutil, subprocess, tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
import yaml

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import convert_benchmark, validate_native_documents
from scap_ng_tools.converter._v04_runtime.v04_direct_yaml import authoring_yaml

EXPECTED_SOURCE = '8c8e5dff860af6b1290ee9273a282db24278f8d5'
EXPECTED_SCHEMA = '919732d4c570b521edf82196a7694dfd8c27fe50'
EXPECTED_SCHEMA_DIGEST = '6bf2fa369fd7b9a0153899ac25109af3e3f9aa59c0f4aa6bb3be1aebd5b14fa0'
EXPECTED_COUNTS = {'converted': 6479, 'manual_only': 1403, 'blocked': 108, 'intentionally_excluded': 209}

def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def stable(value: object) -> str: return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n').hexdigest()
def git_head(path: Path) -> str:
    return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
def safe_name(value: str) -> str:
    return ''.join(c if c.isalnum() or c in '._-' else '-' for c in value).strip('-')
def read_candidate(ledger_path: Path, rules_path: Path):
    ledger = json.loads(ledger_path.read_text(encoding='utf-8'))
    with gzip.open(rules_path, 'rt', encoding='utf-8') as stream: rules = json.load(stream)
    if ledger.get('candidate') != rules.get('candidate'): raise ValueError('ledger/rules candidate metadata differ')
    candidate = ledger['candidate']
    if candidate['source_commit'] != EXPECTED_SOURCE or candidate['schema_commit'] != EXPECTED_SCHEMA or candidate['schema_family_sha256'] != EXPECTED_SCHEMA_DIGEST:
        raise ValueError('candidate source/schema pin differs from PR #33')
    core = {k: rules[k] for k in ('format','scope','rules')}
    if stable(core) != candidate['candidate_digest']: raise ValueError('candidate digest verification failed')
    counts = Counter(row['status'] for row in rules['rules'])
    if dict(counts) != EXPECTED_COUNTS: raise ValueError(f'candidate counts differ: {dict(counts)}')
    if len(ledger.get('blocked_rule_reasons', [])) != 108 or len(ledger.get('excluded_rule_reasons', [])) != 209: raise ValueError('ledger disposition reason index incomplete')
    return ledger, rules, candidate

def source_paths(source_root: Path, benchmarks):
    candidates = {}
    for path in source_root.rglob('*.zip'):
        candidates.setdefault(path.name, []).append(path)
    result = {}
    for row in benchmarks:
        matches = [path for path in candidates.get(row['filename'], []) if sha(path) == row['source_sha256']]
        if not matches:
            raise ValueError(f'source ZIP pin did not resolve: {row["filename"]}')
        # Archives can be duplicated in the public library; equal-byte copies
        # are equivalent, but a distinct match would make provenance ambiguous.
        if len({sha(path) for path in matches}) != 1:
            raise ValueError(f'source ZIP pin has conflicting matches: {row["filename"]}')
        result[row['filename']] = sorted(matches)[0]
    return result

def assessment_artifacts(row):
    return sorted(p for p in row.get('artifacts', []) if p.startswith('authoring/') and '/assessments/' in p and p.endswith('.json'))

def write_json(path: Path, value: object):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
def validate_yaml_docs(snapshot, docs):
    parsed = {}
    for name, doc in docs.items():
        raw = authoring_yaml(doc)
        loaded = yaml.safe_load(raw)
        if loaded != doc: raise ValueError(f'YAML round-trip drift: {name}')
        parsed[name] = loaded
    # This reuses the exact pinned resolver/contract, including generated capability refs.
    validate_native_documents(snapshot, parsed)
    return parsed

def make_archive(staging: Path, output: Path, root_name: str):
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['tar', '--sort=name', '--mtime=UTC 1970-01-01', '--owner=0', '--group=0', '--numeric-owner', '-I', 'gzip -n', '-cf', str(output), '-C', str(staging.parent), root_name], check=True)

def build(args):
    ledger, rules_doc, candidate = read_candidate(args.ledger, args.rules)
    if git_head(args.source_root) != EXPECTED_SOURCE: raise ValueError('source checkout HEAD differs from pinned source commit')
    snapshot = FrozenSchemaSnapshot(args.schema_root)
    if snapshot.manifest()['aggregate_sha256'] != EXPECTED_SCHEMA_DIGEST: raise ValueError('schema digest differs from pinned candidate')
    tools_commit = args.tools_commit or git_head(Path(__file__).resolve().parents[1])
    if len(tools_commit) != 40: raise ValueError('tools commit must be a full commit SHA')
    paths = source_paths(args.source_root, ledger['benchmarks'])
    rows = {(r['benchmark'], r['source_rule']): r for r in rules_doc['rules']}
    with tempfile.TemporaryDirectory(prefix='scapng-issue28-build-') as temp:
        staging = Path(temp) / args.root_name; staging.mkdir()
        doc_count = Counter(); assessment_index=[]; validation = []
        raw_status = Counter(); included_status = Counter(); mismatches=[]
        for number, benchmark in enumerate(ledger['benchmarks'], 1):
            src = paths[benchmark['filename']]
            docs, trace, coverage = convert_benchmark(schema_root=args.schema_root, source=src, sha256_pin=benchmark['source_sha256'], native_recovery=True)
            raw_status.update(coverage['summary']['statuses'])
            expected = {r['source_rule']: r for r in rules_doc['rules'] if r['benchmark'] == benchmark['filename']}
            got = {r['source_rule']: r for r in coverage['rules']}
            for rid, row in expected.items():
                if row['status'] == 'intentionally_excluded': continue
                actual = got.get(rid)
                if actual is None or actual['status'] != row['status']:
                    mismatches.append({'benchmark': benchmark['filename'], 'source_rule': rid, 'expected': row['status'], 'actual': actual and actual.get('status')})
                    continue
                if row['status'] == 'blocked':
                    included_status['blocked'] += 1
                    continue
                included_status[row['status']] += 1
                expected_paths = assessment_artifacts(row)
                if set(expected_paths) != {x for x in actual.get('artifacts', []) if '/assessments/' in x and x.endswith('.json')}:
                    mismatches.append({'benchmark': benchmark['filename'], 'source_rule': rid, 'expected_artifacts': expected_paths, 'actual_artifacts': actual.get('artifacts', [])})
                    continue
                bench_root = staging / 'documents' / f'{number:02d}-{safe_name(benchmark["filename"].removesuffix(".zip"))}'
                for artifact in actual.get('artifacts', []):
                    if artifact not in docs: continue
                    dest = bench_root / PurePosixPath(artifact)
                    write_json(dest, docs[artifact]); dest.with_suffix('.yaml').write_text(authoring_yaml(docs[artifact]), encoding='utf-8')
                    doc_count[dest.suffix] += 1
                for artifact in expected_paths:
                    assessment_index.append({'benchmark': benchmark['filename'], 'source_rule': rid, 'status': row['status'], 'source_rule_sha256': row['source_rule_sha256'], 'assessment': str((bench_root / artifact).with_suffix('.yaml').relative_to(staging)).replace(os.sep,'/')})
            # applicability is shared per benchmark only when at least one accepted doc exists.
            if any(r['benchmark']==benchmark['filename'] and r['status'] in ('converted','manual_only') for r in rules_doc['rules']):
                for artifact, document in docs.items():
                    if artifact.endswith('/applicability.json'):
                        dest=staging/'documents'/f'{number:02d}-{safe_name(benchmark["filename"].removesuffix(".zip"))}'/PurePosixPath(artifact); write_json(dest,document); dest.with_suffix('.yaml').write_text(authoring_yaml(document),encoding='utf-8'); doc_count[dest.suffix]+=1
        if mismatches: raise ValueError('candidate/converter discrepancies: '+json.dumps(mismatches[:8], sort_keys=True))
        if dict(included_status) != {'converted':6479,'manual_only':1403,'blocked':108}: raise ValueError(f'included counts differ: {dict(included_status)}')
        # Validate every emitted JSON and its actual YAML serialization against the exact pin.
        emitted={}
        for path in sorted((staging/'documents').rglob('*.json')):
            emitted[str(path.relative_to(staging))]=json.loads(path.read_text(encoding='utf-8'))
        validate_native_documents(snapshot, emitted)
        yaml_docs={str(path.relative_to(staging)): yaml.safe_load(path.read_text(encoding='utf-8')) for path in sorted((staging/'documents').rglob('*.yaml'))}
        validate_native_documents(snapshot, yaml_docs)
        metadata={'format':'scap-ng-assessment-corpus/1','version':args.root_name,'candidate':candidate,'tools_commit':tools_commit,'source_repository':'niwc-atlantic/scap-content-library','source_checkout_commit':EXPECTED_SOURCE,'schema_checkout_commit':EXPECTED_SCHEMA,'schema_family_sha256':EXPECTED_SCHEMA_DIGEST,'counts':{'source_rules':8199,'generated_assessment_rules':7882,'automated_converted':6479,'manual_only':1403,'blocked':108,'intentionally_excluded':209,'generated_json_documents':len(emitted),'generated_yaml_documents':len(yaml_docs),'assessment_yaml_files':len(assessment_index)},'generated_documents':sorted(emitted),'assessment_index':sorted(assessment_index,key=lambda x:(x['benchmark'],x['source_rule'],x['assessment'])),'validation':{'json_schema':'Draft 2020-12 exact pinned SCAP-NG 0.4 snapshot','json_documents':len(emitted),'yaml_documents':len(yaml_docs),'errors':[],'independent_proof':False,'compiler_execution':False,'scanner_execution':False,'runtime_equivalence_claim':False},'discrepancies':{'raw_converter_statuses':dict(raw_status),'expected_excluded_raw_status_delta':dict(Counter(raw_status)-Counter({'converted':6479,'manual_only':1403,'blocked':108})),'notes':['The converter evaluates all 8,199 source Rules; 209 SQLEXT Rules are intentionally excluded from publication per the candidate ledger.','Schema validation is authoring validation only and is not a runtime-equivalence claim.']}}
        write_json(staging/'manifest.json',metadata)
        sums=[]
        for path in sorted(p for p in staging.rglob('*') if p.is_file() and p.name!='SHA256SUMS'):
            sums.append(f'{sha(path)}  {path.relative_to(staging).as_posix()}')
        (staging/'SHA256SUMS').write_text('\n'.join(sums)+'\n',encoding='utf-8')
        # Include exact reconciled ledger pair for excluded/blocker provenance.
        prov=staging/'provenance'; prov.mkdir(); shutil.copy2(args.ledger,prov/'ACTIVE-CANDIDATE-LEDGER.json'); shutil.copy2(args.rules,prov/'ACTIVE-CANDIDATE-RULES.json.gz'); write_json(prov/'schema-manifest.json',snapshot.manifest())
        # Regenerate manifest after provenance is present, then hashes once more (manifest is included in sums).
        metadata['provenance_files']=['provenance/ACTIVE-CANDIDATE-LEDGER.json','provenance/ACTIVE-CANDIDATE-RULES.json.gz','provenance/schema-manifest.json']; write_json(staging/'manifest.json',metadata)
        sums=[f'{sha(path)}  {path.relative_to(staging).as_posix()}' for path in sorted(p for p in staging.rglob('*') if p.is_file() and p.name!='SHA256SUMS')]; (staging/'SHA256SUMS').write_text('\n'.join(sums)+'\n',encoding='utf-8')
        make_archive(Path(temp),args.output,args.root_name)
    print(json.dumps({'archive':str(args.output),'archive_sha256':sha(args.output),'candidate_digest':candidate['candidate_digest'],'counts':dict(included_status),'raw_converter_statuses':dict(raw_status)},sort_keys=True))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--schema-root',type=Path,required=True); ap.add_argument('--source-root',type=Path,required=True); ap.add_argument('--ledger',type=Path,required=True); ap.add_argument('--rules',type=Path,required=True); ap.add_argument('--output',type=Path,required=True); ap.add_argument('--root-name',default='scap-ng-assessment-corpus-0.4.0-issue28-candidate'); ap.add_argument('--tools-commit'); args=ap.parse_args(); build(args)
if __name__=='__main__': main()
