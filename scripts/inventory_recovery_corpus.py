#!/usr/bin/env python3
"""Read-only source-pattern scoreboard. Never converts or publishes a corpus."""
import argparse
from collections import Counter,defaultdict
from concurrent.futures import ProcessPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys


def inspect(job):
    filename,pin,schema=job
    from scap_ng_tools.converter.direct04 import load_runtime
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    snap=FrozenSchemaSnapshot(schema);engine=load_runtime()
    from v04_direct_scap_source import SourceModel,OVAL,OCIL,XCCDF
    from v04_direct_inventory import SourceInventory
    model=SourceModel(Path(filename),pin,inventory_broken_references=True)
    inventory=SourceInventory(model,mappings=snap.supported_mappings())
    supported={m['capability'] for m in snap.supported_mappings(engine.CAPABILITIES)}
    output=[]
    for row in inventory.rules():
        rule=model.rules[row['source_rule']];patterns=set();automatic=any(c['system']==OVAL for c in row['checks'])
        manual=any(c['system']==OCIL for c in row['checks'])
        if row['inventory_problems']:patterns.add('source_link_or_selection')
        if manual and not automatic:patterns.add('manual_ocil_only')
        if automatic and any(c not in supported for c in row['needed_capabilities']):patterns.add('not_in_portable_capability_pack')
        for dep in row['dependencies']:
            node=model.nodes[dep['component']][dep['id']]
            if dep['tag'].endswith('}external_variable'):patterns.add('external_value_binding')
            if node.get('check_existence')=='all_exist':patterns.add('all_exist_population')
            if dep['kind']=='variable' and node.tag.rsplit('}',1)[-1]=='local_variable' and any(n.tag.rsplit('}',1)[-1] not in ('literal_component','variable_component','object_component') for n in node):patterns.add('oval_function')
            if node.get('deprecated') in ('true','1'):patterns.add('source_deprecated')
        for check in rule.findall('.//{'+XCCDF+'}check'):
            if check.find('{'+XCCDF+'}check-import') is not None:patterns.add('check_import')
            if check.find('{'+XCCDF+'}check-export') is not None:patterns.add('check_export')
        output.append({'source_rule':row['source_rule'],'source_rule_sha256':row['source_rule_sha256'],'automatic_source':automatic,'manual_source':manual,
                       'patterns':sorted(patterns),'capabilities':row['needed_capabilities'],
                       'selection':row['selection'],'inventory_problems':row['inventory_problems'],
                       'current_attempt':'NOT_ATTEMPTED','schema_validated':None,'compiled':None,
                       'independent_source_proof':None,'scanner_execution':False})
    return {'filename':Path(filename).name,'sha256':pin,'xml_sha256':model.xml_sha256,
            'benchmark_id':model.benchmark.get('id'),'component_hashes':model.component_hashes,
            'rules':output,'counts':{'source_rules':len(output),
               'automatic_source':sum(r['automatic_source'] for r in output),
               'manual_source':sum(r['manual_source'] for r in output),
               'manual_only':sum(r['manual_source'] and not r['automatic_source'] for r in output)}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root',required=True);parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--source-commit',required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--workers',type=int,default=3)
    args=parser.parse_args()
    if args.output.exists():parser.error('output already exists')
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=args.source_root,text=True).strip()!=args.source_commit:
        parser.error('source checkout commit mismatch')
    if subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=args.source_root,text=True).strip():
        parser.error('source checkout has modified tracked files')
    paths=sorted((args.source_root/'Archive/2026_Q3').glob('*signed.zip'))
    if len(paths)!=65:parser.error('expected exact65 signed benchmark ZIPs')
    jobs=[(str(p),sha256(p.read_bytes()).hexdigest(),args.schema_root) for p in paths]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:results=list(pool.map(inspect,jobs))
    counts=Counter();groups=defaultdict(list)
    for result in results:
        counts.update(result['counts'])
        for row in result['rules']:
            for pattern in row['patterns']:
                groups[pattern].append({'benchmark':result['filename'],'rule':row['source_rule']})
    value={'format':'read-only-recovery-scoreboard/1','source_repository':'niwc-atlantic/scap-content-library',
           'source_commit':args.source_commit,'read_only':True,'conversion_attempts':0,
           'counts':dict(counts),'pattern_rule_counts':{k:len(v) for k,v in sorted(groups.items())},
           'qualification':'Pattern counts overlap; these are source obligations, not demonstrated converter failures or admissions.',
           'benchmarks':results,'patterns':dict(groups)}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps({'counts':dict(counts),'patterns':value['pattern_rule_counts']}))

if __name__=='__main__':main()
