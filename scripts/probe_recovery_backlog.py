#!/usr/bin/env python3
"""Probe historical automated blockers only; never regenerate the65 library.

Known invalid/deprecated sources and unsupported package extensions stay held.
Every other recorded blocker is attempted through current native DRAFT gates.
"""
import argparse
from collections import Counter,defaultdict
from concurrent.futures import ProcessPoolExecutor
import json
from pathlib import Path


def probe(job):
    source,pin,schema,ids,destination=job
    from scap_ng_tools.converter.recovery04 import recover_benchmark
    docs,trace,ledger=recover_benchmark(schema_root=schema,source=source,sha256_pin=pin,rule_ids=ids)
    out=Path(destination);out.mkdir(parents=True,exist_ok=False)
    for name,value in [('documents.json',docs),('source-trace.json',trace),('ledger.json',ledger)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n')
    return {'filename':Path(source).name,'ledger':ledger,'native_documents':len(docs)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scoreboard',type=Path,required=True);p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--schema-root',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--workers',type=int,default=3)
    a=p.parse_args()
    if a.output.exists():p.error('output exists; refusing overwrite')
    score=json.loads(a.scoreboard.read_text());groups=defaultdict(list);held=Counter()
    pins={b['filename']:b['sha256'] for b in score['benchmarks']}
    for category,rows in score['historical_blocked_rules'].items():
        if category in ('invalid_or_deprecated_source','future_sqlext_extension'):
            held[category]+=len(rows);continue
        for row in rows:groups[row['benchmark']].append(row['source_rule'])
    jobs=[]
    for name,ids in sorted(groups.items()):
        if Path(name).name!=name or not name.endswith('.zip'):p.error('unsafe source filename')
        jobs.append((str(a.source_root/'Archive/2026_Q3'/name),pins[name],a.schema_root,ids,str(a.output/Path(name).stem)))
    a.output.mkdir(parents=True)
    with ProcessPoolExecutor(max_workers=a.workers) as pool:results=list(pool.map(probe,jobs))
    statuses=Counter(r['status'] for b in results for r in b['ledger']['rules'])
    causes=Counter(r['blockers'][0] for b in results for r in b['ledger']['rules'] if r['status']=='BLOCKED' and r['blockers'])
    result={'format':'focused-blocker-probes/1','held_without_conversion':dict(held),'statuses':dict(statuses),
            'current_primary_blockers':dict(causes),'benchmarks':results,
            'qualification':'Focused current DRAFT attempts; no independent source proof or scanner execution.'}
    (a.output/'probe-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'statuses':dict(statuses),'held':dict(held),'causes':dict(causes)}))

if __name__=='__main__':main()
