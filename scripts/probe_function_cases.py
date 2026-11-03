#!/usr/bin/env python3
"""Reproduce the bounded Issue14 eleven-case replay; no full65 conversion."""
import argparse
import json
from pathlib import Path
from scap_ng_tools.converter.recovery04 import recover_benchmark


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root',required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--cases',type=Path,default=Path(__file__).resolve().parents[1]/'tests/fixtures/function-rule-pins.json')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('refusing to overwrite existing evidence')
    cases=json.loads(args.cases.read_text());args.output.mkdir(parents=True)
    rows=[]
    for row in cases:
        filename=row['filename']
        if Path(filename).name!=filename or not filename.endswith('.zip'):raise ValueError('unsafe source filename')
        docs,trace,ledger=recover_benchmark(schema_root=args.schema_root,source=args.source_root/filename,
            sha256_pin=row['sha256'],rule_ids=[row['source_rule']])
        folder=args.output/Path(filename).stem;folder.mkdir()
        for name,value in [('documents',docs),('trace',trace),('ledger',ledger)]:
            (folder/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
        rows.append({**row,'after':ledger['rules'][0]})
    (args.output/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')
    print(json.dumps({'attempts':len(rows),'automated_drafts':sum(r['after']['automated_draft'] for r in rows),
                      'blocked':sum(r['after']['status']=='BLOCKED' for r in rows),'scanner_execution':False}))


if __name__=='__main__':main()
