#!/usr/bin/env python3
"""Source-pinned native DRAFT recovery. No compiler/scanner/proof promotion."""
import argparse
import json
from pathlib import Path
import yaml
from scap_ng_tools.converter.recovery04 import recover_benchmark


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--schema-root',required=True);p.add_argument('--source',required=True)
    p.add_argument('--sha256',required=True);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--rule',action='append',help='optional focused source Rule IDs; omitted means whole benchmark')
    p.add_argument('--organization-parameters',action='store_true',help='explicit controlled policy derivative; remove publisher defaults and delegate resolution')
    p.add_argument('--binary32-comparisons', action='store_true',
                   help='explicit finite-expected binary32 recovery; requires exact coordinated contract sidecar')
    args=p.parse_args()
    if args.output.exists():p.error('output exists; refusing overwrite')
    docs,trace,ledger=recover_benchmark(schema_root=args.schema_root,source=args.source,
        sha256_pin=args.sha256,organization_parameters=args.organization_parameters,rule_ids=args.rule,
        binary32_comparisons=args.binary32_comparisons)
    args.output.mkdir(parents=True)
    for name,doc in docs.items():
        target=args.output/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(json.dumps(doc,indent=2)+'\n')
        target.with_suffix('.yaml').write_text(yaml.safe_dump(doc,sort_keys=False,allow_unicode=True))
    for name,value in [('source-trace.json',trace),('ledger.json',ledger)]:
        (args.output/name).write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(ledger['summary']))

if __name__=='__main__':main()
