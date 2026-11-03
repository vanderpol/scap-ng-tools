#!/usr/bin/env python3
"""Replay eight exact owner corrections; originals/manuals/proof levels retained."""
import argparse
from collections import defaultdict
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--schema-root',required=True);p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    from scap_ng_tools.converter.direct04 import load_runtime
    load_runtime()
    from scap_ng_tools.converter.recovery04 import recover_benchmark
    from v04_direct_scap_source import digest
    base=Path(__file__).resolve().parents[1];groups=defaultdict(list)
    pins=json.loads((base/'tests/fixtures/issue14-absence-pins.json').read_text())
    before={r['source_rule']:r for r in json.loads((base/'docs/evidence/issue14-absence/investigation.json').read_text())['cases']}
    for row in pins:groups[row['filename']].append(row)
    a.output.mkdir(parents=True);rows=[];packages=[]
    for filename,cases in sorted(groups.items()):
        docs,trace,ledger=recover_benchmark(schema_root=a.schema_root,source=a.source_root/filename,
            sha256_pin=cases[0]['sha256'],rule_ids=[r['source_rule'] for r in cases],approved_absence_corrections=True)
        directory=Path(filename).stem.removeprefix('U_').removesuffix('-signed').lower().replace('_','-')
        group=a.output/directory;group.mkdir()
        for name,value in [('documents.json',docs),('trace.json',trace),('ledger.json',ledger)]:
            (group/name).write_text(json.dumps(value,indent=2)+'\n')
        packages.append({'directory':directory,'filename':filename,'documents':len(docs),'rules':len(ledger['rules'])})
        for row in ledger['rules']:
            old=before[row['source_rule']]
            manual=next(d for d in docs.values() if d.get('assessment',{}).get('id')==old['manual_assessment'])
            if digest(manual)!=old['manual_document_sha256']:raise AssertionError('manual document changed')
            if row['status']!='AUTOMATED_DRAFT' or not row['owner_normalized']:raise AssertionError(row)
            binding=next(b for b in trace['rules'] if b['source_rule']==row['source_rule'])
            rows.append({'filename':filename,'source_zip_sha256':cases[0]['sha256'],
                'source_rule':row['source_rule'],'source_rule_sha256':row['source_rule_sha256'],
                'before':'AUTOMATED_DRAFT' if 'SV-271844' in row['source_rule'] else 'BLOCKED',
                'after':row['status'],'owner_normalized':True,'manual_document_sha256':digest(manual),
                'source_corrections':[w for w in binding['conversion_warnings'] if w.get('source_correction')],
                'compiled':False,'source_semantic_proof':False,'scanner_execution':False})
    report={'format':'issue14-approved-absence-recovery/1','base_commit':'0b8e5eeb4ff8121c2dd7d8f604a03f34a1d5b164',
        'decision':'https://github.com/vanderpol/scap-ng-tools/issues/14#issuecomment-6615375024',
        'counts':{'previously_corrected':1,'new_owner_corrected_drafts':7,'total_owner_corrected_drafts':8,'remaining_absence_blockers':0},
        'packages':packages,'rules':rows,'source_semantic_proof':False,'scanner_execution':False}
    (a.output/'recovery.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['counts']))


if __name__=='__main__':main()
