#!/usr/bin/env python3
"""Join immutable historical evidence with fresh read-only source identities.

Historical proof/compile counts are never promoted to current-schema results.
Only explicitly supplied current ledgers establish attempted conversion status.
"""
import argparse
from collections import Counter,defaultdict
from hashlib import sha256
import json
from pathlib import Path
import zipfile


def cause(row):
    message=row.get('primary_blocker',{}).get('message','')
    if row.get('original_source_validation')=='UNSUPPORTED_PACKAGE_EXTENSION':return 'future_sqlext_extension'
    if row.get('original_source_validation')=='KNOWN_INVALID_OR_DEPRECATED':return 'invalid_or_deprecated_source'
    if 'Value operator' in message:return 'xccdf_value_operator'
    if 'Value constraints' in message:return 'xccdf_value_constraints'
    if 'external Variable' in message or 'check-export' in message:return 'external_value_binding'
    if any(s in message for s in ('catalog','unresolved','reference kind')):return 'catalog_or_link_resolution'
    if 'all_exist' in message:return 'all_exist_population'
    if 'function' in message or 'aggregation' in message:return 'oval_function'
    if 'ordered comparison' in message:return 'ordered_comparison_datatype'
    if 'absence' in message:return 'comparator_bearing_absence'
    if 'capability' in message:return 'capability_or_mapping'
    return 'other_source_or_adapter'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True);p.add_argument('--historical-review',type=Path,required=True)
    p.add_argument('--historical-sha256',required=True);p.add_argument('--current-ledger',type=Path,action='append',default=[])
    p.add_argument('--backlog-summary',type=Path,help='fresh selected-blocker probe results')
    p.add_argument('--current-overlay',type=Path,action='append',default=[],help='explicit later qualification replacing matching source/Rule identities')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('output exists; refusing overwrite')
    if sha256(a.historical_review.read_bytes()).hexdigest()!=a.historical_sha256:p.error('historical archive hash mismatch')
    fresh=json.loads(a.inventory.read_text());by_hash={b['sha256']:b for b in fresh['benchmarks']}
    historical=Counter();root_causes=defaultdict(list);streams=[];joined=set()
    with zipfile.ZipFile(a.historical_review) as z:
        names=[n for n in z.namelist() if '/records/streams/' in n and n.endswith('.json') and not n.endswith('source-trace.json')]
        if len(names)!=65:p.error('historical manifest must contain65 streams')
        for name in names:
            record=json.loads(z.read(name));ledger=record['original_ledger'];pin=ledger['source_zip_sha256']
            if pin not in by_hash or pin in joined:p.error('historical/current source identity mismatch')
            joined.add(pin);current=by_hash[pin];rows={r['source_rule']:r for r in current['rules']}
            if set(rows)!={r['source_rule'] for r in ledger['rules']}:p.error('historical/current Rule denominator mismatch')
            counts=Counter()
            for old in ledger['rules']:
                row=rows[old['source_rule']]
                if row['source_rule_sha256']!=old['source_rule_sha256']:p.error('historical/current Rule bytes differ')
                status=old['draft_status'];historical[status]+=1;counts[status]+=1
                if old.get('independent_source_proof')=='RETAINED_EXACT_HASH_EVIDENCE':historical['retained_historical_proof']+=1
                if old.get('compile_status')=='COMPILED_OPERANDS_CHECKED':historical['historical_compiled']+=1
                if status=='BLOCKED_EXPLICIT':
                    key=cause(old)
                    root_causes[key].append({'benchmark':current['filename'],'source_rule':old['source_rule'],
                        'historical_message':old.get('primary_blocker',{}).get('message'),
                        'fresh_source_patterns':row['patterns'],'current_attempt':'NOT_ATTEMPTED'})
            streams.append({'filename':current['filename'],'sha256':pin,'rules':len(rows),'historical':dict(counts)})
    attempted=Counter();current_rows=[];current={};receipts=[]
    for path,is_overlay in [(p,False) for p in a.current_ledger]+[(p,True) for p in a.current_overlay]:
        ledger=json.loads(path.read_text());pin=ledger['source_zip_sha256']
        if pin not in by_hash:p.error('current ledger source not present in inventory')
        originals={r['source_rule']:r for r in by_hash[pin]['rules']}
        for row in ledger['rules']:
            if row['source_rule'] not in originals or row['source_rule_sha256']!=originals[row['source_rule']]['source_rule_sha256']:
                p.error('current attempt Rule identity mismatch')
            key=pin,row['source_rule']
            if key in current and not is_overlay:p.error('duplicate current Rule; use explicit --current-overlay')
            current[key]=row
        receipts.append({'ledger':path.name,'sha256':sha256(path.read_bytes()).hexdigest(),
                         'rows':len(ledger['rules']),'explicit_overlay':is_overlay})
    for (pin,rid),row in current.items():
        attempted[row['status']]+=1;attempted['source_rules']+=1
        attempted['manual_assessments']+=row['manual']
        attempted['manual_choices']+=row['manual'] and row.get('rule_emitted',row['status']!='BLOCKED')
        attempted['compiled_rules']+=row['compiled']
        current_rows.append({'source_zip_sha256':pin,'source_rule':rid,'status':row['status']})
    priority=['external_value_binding','xccdf_value_operator','xccdf_value_constraints','catalog_or_link_resolution',
              'all_exist_population','oval_function','ordered_comparison_datatype','comparator_bearing_absence',
              'capability_or_mapping','other_source_or_adapter','invalid_or_deprecated_source','future_sqlext_extension']
    output={'format':'recovery-evidence-scoreboard/1','source_commit':fresh['source_commit'],
            'fresh_inventory_sha256':sha256(a.inventory.read_bytes()).hexdigest(),
            'historical_archive_sha256':a.historical_sha256,'source_counts':fresh['counts'],
            'source_pattern_counts':fresh['pattern_rule_counts'],'historical_only':dict(historical),
            'current_attempts':dict(attempted),'current_ledger_receipts':receipts,'current_unattempted':fresh['counts']['source_rules']-attempted['source_rules'],
            'ranking':[{'cause':key,'historical_blocked_rules':len(root_causes[key]),
                       'benchmarks':dict(Counter(r['benchmark'] for r in root_causes[key])),
                       'qualification':'Historical blockers, matched to unchanged fresh source; current admission unattempted.'}
                      for key in priority if key in root_causes],
            'benchmarks':sorted(streams,key=lambda b:b['filename']),
            'historical_blocked_rules':dict(root_causes),'current_rules':current_rows,
            'limitations':['No65-stream conversion/compiler or library publication was run.',
                           'Source patterns overlap; they are obligations, not demonstrated current failures.',
                           'Historical proof hashes apply only to historical snapshots; no current proof promotion.',
                           'Current source XSD/Schematron verification is not implied by XML/reference inventory.']}
    if a.backlog_summary:
        backlog=json.loads(a.backlog_summary.read_text())
        recovered=backlog['statuses'].get('AUTOMATED_DRAFT',0)
        blocked=backlog['statuses'].get('BLOCKED',0)
        held=sum(backlog['held_without_conversion'].values())
        if recovered+blocked+held!=historical['BLOCKED_EXPLICIT']:p.error('backlog denominator mismatch')
        output['current_automated_backlog']={'historical_blocked':historical['BLOCKED_EXPLICIT'],
            'attempted':recovered+blocked,'recovered_draft':recovered,'still_blocked_after_attempt':blocked,
            'held_without_conversion':backlog['held_without_conversion'],'remaining_including_held':blocked+held,
            'current_primary_blockers':backlog['current_primary_blockers']}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({k:output[k] for k in ('source_counts','historical_only','current_attempts','current_unattempted')}))

if __name__=='__main__':main()
