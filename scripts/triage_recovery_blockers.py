#!/usr/bin/env python3
"""Source-pinned read-only classification of the PR15 remaining48 cases.

Writes only a compact ledger to a fresh output directory. Native drafts are
checked in memory; this is not a new library, compilation or source/scanner proof.
"""
import argparse
from collections import Counter,defaultdict
from hashlib import sha256
import json
from pathlib import Path


def triage(schema_root,source_root,cases,*,binary32_comparisons=False,approved_oracle_absence=False):
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    from scap_ng_tools.converter.direct04 import load_runtime
    from scap_ng_tools.converter.recovery04 import recover_benchmark,_classes
    from scap_ng_tools.converter._v04_semantic.validation import document_errors
    snapshot=FrozenSchemaSnapshot(schema_root);engine=load_runtime()
    from v04_direct_scap_source import digest,xml_identity
    from scap_ng_tools.converter.binary32 import require_contract
    binary32_contract=require_contract(snapshot.schema_root) if binary32_comparisons else None
    Source,Visitor=_classes(engine,binary32_contract=binary32_contract);groups=defaultdict(list);rows=[]
    for row in cases:
        name=row['filename']
        if Path(name).name!=name or not name.endswith('.zip'):raise ValueError('unsafe source filename')
        groups[name].append(row)
    for name,selected in sorted(groups.items()):
        pins={r['sha256'] for r in selected};ids=[r['source_rule'] for r in selected]
        if len(pins)!=1 or len(ids)!=len(set(ids)):raise ValueError('inconsistent source pins or duplicate Rules')
        pin=pins.pop();source=Path(source_root)/name
        _,recovery_trace,ledger=recover_benchmark(schema_root=snapshot.schema_root,source=source,sha256_pin=pin,rule_ids=ids,
                                    binary32_comparisons=binary32_comparisons,approved_oracle_absence=approved_oracle_absence)
        model=Source(source,pin,inventory_broken_references=True,draft_compatibility=True)
        mappings=snapshot.supported_mappings(engine.CAPABILITIES)
        for old,current in zip(selected,ledger['rules']):
            failures=[]
            CurrentVisitor=Visitor
            if approved_oracle_absence:
                from scap_ng_tools.converter.approved_absence import oracle_visitor
                CurrentVisitor=oracle_visitor(Visitor,model,current['source_rule'])
            class TraceVisitor(CurrentVisitor):pass
            for method in ('predicate','parameter','operand','convert_state','convert_object','convert_test','function'):
                def wrapped(name):
                    prior=getattr(CurrentVisitor,name)
                    def visit(self,element,*args,**kwargs):
                        try:return prior(self,element,*args,**kwargs)
                        except ValueError as error:
                            failures.append({'method':name,'message':str(error),'component':self.component_id,
                                'parsed_node':xml_identity(element),'parsed_node_sha256':digest(xml_identity(element))})
                            raise
                    return visit
                setattr(TraceVisitor,method,wrapped(method))
            extra=[]
            try:
                drafts,_=engine.convert_rule(model,current['source_rule'],mappings,converter_factory=TraceVisitor)
                extra=[e.message for d in drafts.values() for e in document_errors(snapshot,next(iter(d)),d)]
            except ValueError:pass
            related=[]
            failure=current['blockers'][0] if current['blockers'] else ''
            if failure.startswith('state capability mismatch:') and failures:
                cid=failures[0]['component'];state=model.nodes[cid][failure.split(': ',1)[1]]
                related.append({'kind':'referenced_state','parsed_node':xml_identity(state),'parsed_node_sha256':digest(xml_identity(state))})
            rows.append({'filename':name,'source_zip_sha256':pin,'source_rule':current['source_rule'],
                'source_rule_sha256':current['source_rule_sha256'],'pr15_blockers':old['pr15_blockers'],
                'status':current['status'],'blockers':current['blockers'],'manual_preserved':current['manual'],
                'schema_validated':current['schema_validated'],'semantic_validated':current['semantic_validated'],
                'first_failing_source_operation':failures[0] if failures else None,'related_source_nodes':related,
                'additional_native_diagnostics':extra,'compiled':False,'source_semantic_proof':False,'scanner_execution':False})
            if approved_oracle_absence:
                binding=next((b for b in recovery_trace['rules'] if b['source_rule']==current['source_rule']),{})
                rows[-1]['approved_source_corrections']=[w for w in binding.get('conversion_warnings',[])
                    if w['code']=='approved_oracle_absence_20261024']
    result={'format':'issue14-readonly-blocker-triage/1','read_only_source':True,
        'source_commit':'8c8e5dff860af6b1290ee9273a282db24278f8d5','schema':snapshot.manifest(),
        'recovery_adapter_sha256':sha256((Path(__file__).resolve().parents[1]/'src/scap_ng_tools/converter/recovery04.py').read_bytes()).hexdigest(),
        'counts':dict(Counter(r['status'] for r in rows)),'rules':rows,
        'qualification':'Focused authoring/source-witness classification; compiled/source-semantic/scanner flags remain false.'}
    if binary32_contract is not None:result['binary32_comparison_contract']=binary32_contract
    if approved_oracle_absence:result['approved_oracle_absence_enabled']=True
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--schema-root',required=True);p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--cases',type=Path,default=Path(__file__).resolve().parents[1]/'tests/fixtures/issue14-remaining48-pins.json')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--binary32-comparisons',action='store_true',help='explicit coordinated binary32 profile')
    p.add_argument('--approved-oracle-absence',action='store_true',help='exact existing Oracle source correction')
    a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    result=triage(a.schema_root,a.source_root,json.loads(a.cases.read_text()),binary32_comparisons=a.binary32_comparisons,
                  approved_oracle_absence=a.approved_oracle_absence)
    a.output.mkdir(parents=True)
    (a.output/'triage.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'cases':len(result['rules']),'counts':result['counts'],'scanner_execution':False}))


if __name__=='__main__':main()
