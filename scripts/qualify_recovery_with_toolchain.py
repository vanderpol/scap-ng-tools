#!/usr/bin/env python3
"""Optional external compiler qualification, never a package runtime dependency.

Use an explicitly pinned compatible native toolchain. Package consistency and
external-source comparison do not establish original OVAL/scanner equivalence.
"""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler-root',type=Path,required=True);p.add_argument('--compiler-commit',required=True)
    p.add_argument('--documents',type=Path,required=True);p.add_argument('--ledger',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--derive-maps',action='store_true')
    p.add_argument('--negatives',action='store_true')
    a=p.parse_args()
    if a.output.exists():p.error('output exists; refusing overwrite')
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.compiler_root,text=True).strip()!=a.compiler_commit:
        p.error('external compiler source commit mismatch')
    sys.path.insert(0,str(a.compiler_root/'tools'))
    from v04_native_bundle_compiler import build_bundle,verify_bundle
    from verify_v04_package_consumer import verify
    docs=json.loads(a.documents.read_text());ledger=json.loads(a.ledger.read_text())
    if a.derive_maps:
        for doc in docs.values():
            if 'rule' in doc and 'automated' in doc['rule']['assessment_choices']:
                doc['rule'].pop('organizational_input_requirements',None)
    raw,manifest=build_bundle(docs);a.output.mkdir(parents=True)
    bundle=a.output/'native.scapng';bundle.write_bytes(raw)
    source={(next(iter(d)),next(iter(d.values()))['id']):(name,d) for name,d in docs.items()}
    local=verify_bundle(raw);independent=verify(bundle,source=source)
    negative=[]
    if a.negatives:
        for kind in ('missing-required','unknown-binding','missing-parameter','datatype','cardinality','dishonest-map','wrong-pointer-kind'):
            d=deepcopy(json.loads(a.documents.read_text()))
            rule=next(x['rule'] for x in d.values() if 'rule' in x and 'sv-241989' in x['rule']['id'])
            binding=rule['assessment_choices']['automated'];name=next(iter(binding['inputs']))
            bench=next(x['benchmark'] for x in d.values() if 'benchmark' in x)
            parameter_id=binding['inputs'][name]['parameter'];parameter=next(x for x in bench['parameters'] if x['id']==parameter_id)
            if kind=='missing-required':binding['inputs'].pop(name)
            elif kind=='unknown-binding':binding['inputs']['unresolved-input']=binding['inputs'].pop(name)
            elif kind=='missing-parameter':binding['inputs'][name]['parameter']='unresolved-parameter'
            elif kind=='datatype':parameter['datatype']='boolean'
            elif kind=='cardinality':parameter['cardinality']='zero_or_more'
            elif kind=='dishonest-map':rule['organizational_input_requirements']={}
            else:rule['organizational_input_requirements']['automated'][0]['uses'][0]['kind']='presence'
            try:build_bundle(d)
            except ValueError as e:negative.append({'case':kind,'rejected':True,'diagnostic':str(e)})
            else:raise AssertionError('accepted invalid case: '+kind)
        # Explicitly controlled optional-policy derivative; original required
        # source and its proof status remain unchanged.
        d=deepcopy(json.loads(a.documents.read_text()))
        rule=next(x['rule'] for x in d.values() if 'rule' in x and 'sv-241989' in x['rule']['id'])
        binding=rule['assessment_choices']['automated'];name=next(iter(binding['inputs']))
        assessment=next(x['assessment'] for x in d.values() if x.get('assessment',{}).get('id')==binding['assessment'])
        assessment['inputs'][name]['required']=False
        original=deepcopy(assessment['evaluate'])
        assessment['evaluate']={'if':{'input_provided':name},'then':original,'else':{'not_evaluated':{'reason':'Controlled omitted optional Input fixture'}}}
        rule.pop('organizational_input_requirements',None)
        guarded,_=build_bundle(d);verify_bundle(guarded)
        assessment['evaluate']=original
        try:build_bundle(d)
        except ValueError as e:negative.append({'case':'unguarded-optional-controlled-derivative','rejected':True,'diagnostic':str(e)})
        else:raise AssertionError('accepted unguarded optional derivative')
    for row in ledger['rules']:
        if row['status'] in ('AUTOMATED_DRAFT','MANUAL'):row['compiled']=True
    report={'compiler_commit':a.compiler_commit,'bundle_sha256':sha256(raw).hexdigest(),
            'compile':local,'independent_package_consumer':independent,'negative_cases':negative,
            'source_semantic_proof':False,'scanner_execution':False,'derived_maps':a.derive_maps}
    (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    (a.output/'qualified-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
    print(json.dumps(report))

if __name__=='__main__':main()
