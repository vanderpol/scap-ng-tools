#!/usr/bin/env python3
"""Optional native identity qualification of eight corrected drafts; no scanner."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys


def change_absence(node):
    if isinstance(node,dict):
        if node.get('values_found')=='none':
            node['values_found']='one_or_more';return True
        return any(change_absence(value) for value in node.values())
    if isinstance(node,list):return any(change_absence(value) for value in node)
    return False


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler-root',type=Path,required=True);p.add_argument('--compiler-commit',required=True)
    p.add_argument('--recovery',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.compiler_root,text=True).strip()
    if commit!=a.compiler_commit:p.error('compiler pin mismatch')
    sys.path.insert(0,str(a.compiler_root/'tools'))
    from v04_native_bundle_compiler import build_bundle,verify_bundle,compile_assessment_program
    from verify_v04_package_consumer import verify,program_contract
    from audit_v04_eight_assessment_pilot import verify_program
    recovery=json.loads((a.recovery/'recovery.json').read_text());a.output.mkdir(parents=True)
    results=[];totals={'packages':0,'documents':0,'programs':0,'tests':0,'manual_assessments':0,'rejected_mutants':0}
    for package in recovery['packages']:
        directory=package['directory']
        if not directory or Path(directory).name!=directory or directory in ('.','..'):
            raise ValueError('unsafe package directory')
        docs=json.loads((a.recovery/directory/'documents.json').read_text())
        raw,_=build_bundle(docs);target=a.output/directory;target.mkdir()
        bundle=target/'native.scapng';bundle.write_bytes(raw);local=verify_bundle(raw)
        source={(next(iter(d)),next(iter(d.values()))['id']):(name,d) for name,d in docs.items()}
        independent=verify(bundle,source=source);negatives=[];manuals=0
        for document in docs.values():
            assessment=document.get('assessment')
            if not assessment:continue
            if assessment['mode']=='manual':manuals+=1;continue
            program=compile_assessment_program(assessment)
            program_contract(assessment,program);verify_program(assessment,program)
            for kind in ('capability','absence-cardinality'):
                mutant=deepcopy(program);instruction=mutant['test_instructions'][0]
                if kind=='capability':instruction['capability']='windows.registry'
                elif not change_absence(instruction['operands']['require']):raise AssertionError('absence operand missing')
                try:verify_program(assessment,mutant)
                except ValueError as error:
                    negatives.append({'assessment':assessment['id'],'case':kind,'rejected':True,'diagnostic':str(error)})
                else:raise AssertionError('accepted program mutant: '+kind)
        results.append({'filename':package['filename'],'bundle_sha256':sha256(raw).hexdigest(),
            'compile':local,'independent_package_consumer':independent,'manual_assessments':manuals,
            'rejected_mutants':negatives})
        totals['packages']+=1
        for key in ('documents','programs','tests'):totals[key]+=local[key]
        totals['manual_assessments']+=manuals;totals['rejected_mutants']+=len(negatives)
    report={'format':'issue14-approved-absence-native-identity/1','compiler_commit':commit,
        'totals':totals,'results':results,'source_semantic_proof':False,'scanner_execution':False,
        'qualification':'Owner-corrected source/package/program identity only; not original OVAL/scanner equivalence.'}
    (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(totals))


if __name__=='__main__':main()
