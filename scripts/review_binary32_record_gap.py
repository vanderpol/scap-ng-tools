#!/usr/bin/env python3
"""Independent record-argument profile witness for native PR278; no scanner."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.compiler_root,text=True).strip()
    if commit!='855c6023d55d882b55c0507d5492e6f4e4946023':p.error('review target changed')
    sys.path.insert(0,str(a.compiler_root/'tools'))
    from v04_native_bundle_compiler import compile_assessment_program
    from verify_v04_package_consumer import program_contract,float_comparisons
    from v04_float_comparisons import float_inventory
    from validate_native_json_schemas import build_validators,document_errors
    validator=build_validators(a.compiler_root/'schema/v0.4.0')['assessment.schema.json'];rows=[]
    for value in (1.25,1.2):
        document={'assessment':{'id':'record-input-assessment','version':1,'assessment_title':'Record input witness',
            'specification':{'id':'scap-ng.pre-alpha.assessment','version':'0.4.0'},'mode':'automated',
            'tests':{'record-input-test':{'test_title':'Typed argument','capability':'windows.cmdlet',
                'object':{'module_name':None,'module_id':None,'module_version':None,'verb':'Get','noun':'Item',
                    'parameters':{'fields':{'Threshold':{'float_equals':value,'selection_match':'one_or_more'}}},'select':None},
                'require':{'item_requirement':{'items_found':'one_or_more'}},'reported_elements':'all'}},
            'evaluate':{'test':'record-input-test'}}}
        errors=[error.message for error in document_errors(validator,document)]
        program=compile_assessment_program(document['assessment']);program_contract(document['assessment'],program)
        rows.append({'document':document,'validation_errors':errors,'program_format':program['format'],
            'compiler_inventory':float_inventory(document['assessment']),
            'independent_reader_inventory':float_comparisons(document['assessment']),
            'contract_bound':'binary32_comparison_contract' in program})
    result={'format':'issue14-binary32-independent-review-gap/1','compiler_commit':commit,'cases':rows,
        'finding':'Valid cmdlet API record predicates evade float inventory and finite-canonical validation. Canonical1.25 lacks program binding; noncanonical1.2 is accepted. Both visitors miss the same grammar site.',
        'merge_blocker':True,'scanner_execution':False}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'cases':len(rows),'merge_blocker':True,'formats':[r['program_format'] for r in rows]}))


if __name__=='__main__':main()
