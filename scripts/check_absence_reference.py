#!/usr/bin/env python3
"""Pinned upstream C component experiment, not an OpenSCAP/scanner run.

Extract two unmodified upstream functions into a small named-enum harness.
The experiment does not emulate collection or NIWC's shellcommand extension.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PIN='099cd84a0fa23c0e5d748e4e577c900c9b280623'


def function(text,name):
    start=text.index('oval_result_t '+name+'(');brace=text.index('{',start);level=1;end=brace+1
    while level:
        if text[end]=='{':level+=1
        elif text[end]=='}':level-=1
        end+=1
    return text[start:end]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--openscap-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.openscap_root,text=True).strip()!=PIN:p.error('source pin mismatch')
    paths=['src/OVAL/results/oval_resultTest.c','src/OVAL/results/oval_status_counter.c']
    raw=[(a.openscap_root/path).read_text() for path in paths]
    funcs=[function(raw[0],'ores_get_result_bychk'),function(raw[1],'oval_status_counter_get_result')]
    names=sorted(set(re.findall(r'\bOVAL_[A-Z_]+\b','\n'.join(funcs))))
    prelude='#include <stdio.h>\n#define oscap_seterr(...) ((void)0)\n#define dW(...) ((void)0)\n'
    prelude+='typedef int oval_result_t; typedef int oval_check_t; typedef int oval_existence_t;\n'
    prelude+='enum { '+','.join(name+'='+str(i+1) for i,name in enumerate(names))+' };\n'
    prelude+='struct oresults { int true_cnt,false_cnt,error_cnt,unknown_cnt,notappl_cnt,noteval_cnt; };\n'
    prelude+='struct oval_status_counter { int error_cnt,exists_cnt,does_not_exist_cnt,not_collected_cnt; };\n'
    main=r'''
int main(void) {
 struct oval_status_counter counts={0}; struct oresults values={0};
 int existence=oval_status_counter_get_result(&counts,OVAL_NONE_EXIST);
 int empty=ores_get_result_bychk(&values,OVAL_CHECK_ALL);
 printf("%d %d\n",existence==OVAL_RESULT_TRUE,empty==OVAL_RESULT_UNKNOWN);
 counts.does_not_exist_cnt=1; values.false_cnt=1;
 int dne=oval_status_counter_get_result(&counts,OVAL_NONE_EXIST);
 int all=ores_get_result_bychk(&values,OVAL_CHECK_ALL);
 printf("%d %d\n",dne==OVAL_RESULT_TRUE,all==OVAL_RESULT_FALSE);
 return 0;
}
'''
    source=prelude+'\n'.join(funcs)+main
    compiler=shutil.which('cc')
    if not compiler:p.error('C compiler unavailable')
    with tempfile.TemporaryDirectory() as temp:
        path=Path(temp)/'reference.c';path.write_text(source);program=Path(temp)/'reference'
        subprocess.run([compiler,'-std=c99',str(path),'-o',str(program)],check=True)
        output=subprocess.check_output([str(program)],text=True)
    if output!='1 1\n1 1\n':raise AssertionError(output)
    result={'format':'issue14-absence-independent-C-components/1','openscap_commit':PIN,
        'source_files':{path:sha256((a.openscap_root/path).read_bytes()).hexdigest() for path in paths},
        'extracted_function_hashes':[sha256(f.encode()).hexdigest() for f in funcs],
        'empty_population':{'existence_piece':'true','empty_all_value_aggregate':'unknown','native_comparator_free_absence':'true'},
        'does_not_exist_entity':{'existence_piece':'true','per_entity_status_comparison':'false (upstream _evaluate_sysent early return)','all_value_aggregate':'false'},
        'limitation':'Exact upstream component functions with named-enum stubs. Not a full evaluator/collector/NIWC shellcommand run, nor normative resolution of omitted empty rows.',
        'lossless_comparator_elision_established':False,'scanner_execution':False}
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
