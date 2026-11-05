#!/usr/bin/env python3
"""Bounded fixture/component experiments; never a scanner-equivalence oracle."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import yaml

def run(argv,*,deny=False):
    options={}
    if deny and os.geteuid()==0:options={'user':65534,'group':65534,'extra_groups':[]}
    result=subprocess.run(argv,capture_output=True,text=True,timeout=10,env={**os.environ,'LC_ALL':'C'},**options)
    return {'argv':argv,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
            'privilege':'uid65534' if options else 'current_uid'}

def command_result(result,pattern=None,count=False):
    if result['exit'] or result['stderr']:return 'error'
    lines=result['stdout'].splitlines()
    if not lines:return 'false'
    if count:
        try:return str(all(int(line)>=2 for line in lines)).lower()
        except ValueError:return 'error'
    return str(all(re.search(pattern,line) is not None for line in lines)).lower()

def fixtures(case,directory,output):
    a=yaml.safe_load((directory/'original.yaml').read_text())['assessment'];kind=case['kind']
    shared=next(iter(a['shared_objects'].values()));pattern=shared['pattern']['matches_regex']
    source=json.loads((directory/'source.json').read_text())
    def source_patterns(n):
        if n[0].endswith('}pattern'):yield n[2]
        for child in n[3]:yield from source_patterns(child)
    if not any(pattern==p for node in source['original_oval_nodes'].values() for p in source_patterns(node['xml_identity'])):
        raise AssertionError('native/source OVAL regex mismatch')
    rows=[];labels=('positive','negative','missing','malformed','duplicate','conflicting','permission-denied')
    mount=case.get('mount');option=case.get('option')
    for label in labels:
        if kind=='mount':
            line=f'/dev/test {mount} xfs rw,{option} 0 0\n'
            text={'positive':line,'negative':f'/dev/test {mount} xfs rw 0 0\n','missing':None,
                'malformed':f'/dev/test {mount} xfs rw,{option}\n','duplicate':line+line,
                'conflicting':line+f'/dev/other {mount} xfs rw 0 0\n','permission-denied':line}[label]
        else:
            line='nameserver 192.0.2.1\nnameserver 192.0.2.2\n'
            text={'positive':line,'negative':'nameserver 192.0.2.1\n','missing':None,
                'malformed':'nameserverBROKEN one\nnameserverBROKEN two\n',
                'duplicate':'nameserver 192.0.2.1\nnameserver 192.0.2.1\n',
                'conflicting':'nameserver 192.0.2.1\nnameserver\t192.0.2.1\n','permission-denied':line}[label]
        with tempfile.TemporaryDirectory(prefix='rhel9-audit-') as tmp:
            folder=Path(tmp);folder.chmod(0o755);path=folder/'input'
            if text is not None:path.write_text(text)
            if label=='permission-denied':path.chmod(0)
            denied=label=='permission-denied'
            if kind=='mount':argv=['/usr/bin/findmnt','--fstab','--tab-file',str(path),'--first-only','--mountpoint',mount,'--noheadings','--raw','--output','OPTIONS']
            else:argv=['/bin/bash','-c',f"set -o pipefail; LC_ALL=C /usr/bin/grep '^nameserver' '{path}' | LC_ALL=C /usr/bin/sort -u | /usr/bin/wc -l"]
            actual=run(argv,deny=denied)
            if denied:
                # An actual unprivileged EACCES witness, not chmod under root.
                denied_read=run(['/bin/cat',str(path)],deny=True)
                if denied_read['exit']==0:raise AssertionError('permission-denied fixture unexpectedly readable')
                before='error';matches=[];pcre=None
            elif text is None:before='false';matches=[];pcre=None
            else:
                matches=re.findall(pattern,text,re.MULTILINE)
                if kind=='mount':before=str(bool(matches) and option in matches[0].split(',')).lower()
                else:before=str(len(set(matches))>=2).lower()
                pcre=run(['/usr/bin/grep','-P',pattern,str(path)])
                if (pcre['exit']==0)!=bool(matches):raise AssertionError('independent regex engines disagree')
            after=command_result(actual,'(^|,)'+option+'(,|$)' if option else None,count=kind=='dns')
            rows.append({'case':label,'fixture_text':text,'source_regex_verbatim':pattern,'source_capture_values':matches,
                'source_component_model':before,'proposed_component_model':after,'same':before==after,
                'execution':actual,'independent_PCRE':pcre,
                'source_model_scope':'Pinned scalar regex/instance1/split or unique-count component; other source conditions assumed true, not a full OVAL evaluator.',
                'execution_scope':'Real Debian utility on synthetic bounded file. Not RHEL9 or SCAP collector/native scanner differential.'})
    return rows

def abstract_witnesses(case):
    # Literal independent expectations for obligations visible in source.json:
    # required native conjuncts can fail even when the short utility succeeds.
    obligation={'fips':'minimum RSA/hash/negative algorithm constraints',
        'crypto':'exact FIPS backend targets and NSS regular-file type',
        'aide':'configured working database existence via discovered aide.conf',
        'audit':'all architecture/UID/syscall persistent-rule conditions'}[case['kind']]
    expected=[('positive','true','true'),('negative','false','false'),('missing','false','true'),
        ('malformed','false','true'),('duplicate','false','true'),('conflicting','false','true'),('permission-denied','error','true')]
    return [{'case':label,'source_expected':old,'proposed_expected':new,'same':old==new,
        'omitted_obligation':obligation,'utility_status_assumption':'0, relevant positive output; negative case supplies negative/no matching output',
        'witness_type':'Abstract independent conjunction/omitted-obligation countermodel, NOT executed utility/evaluator evidence',
        'realization_required':'Instantiate exact source fixtures and utility behavior on pinned RHEL9 before any runtime claim.'} for label,old,new in expected]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--review',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.output.exists():p.error('refusing existing output')
    review=json.loads((args.review/'candidates.json').read_text());rows=[]
    for case in review['candidates']:
        if case['kind'] in ('mount','dns'):w=fixtures(case,args.review/case['directory'],args.output)
        else:w=abstract_witnesses(case)
        rows.append({'rank':case['rank'],'source_rule':case['source_rule'],'kind':case['kind'],'cases':w,
            'not_collected_unknown':'NOT simulated by empty stdout. Collector completeness/unknown propagation remains unproved.',
            'full_original_OVAL_native_scanner_equivalence':False})
    result={'format':'rhel9-shellcommand-component-witnesses/1',
        'host_os_release':Path('/etc/os-release').read_text(),'findmnt_version':run(['/usr/bin/findmnt','--version']),
        'utility_availability':{name:shutil.which(name) for name in ('findmnt','sshd','oscap','update-crypto-policies','rpm','auditctl')},
        'concrete_fixture_cases':42,'abstract_cases':28,'scanner_runtime_equivalence':False,'cases':rows}
    # Remove incidental random temp paths while preserving commands and results.
    rendered=re.sub(r'/tmp/rhel9-audit-[^/\s\x22\x27]+','<temporary-fixture-directory>',json.dumps(result,indent=2))
    args.output.write_text(rendered+'\n');print(json.dumps({'concrete_fixture_cases':42,'abstract_cases':28,'scanner_runtime_equivalence':False}))

if __name__=='__main__':main()
