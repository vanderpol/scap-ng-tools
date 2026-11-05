#!/usr/bin/env python3
"""Read-only audit-pattern comparison and two explicitly unproved review sketches."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import yaml
from audit_rhel9_complexity import metrics

def fold_constant(node,variables,seen=()):
    if isinstance(node,str):return node
    if ('literal' in node and node['literal'].get('datatype')=='string'
            and isinstance(node['literal'].get('value'),str)):return node['literal']['value']
    if 'concat' in node:return ''.join(fold_constant(n,variables,seen) for n in node['concat'])
    if 'variable' in node:
        name=node['variable']
        if name in seen:raise ValueError('cyclic constant reference')
        return fold_constant(variables[name]['expression'],variables,seen+(name,))
    raise ValueError('not a proven constant-string expression')

def patterns(row):
    n=row['native'];result=[]
    for test in n['tests']:
        obj=test['object']
        if test['require']!={'items_found':'one_or_more'}:raise ValueError('not a presence-only Test')
        if obj['full_path']!={'equals':'/etc/audit/audit.rules'}:raise ValueError('not the fixed audit.rules selector')
        if obj['instance'] not in ({'equals':1,'datatype':'integer'},{'greater_than_or_equal':1,'datatype':'integer'}):
            raise ValueError('instance semantics require separate review')
        raw=fold_constant(obj['pattern']['matches_regex'],n['variables'])
        flags=('i' if obj.get('ignore_case') else '')+('m' if obj.get('multiline') else '')+('s' if obj.get('singleline') else '')
        regex=('(?'+flags+')' if flags else '')+raw
        result.append({'original_test':test['id'],'raw_regex':raw,'effective_regex':regex,
            'raw_regex_sha256':sha256(raw.encode()).hexdigest(),'folded_variable':isinstance(obj['pattern']['matches_regex'],dict)})
    return result

def and_tests(expression):
    if set(expression)=={'test'}:return [expression['test']]
    if set(expression)=={'and'}:return [t for e in expression['and'] for t in and_tests(e)]
    raise ValueError('not a pure conjunction; do not flatten')

def python_matches(regex,text):return re.search(regex,text) is not None

def pcre_matches(regex,text):
    p=subprocess.run(['/usr/bin/grep','-zP',regex],input=text,text=True,capture_output=True,
                     timeout=5,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    if p.returncode not in (0,1):raise ValueError(p.stderr)
    return p.returncode==0

def example_text(row):
    return '\n'.join(line.strip() for line in row['official_check_text'].splitlines() if re.match(r'^\s*-(?:a|w)\s',line))+'\n'

def input_status_probes():
    """Observe OS errors only; native collector status conversion remains unproved."""
    rows=[]
    program="import pathlib,sys\ntry:\n pathlib.Path(sys.argv[1]).read_bytes()\nexcept OSError as e:\n print(e.errno)\n"
    with tempfile.TemporaryDirectory(prefix='rhel9-audit-status-') as tmp:
        root=Path(tmp);root.chmod(0o755);denied=root/'denied';denied.write_text('synthetic fixture');denied.chmod(0)
        for label,path,expected in [('missing-file',root/'missing',2),('permission-denied',denied,13)]:
            kwargs={'user':65534,'group':65534,'extra_groups':[]} if os.geteuid()==0 else {}
            p=subprocess.run([sys.executable,'-c',program,str(path)],capture_output=True,text=True,timeout=5,**kwargs)
            if p.returncode or p.stdout.strip()!=str(expected):raise AssertionError('OS status probe failed: '+label)
            rows.append({'case':label,'observed_os_errno':expected,'privilege':'uid65534' if kwargs else 'current uid',
                'native_collector_and_scanner_executed':False,
                'qualification':'Real OS input failure only. Native status/require propagation remains a required differential proof.'})
    return rows

def make_proposal(row,patterns,kind):
    conditions=[{'fields':{('text' if kind=='same-file-native' else 'stdout_line'):{
        'matches_regex':p['effective_regex'],'values_found':'one_or_more','values_matching':'one_or_more'}}} for p in patterns]
    if kind=='same-file-native':
        obj={'full_path':{'equals':'/etc/audit/audit.rules'},'pattern':{'matches_regex':r'(?s)\A.*\Z'},
            'instance':{'equals':1,'datatype':'integer'},'ignore_case':False,'multiline':False,'singleline':True,
            'item_creation':'all_object_elements_fullfilled','filesystem':'all'}
        capability='independent.textfilecontent54'
    else:
        obj={'shell':'bash','command':'LC_ALL=C /usr/sbin/auditctl -l',
             'error_if_exit_status_not_0':True,'error_if_stderr_exists':True}
        capability='independent.shellcommand'
        conditions.insert(0,{'fields':{'exit_status':{'equals':0,'datatype':'integer'}}})
    return {'assessment':{'id':'rhel9-audit-xattr-'+kind+'-review-assessment','version':1,
        'assessment_title':row['title']+' UNPROVED audit sketch.','mode':'automated','class':'compliance',
        'specification':{'id':'scap-ng.pre-alpha.assessment','version':'0.4.0'},
        'tests':{'all-required-patterns-test':{'test_title':'All24 original regex obligations retained independently',
            'capability':capability,'object':obj,
            'require':{'item_requirement':{'items_found':'one_or_more','items_satisfying':'every'},
                'field_requirement':{'values_found':'one_or_more','values_matching':'every'},'and':conditions},
            'reported_elements':'all'}},'evaluate':{'test':'all-required-patterns-test'}}}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--crosswalk',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    x=json.loads(a.crosswalk.read_text());selected=[r for r in x['rows'] if 'AUDITCTL_LOADED_RULES_VS_PERSISTENT_FILE' in r['review_tags']]
    a.output.mkdir(parents=True);screen=[]
    for row in selected:
        ps=patterns(row)
        if set(and_tests(row['native']['evaluate']))!={t['id'] for t in row['native']['tests']}:raise ValueError('unused Test')
        text=example_text(row);matches=[]
        for pattern in ps:
            py=python_matches(pattern['effective_regex'],text);pc=pcre_matches(pattern['effective_regex'],text)
            if py!=pc:raise AssertionError('independent regex engines disagree')
            matches.append(py)
        screen.append({'source_rule':row['source_rule'],'native_test_count':len(ps),
            'printed_manual_examples':text,'pattern_matches':matches,'all_patterns_match':all(matches),
            'qualification':'Real PCRE/Python regex components on printed manual examples; not auditctl/OVAL/native scanner execution.'})
    target=next(r for r in selected if 'SV-258179r' in r['source_rule']);ps=patterns(target)
    # Algebraic comparison for complete scalar file snapshots only. It does not
    # implement a collector, completeness model or six-state scanner evaluator.
    base=example_text(target)
    content_cases=[('positive',base),('negative_missing_b32','\n'.join(l for l in base.splitlines() if 'arch=b32' not in l)+'\n'),
        ('empty',''),('malformed_line_split',base.replace('arch=b32 -S','arch=b32\n-S',1)),
        ('duplicate',base+base),('conflicting_extra_line',base+'-a never,exit -F arch=b64 -S setxattr\n')]
    fixtures=[]
    for name,text in content_cases:
        source=[pcre_matches(p['effective_regex'],text) for p in ps]
        collected=re.search(r'(?s)\A.*\Z',text).group(0)
        proposed=[python_matches(p['effective_regex'],collected) for p in ps]
        if source!=proposed:raise AssertionError('whole-file proposal changed a regex obligation')
        fixtures.append({'case':name,'input':text,'original_24_obligations':source,'proposed_24_obligations':proposed,
            'same_component_result':source==proposed,'result':all(source),
            'qualification':'Complete-file regex component equivalence only; no native collector run.'})
    sketches=[]
    for kind in ('same-file-native','runtime-shell'):
        proposed=make_proposal(target,ps,kind);directory=a.output/('case-'+kind);directory.mkdir()
        (directory/'proposed-UNAPPROVED.yaml').write_text(yaml.safe_dump(proposed,sort_keys=False))
        after=metrics(proposed['assessment']);before=target['native']['score']
        sketches.append({'kind':kind,'directory':directory.name,'before_score':before,'after_score':after['score'],
            'apparent_structural_reduction_percent':round(100*(before-after['score'])/before,2),
            'tests_before':24,'tests_after':1,'original_regex_obligations_before':24,'original_regex_obligations_after':24,
            'folded_constant_variables':sum(p['folded_variable'] for p in ps),
            'raw_regex_mapping':ps,'metric_after':after,'native_scanner_equivalence':'UNPROVED',
            'blockers':(['Whole-file capture/status/completeness and regex-flag semantics need independent native runtime proof',
                'No claim of70% less semantic work: all24 obligations remain'] if kind=='same-file-native' else
                ['Owner decision: loaded rules instead of persisted audit.rules',
                 'Original no-enumeration criterion excludes auditctl -l unless explicitly excepted',
                 'Multi-line Item/field framing, canonicalized output and permission/error contracts unproved'])})
    output={'format':'rhel9-audit-pattern-review/1','source_rule':target['source_rule'],'summary':{
        'source_pattern_tests_checked':sum(len(r['pattern_matches']) for r in screen),'rules_checked':len(screen),
        'all_printed_example_patterns_match':all(r['all_patterns_match'] for r in screen),
        'full_scanner_equivalence_proofs':0},'printed_example_screen':screen,'controlled_snapshot_fixtures':fixtures,
        'input_status_probes':input_status_probes(),
        'status_cases_requiring_native_runtime':['missing file','permission denied','not collected/unknown','partial/incomplete collection','concurrent writes and snapshot boundaries'],
        'sketches':sketches,'production_changes':0}
    (a.output/'pattern-review.json').write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'summary':output['summary'],'sketches':[{k:s[k] for k in ('kind','before_score','after_score','apparent_structural_reduction_percent')} for s in sketches]}))

if __name__=='__main__':main()
