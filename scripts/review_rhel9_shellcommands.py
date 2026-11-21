#!/usr/bin/env python3
"""Ten strongest bounded-utility review sketches, NOT replacement approvals."""
from copy import deepcopy
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile
import yaml
from audit_rhel9_complexity import inputs,inventory,metrics,xml_identity,digest

MANUAL_SHA='1875de2543d01695c5a346c51888cc336113e9199bfe6726d74a08de286ca1ae'
CASES=[
 ('rhel-9-mount-var-log-nodev-f7f48307.yaml','mount','/var/log','nodev'),
 ('rhel-9-mount-tmp-nodev-option-5ecfec47.yaml','mount','/tmp','nodev'),
 ('rhel-9-mount-var-log-noexec-a8d745d7.yaml','mount','/var/log','noexec'),
 ('rhel-9-mount-var-log-nosuid-6e52943e.yaml','mount','/var/log','nosuid'),
 ('rhel-9-mount-var-log-audit-00e2206b.yaml','mount','/var/log/audit','nodev'),
 ('rhel-9-systems-using-domain-name-2c546f21.yaml','dns',None,None),
 ('rhel-9-implement-fips-140-3-952cd887.yaml','fips',None,None),
 ('rhel-9-cryptographic-policy-not-overridden-9ed0c15a.yaml','crypto',None,None),
 ('rhel-9-aide-package-installed-538959e6.yaml','aide',None,None),
 ('rhel-9-audit-uses-setxattr-fsetxattr-f8af9d42.yaml','audit',None,None)]

def quantifier(value):return {'values_found':'one_or_more','values_matching':'every',**value}

def shell_test(command,stdout=None,integer=False):
    fields={'exit_status':quantifier({'equals':0,'datatype':'integer'})}
    if stdout is not None:fields['stdout_line']=quantifier({'greater_than_or_equal':2,'datatype':'integer'} if integer else {'matches_regex':stdout})
    return {'test_title':'Audit sketch: bounded evidence collection, equivalence NOT established',
        'capability':'independent.shellcommand','object':{'shell':'bash','command':command,
        'error_if_exit_status_not_0':True,'error_if_stderr_exists':True},
        'require':{'item_requirement':{'items_found':'one_or_more','items_satisfying':'every'},
                   'field_requirement':{'values_found':'one_or_more','values_matching':'every'},'fields':fields},'reported_elements':'all'}

def group_requirement(test):
    test=deepcopy(test);req=test['require'];item={k:req.pop(k) for k in ('items_found','items_satisfying') if k in req}
    test['require']={'item_requirement':item,'field_requirement':{'values_found':'one_or_more','values_matching':'every'},**req};return test

def proposal(a,kind,mount,option,index):
    p={k:deepcopy(a[k]) for k in ('version','assessment_title','mode','class','specification') if k in a}
    p['id']=f'rhel9-shellcommand-audit-{index:02d}-assessment'
    sid='bounded-evidence-test'
    if kind=='mount':
        original=next(t for t in a['tests'].values() if t['capability']=='linux.partition')
        command=f'LC_ALL=C /usr/bin/findmnt --fstab --first-only --mountpoint {mount} --noheadings --raw --output OPTIONS'
        p['tests']={'mounted-option-test':group_requirement(original),sid:shell_test(command,'(^|,)'+option+'(,|$)')}
        p['evaluate']={'and':[{'test':'mounted-option-test'},{'test':sid}]}
    elif kind=='dns':
        original=next(t for t in a['tests'].values() if 'system-is-using-dns' in next(k for k,v in a['tests'].items() if v is t))
        command="set -o pipefail; LC_ALL=C /usr/bin/grep '^nameserver' /etc/resolv.conf | LC_ALL=C /usr/bin/sort -u | /usr/bin/wc -l"
        p['tests']={'uses-dns-test':group_requirement(original),sid:shell_test(command,'integer',integer=True)}
        p['evaluate']={'or':[{'not':{'test':'uses-dns-test'}},{'and':[{'test':'uses-dns-test'},{'test':sid}]}]}
    else:
        command,pattern={
          'fips':('LC_ALL=C /usr/bin/update-crypto-policies --show','^FIPS'),
          'crypto':('LC_ALL=C /usr/bin/update-crypto-policies --check',None),
          'aide':("LC_ALL=C /usr/bin/rpm -q --qf '%{NAME}\\n' aide",'^aide$'),
          'audit':('LC_ALL=C /usr/sbin/auditctl -l','(setxattr|fsetxattr|lsetxattr|removexattr|fremovexattr|lremovexattr)')}[kind]
        p['tests']={sid:shell_test(command,pattern)};p['evaluate']={'test':sid}
    return {'assessment':p},command

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('archive','source','manual'):p.add_argument('--'+key,required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.output.exists():p.error('refusing existing output')
    if sha256(Path(args.manual).read_bytes()).hexdigest()!=MANUAL_SHA:p.error('DISA manual SHA mismatch')
    with zipfile.ZipFile(args.manual) as z:
        member,=[n for n in z.namelist() if n.endswith('xccdf.xml')];manual_raw=z.read(member);root=ET.fromstring(manual_raw)
    manual_rules={n.get('id'):n for n in root.iter() if n.tag.endswith('}Rule')}
    docs,ledger,trace,rules,nodes=inputs(args.archive,args.source);inv=inventory(args.archive,args.source)
    byfile={Path(n).name:(n,raw) for n,raw in docs.items()};rows={r['id']:r for r in inv['rows']}
    bindings={r['assessment']:r for r in trace['rules']};args.output.mkdir(parents=True);candidates=[]
    normalize=lambda text:re.sub(r'\s+',' ',text).strip()
    for index,(filename,kind,mount,option) in enumerate(CASES,1):
        path,raw=byfile[filename];a=yaml.safe_load(raw)['assessment'];before=rows[a['id']];binding=bindings[a['id']]
        rule=rules[binding['source_rule']];manual_id=binding['source_rule'].removeprefix('xccdf_mil.disa.stig_rule_')
        manual=manual_rules[manual_id]
        manual_check='\n'.join(''.join(n.itertext()) for n in manual.iter() if n.tag.endswith('}check-content'))
        niwc_check='\n'.join(''.join(n.itertext()) for n in rule.iter() if n.tag.endswith('}check-content'))
        proposed,command=proposal(a,kind,mount,option,index);after=metrics(proposed['assessment'])
        directory=args.output/f'case-{index:02d}';directory.mkdir();(directory/'original.yaml').write_bytes(raw)
        (directory/'proposed-UNAPPROVED.yaml').write_text(yaml.safe_dump(proposed,sort_keys=False))
        source={'source_rule':binding['source_rule'],'source_rule_sha256':binding['source_rule_sha256'],
            'original_oval_nodes':{ident:{'sha256':meta['sha256'],'xml_identity':xml_identity(nodes[binding['component']][ident])} for ident,meta in binding['dependencies'].items()},
            'source_platforms':binding['source_platforms'],'disa_manual_member':member,'disa_manual_rule':manual_id,
            'disa_manual_rule_sha256':digest(xml_identity(manual)),'disa_check':manual_check,'niwc_check':niwc_check,
            'normalized_checks_identical':normalize(manual_check)==normalize(niwc_check),
            'check_comparison':'Whitespace normalization only; revision and full text retained. No fuzzy equivalence.'}
        (directory/'source.json').write_text(json.dumps(source,indent=2)+'\n')
        reduction=round(100*(before['score']-after['score'])/before['score'],2)
        reasons={
          'mount':['R1_reduction_below70','R6_literal_source_regex_and_parser_differences','R8_keep_simple_linux_partition'],
          'dns':['R6_missing_error_and_lexical_uniqueness_differ','R9_pipeline_failure_mapping','R1_reduction_below70'],
          'fips':['R6_loses_hash_RSA_and_negative_algorithm_obligations','R8_show_command_already_present'],
          'crypto':['R6_selected_policy_check_not_exact_FIPS_links_and_nss_type','R8_simple_native_symlink_file_checks'],
          'aide':['R4_original_requires_recursive_discovery','R6_package_presence_not_database_existence','R8_keep_simple_rpminfo'],
          'audit':['R4_audit_rule_enumeration','R5_equivalent_shell_would_recreate_complex_logic','R6_loses_arch_UID_and_persistent_obligations']}[kind]
        if reduction<70 and 'R1_reduction_below70' not in reasons:reasons.append('R1_reduction_below70')
        candidates.append({'rank':index,'directory':directory.name,'kind':kind,'id':a['id'],'source_rule':binding['source_rule'],
            'title':a['assessment_title'],'command':command,'mount':mount,'option':option,
            'before_score':before['score'],'after_score':after['score'],'apparent_reduction_percent':reduction,
            'reduction_at_least70':reduction>=70,'before_metric':{k:v for k,v in before.items() if k in ('parts','boolean_depth','variable_function_chain_depth')},
            'after_metric':after,'disposition':'REJECT_REPLACEMENT_SKETCH','reasons':reasons,
            'equivalence':'UNPROVED; component counterexamples and omitted obligations prevent recommendation',
            'runtime_equivalence_proved':False,'applicability_rule_binding':'Original Rule/profiles/platforms untouched; transplant not approved',
            'manual_check_normalized_identical':source['normalized_checks_identical'],
            'original_yaml_sha256':sha256(raw).hexdigest(),'proposed_yaml_sha256':sha256((directory/'proposed-UNAPPROVED.yaml').read_bytes()).hexdigest(),
            'semantic_assumptions':['Exact pinned source regex/instance/cardinality/status behavior is authoritative; no unescaping or default repair.',
                'Utility absolute path, version, locale, privileges, namespace and output framing require pinned RHEL9 verification.',
                'Multiple/empty/malformed output, stderr and nonzero exits need an explicit collector status crosswalk.',
                'Applicable Rule selection, exceptions and evidence cannot be replaced by an exit-code compliance decision.'],
            'outstanding_proofs':['Pinned RHEL9 utilities and SCAP collector differential execution','Original OVAL and native scanner error/unknown/not-collected propagation',
                'All omitted state/file/architecture conditions, duplicates and conflicts','Exact Rule/profile/applicability and evidence-level differential check']})
    shortlist={c['id'] for c in candidates}
    for row in inv['rows']:
        if row['id'] in shortlist:row['triage']='REJECTED_SHORTLIST_SKETCH'
        elif row['complex']:
            row['triage']='KEEP_NATIVE_STRUCTURAL_SCREEN'
            row['screen_reason']='set_filter_or_discovery_semantics' if row['set_count'] or row['filter_count'] or 'traversal' in row['semantic_operations'] else 'native_capability_or_multicondition_contract_not_a_bounded_utility_substitute'
    inv['summary']={'analyzed':len(inv['rows']),'complex':inv['complex_count'],'deep_reviewed':10,
        'promising_meets_all_criteria':0,'rejected_shortlist':10,'other_complex_screened_keep_native':inv['complex_count']-10,
        'shortlist_runtime_equivalence_unproved':10,'production_replacements':0}
    # Complete valid JSON, one assessment per line for manageable review diffs.
    head={k:v for k,v in inv.items() if k!='rows'}
    (args.output/'inventory.json').write_text(json.dumps(head,indent=2)[:-2]+',\n  "rows": [\n'+',\n'.join('    '+json.dumps(r,sort_keys=True) for r in inv['rows'])+'\n  ]\n}\n')
    report={'format':'rhel9-shellcommand-review/1','manual_zip_sha256':MANUAL_SHA,'manual_xml_sha256':sha256(manual_raw).hexdigest(),
        'manual_url':'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R9_STIG.zip',
        'ranking':'Bounded collector feasibility first; ten strongest avenues reviewed, not ten qualifying recommendations.',
        'summary':inv['summary'],'candidates':candidates}
    (args.output/'candidates.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'summary':inv['summary'],'cases':[(c['rank'],c['before_score'],c['after_score'],c['apparent_reduction_percent'],c['manual_check_normalized_identical']) for c in candidates]}))

if __name__=='__main__':main()
