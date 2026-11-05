#!/usr/bin/env python3
"""Check-text-first RHEL9 crosswalk. Parses commands as data; executes none."""
import argparse
from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
import re
import shlex
import xml.etree.ElementTree as ET
import zipfile
import yaml
from audit_rhel9_complexity import inputs,inventory,digest,xml_identity,walk
from review_rhel9_shellcommands import MANUAL_SHA

KNOWN_UTILITIES={'cat','more','less','tail','grep','egrep','fgrep','stat','sysctl','systemctl','sshd','gsettings',
    'postconf','postmap','rpm','dnf','findmnt','getenforce','sestatus','update-crypto-policies','chage','getent',
    'ls','lsblk','ip','nmcli','firewall-cmd','cryptsetup','auditctl','grubby','usbguard','pwck','opensc-tool',
    'systemd-analyze','gpg','find','awk','cut','df','mount','openssl','sort','uniq','wc',
    'NetworkManager','ssh-keygen','ss','logger'}
CONTROL={'|','||','&&',';','&'}

def command_stages(command):
    """Conservative lexical index, not a shell evaluator or safety approval."""
    try:
        lexer=shlex.shlex(command,posix=True,punctuation_chars='|&;');lexer.whitespace_split=True;lexer.commenters=''
        tokens=list(lexer)
    except ValueError as e:return [],str(e)
    pieces=[];current=[]
    for token in tokens:
        if token in CONTROL:
            if current:pieces.append(current);current=[]
        else:current.append(token)
    if current:pieces.append(current)
    stages=[]
    for words in pieces:
        words=list(words)
        while words and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*',words[0]):words.pop(0)
        if words and words[0]=='env':
            words.pop(0)
            while words and '=' in words[0]:words.pop(0)
        if words and Path(words[0]).name=='sudo':
            words.pop(0)
            while words and words[0].startswith('-'):
                option=words.pop(0)
                if option in ('-u','-g','--user','--group') and words:words.pop(0)
        if not words:continue
        utility=Path(words[0]).name
        if not re.fullmatch(r'[A-Za-z0-9_+.-]+',utility):continue
        stages.append({'utility':utility,'argv':words,'known_utility_family':utility in KNOWN_UTILITIES})
    return stages,None

def extract_commands(text):
    rows=[]
    for line_no,line in enumerate(text.splitlines(),1):
        # Whitespace after the prompt is required: $Action... is config output.
        match=re.match(r'^\s*[$#]\s+(.+?)\s*$',line)
        if not match:continue
        command=match.group(1);stages,error=command_stages(command)
        if not stages and not error:kind='configuration_or_empty'
        elif stages and stages[0]['utility'].endswith(':'):kind='prose'
        elif stages and stages[0]['utility'] in KNOWN_UTILITIES:kind='recognized_utility_prompt'
        else:kind='unclassified_prompt_needs_review'
        rows.append({'line':line_no,'original_line':line,'command':command,'kind':kind,'stages':stages,
            'lexical_error':error,'shape_flags':shape_flags(command,stages)})
    return rows

def shape_flags(command,stages):
    flags=set()
    for stage in stages:
        u=stage['utility'];args=stage['argv'][1:]
        if u in ('find','lsblk','df','mount') or (u=='auditctl' and any(a in ('-l','--list-rules') for a in args)):
            flags.add('enumeration_or_discovery')
        if u in ('grubby',) and any(a=='--info=ALL' for a in args):flags.add('enumeration_or_discovery')
        if u in ('grep','egrep','fgrep') and any(a in ('--recursive','--dereference-recursive') or
                (re.fullmatch(r'-[A-Za-z]+',a) and ('r' in a[1:] or 'R' in a[1:])) for a in args):
            flags.add('recursive_search')
        if any(a.startswith('/') and any(c in a for c in '*?[') for a in args):flags.add('possible_file_glob')
        if u in ('awk','sed','function','for','while'):flags.add('embedded_logic_needs_review')
        if u=='sshd' or u=='gsettings' or u=='systemd-analyze':flags.add('effective_context_or_defaults')
        if u in ('sudo',):flags.add('unresolved_wrapper')
        if u=='logger':flags.add('state_changing_probe')
        if u=='ss':flags.add('enumeration_or_discovery')
        if u in ('auditctl','dnf','systemctl','firewall-cmd','rpm','grubby','gsettings','postmap'):
            flags.add('utility_options_require_readonly_review')
    if len(stages)>1:flags.add('pipeline_or_control_flow_status_contract')
    if '$(' in command or '`' in command:flags.add('command_substitution')
    return sorted(flags)

def invokes(commands,utility):
    return any(s['utility']==utility for c in commands for s in c['stages'])

def native_details(a):
    shared=a.get('shared_objects',{});tests=[];sites=[]
    for ident,test in a['tests'].items():
        obj=test.get('object');resolved=shared.get(obj) if isinstance(obj,str) else obj
        tests.append({'id':ident,'test_title':test.get('test_title'),'capability':test['capability'],
            'object_reference':obj if isinstance(obj,str) else None,'object':resolved,'require':test['require'],
            'variable':test.get('variable'),'reported_elements':test.get('reported_elements')})
        if test['capability']=='independent.shellcommand' and isinstance(resolved,dict):
            sites.append({'site':'Test:'+ident,'object':resolved})
    for name,var in a.get('variables',{}).items():
        for node in walk(var):
            obj=node.get('object');obj=shared.get(obj) if isinstance(obj,str) else obj
            if isinstance(obj,dict) and obj.get('capability')=='independent.shellcommand':
                sites.append({'site':'Variable:'+name,'object':obj})
    for site in sites:
        command=site['object']['command']
        site['stages'],site['lexical_error']=command_stages(command) if isinstance(command,str) else ([],None)
        site['dynamic_command']=not isinstance(command,str)
    return {'assessment_id':a['id'],'tests':tests,'variables':a.get('variables',{}),
            'evaluate':a['evaluate'],'shellcommand_sites':sites}

def source_objects(old,nodes):
    objects=[]
    for dep in old['dependencies']:
        if dep['kind']!='object':continue
        node=nodes[dep['component']][dep['id']]
        if digest(xml_identity(node))!=dep['sha256']:raise ValueError('original Object hash mismatch')
        objects.append({'id':dep['id'],'component':dep['component'],'type':node.tag.rsplit('}',1)[-1],
            'sha256':dep['sha256'],'controls':[xml_identity(c) for c in node]})
    return objects

def object_texts(objects,element):
    result=[]
    for obj in objects:
        for control in obj['controls']:
            if control[0].endswith('}'+element) and isinstance(control[2],str):result.append(control[2])
    return sorted(set(result))

def crosswalk(archive,source,manual):
    if sha256(Path(manual).read_bytes()).hexdigest()!=MANUAL_SHA:raise ValueError('official manual SHA mismatch')
    docs,ledger,trace,rules,nodes=inputs(archive,source);inv=inventory(archive,source)
    scores={r['id']:r for r in inv['rows']};bindings={r['source_rule']:r for r in trace['rules']}
    originals={r['source_rule']:r for r in ledger['original_ledger']['rules']}
    native={}
    for path,raw in docs.items():
        a=yaml.safe_load(raw)['assessment'];native[a['id']]=(a,path,sha256(raw).hexdigest())
    with zipfile.ZipFile(manual) as z:
        member,=[n for n in z.namelist() if n.endswith('xccdf.xml')];root=ET.fromstring(z.read(member))
    manual_rules={n.get('id'):n for n in root.iter() if n.tag.endswith('}Rule')}
    rows=[];families=Counter();primary=Counter();audit_invocations=[]
    for rid,old in sorted(originals.items()):
        original=rules[rid];manual_id=rid.removeprefix('xccdf_mil.disa.stig_rule_');m=manual_rules[manual_id]
        if digest(xml_identity(original))!=old['source_rule_sha256']:raise ValueError('source Rule hash mismatch')
        text='\n'.join(''.join(c.itertext()) for c in m.iter() if c.tag.endswith('}check-content'))
        niwc='\n'.join(''.join(c.itertext()) for c in original.iter() if c.tag.endswith('}check-content'))
        commands=extract_commands(text);utilities=sorted({s['utility'] for c in commands for s in c['stages']})
        first=sorted({c['stages'][0]['utility'] for c in commands if c['kind']=='recognized_utility_prompt'})
        for name in utilities:families[name]+=1
        for name in first:primary[name]+=1
        objects=source_objects(old,nodes);paths=object_texts(objects,'filepath')
        types=sorted({o['type'] for o in objects});audit=invokes(commands,'auditctl')
        if rid in bindings:
            b=bindings[rid];a,path,rawhash=native[b['assessment']];details=native_details(a)
            details.update(path=path,yaml_sha256=rawhash,score=scores[a['id']]['score'],test_count=len(a['tests']),
                capabilities=sorted({t['capability'] for t in a['tests'].values()}))
            status='AUTOMATED_CONVERTED'
        else:
            details=None;status='MANUAL_ONLY_EXCLUDED' if not any(c['system']=='http://oval.mitre.org/XMLSchema/oval-definitions-5' for c in old['checks']) else 'AUTOMATED_NO_NATIVE_CONTENT'
        native_utilities=sorted({s['utility'] for site in details['shellcommand_sites'] for s in site['stages']}) if details else []
        tags=[]
        if audit and '/etc/audit/audit.rules' in paths:tags.append('AUDITCTL_LOADED_RULES_VS_PERSISTENT_FILE')
        if details and any(s['utility']=='auditctl' for site in details['shellcommand_sites'] for s in site['stages']):tags.append('AUDITCTL_ALREADY_SHELLCOMMAND')
        if details and details['shellcommand_sites']:tags.append('HAS_EXISTING_SHELLCOMMAND')
        if details and len(a['tests'])==1 and not details['shellcommand_sites']:tags.append('ALREADY_ONE_NATIVE_TEST')
        if 'sshd' in first and 'textfilecontent54_object' in types:tags.append('SSHD_EFFECTIVE_QUERY_VS_CONFIG_TEXT')
        if 'sysctl' in first and any(p.startswith('/etc/') for p in paths):tags.append('SYSCTL_RUNTIME_PLUS_PERSISTENT_NATIVE_INPUTS')
        if '/etc/audit/auditd.conf' in paths:tags.append('AUDITD_CONF_FIXED_FILE')
        if status!='AUTOMATED_CONVERTED':tags.append(status)
        if any('enumeration_or_discovery' in c['shape_flags'] or 'recursive_search' in c['shape_flags'] for c in commands):tags.append('MANUAL_COMMAND_SHAPE_CONFLICTS_WITH_PRIOR_REPLACEMENT_LIMITS')
        rows.append({'source_rule':rid,'manual_rule':manual_id,'title':old['title'],'status':status,
            'manual_rule_sha256':digest(xml_identity(m)),'source_rule_sha256':old['source_rule_sha256'],
            'official_check_text':text,'official_check_text_sha256':sha256(text.encode()).hexdigest(),
            'niwc_check_text_sha256':sha256(niwc.encode()).hexdigest(),
            'normalized_manual_check_identical':re.sub(r'\s+',' ',text).strip()==re.sub(r'\s+',' ',niwc).strip(),
            'commands':commands,'primary_command_families':first,'all_command_families':utilities,
            'auditctl_mentioned':'auditctl' in text,'auditctl_invoked':audit,
            'original_oval_objects':objects,'original_oval_object_types':types,'original_oval_filepaths':paths,
            'native':details,'native_command_families':native_utilities,'review_tags':tags,
            'historical_proof_level':old['proof_level'],'historical_program_sha256':old.get('program_sha256'),
            'source_platforms':bindings[rid]['source_platforms'] if rid in bindings else None,
            'disposition':'CROSS_REFERENCE_ONLY; no replacement or source correction authorized by this ledger'})
        if audit:audit_invocations.append(rows[-1])
    if len(rows)!=445 or len(manual_rules)!=445:raise ValueError('scope changed')
    prompt_count=sum(len(r['commands']) for r in rows)
    summary={'all_official_checks_cross_referenced':len(rows),'native_automated':sum(r['status']=='AUTOMATED_CONVERTED' for r in rows),
        'manual_only_excluded':sum(r['status']=='MANUAL_ONLY_EXCLUDED' for r in rows),'automated_without_native':sum(r['status']=='AUTOMATED_NO_NATIVE_CONTENT' for r in rows),
        'prompt_records':prompt_count,'recognized_utility_prompts':sum(c['kind']=='recognized_utility_prompt' for r in rows for c in r['commands']),
        'unclassified_prompts':sum(c['kind']=='unclassified_prompt_needs_review' for r in rows for c in r['commands']),
        'all_normalized_manual_checks_identical':all(r['normalized_manual_check_identical'] for r in rows),
        'auditctl_mentions':sum(r['auditctl_mentioned'] for r in rows),'auditctl_invocation_checks':len(audit_invocations),
        'auditctl_persistent_file_targets':sum('AUDITCTL_LOADED_RULES_VS_PERSISTENT_FILE' in r['review_tags'] for r in rows),
        'auditctl_already_shellcommand':sum('AUDITCTL_ALREADY_SHELLCOMMAND' in r['review_tags'] for r in rows),
        'auditctl_native_test_count':sum(r['native']['test_count'] for r in audit_invocations if r['native']),
        'auditctl_persistent_target_test_count':sum(r['native']['test_count'] for r in rows if 'AUDITCTL_LOADED_RULES_VS_PERSISTENT_FILE' in r['review_tags']),
        'native_assessments_with_shellcommand':sum(bool(r['native'] and r['native']['shellcommand_sites']) for r in rows),
        'native_shellcommand_collection_sites':sum(len(r['native']['shellcommand_sites']) for r in rows if r['native']),
        'tag_counts':dict(sorted(Counter(t for r in rows for t in r['review_tags']).items()))}
    return {'format':'rhel9-check-command-crosswalk/1','parent_analysis_commit':'14fd21039c026a4ef744c17cccc1f305040f42bb',
        'pins':{**inv['pins'],'manual_sha256':MANUAL_SHA},'summary':summary,
        'command_family_rule_counts':dict(primary.most_common()),'all_stage_family_rule_counts':dict(families.most_common()),
        'qualification':'All445 check texts inspected without complexity threshold. Lexical command index, not a shell safety/semantic-equivalence analyzer. No command executed.',
        'rows':rows}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('archive','source','manual'):p.add_argument('--'+arg,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    result=crosswalk(a.archive,a.source,a.manual);a.output.mkdir(parents=True)
    head={k:v for k,v in result.items() if k!='rows'}
    (a.output/'crosswalk.json').write_text(json.dumps(head,indent=2)[:-2]+',\n  "rows": [\n'+',\n'.join('    '+json.dumps(r,sort_keys=True) for r in result['rows'])+'\n  ]\n}\n')
    columns=['source_rule','title','status','manual_commands','native_test_count','native_score','native_capabilities','original_oval_filepaths','native_commands','review_tags']
    for name,selected in [('crosswalk.csv',result['rows']),('auditctl.csv',[r for r in result['rows'] if r['auditctl_invoked']])]:
        with (a.output/name).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=columns,lineterminator='\n');w.writeheader()
            for r in selected:
                n=r['native'];w.writerow({k:v for k,v in {'source_rule':r['source_rule'],'title':r['title'],'status':r['status'],
                    'manual_commands':' ; '.join(c['command'] for c in r['commands']),
                    'native_test_count':n['test_count'] if n else '', 'native_score':n['score'] if n else '',
                    'native_capabilities':', '.join(n['capabilities']) if n else '',
                    'original_oval_filepaths':', '.join(r['original_oval_filepaths']),
                    'native_commands':' ; '.join(str(s['object']['command']) for s in n['shellcommand_sites']) if n else '',
                    'review_tags':', '.join(r['review_tags'])}.items()})
    print(json.dumps(result['summary']))

if __name__=='__main__':main()
