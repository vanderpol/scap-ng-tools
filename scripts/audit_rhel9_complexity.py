#!/usr/bin/env python3
"""Read-only, pinned RHEL9 audit. Never converts or rewrites production content."""
import argparse
from collections import Counter
from hashlib import sha256
import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile
import yaml

ARCHIVE_SHA='a01ea589501bf8a53e5df68e50ca9478f19543d2bd3844546667fde743c28d8c'
SOURCE_SHA='70aa6a16221df2c53b094b11b48b16aca1f6d7147c11123b655659ca7711dbb5'
KEY='red-hat-enterprise-linux-9-stig-scap-benchmark-n-e258b4d9'
PREFIX='scap-ng-normalized-review/'
COMPARISONS={'equals','not_equal','case_insensitive_equals','matches_regex','greater_than','greater_than_or_equal',
             'less_than','less_than_or_equal','contains','subset_of','superset_of','bitwise_and','bitwise_or'}
BOOLEANS={'and','or','not','if','all','any','one','xor'}
QUANTIFIERS={'items_found','items_satisfying','values_found','values_matching','value_match','selection_match',
             'records_found','records_matching'}

def digest(value):
    return sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()

def xml_identity(e):
    return [e.tag,sorted(e.attrib.items()),e.text if not len(e) else None,[xml_identity(c) for c in e]]

def walk(node):
    if isinstance(node,dict):
        yield node
        for value in node.values():yield from walk(value)
    elif isinstance(node,list):
        for value in node:yield from walk(value)

def bool_depth(node):
    if isinstance(node,dict):return int(bool(BOOLEANS & node.keys()))+max([bool_depth(v) for v in node.values()]+[0])
    if isinstance(node,list):return max([bool_depth(v) for v in node]+[0])
    return 0

def stripped(node):
    if isinstance(node,dict):return {k:stripped(v) for k,v in node.items() if not k.endswith('_title')}
    if isinstance(node,list):return [stripped(v) for v in node]
    return node

def metrics(a):
    tests=a.get('tests',{});variables=a.get('variables',{});shared=a.get('shared_objects',{})
    # Declaration names are identifiers, never operator tokens (e.g. Test "one").
    executable=[*tests.values(),*variables.values(),*shared.values(),a.get('evaluate',{})]
    nodes=list(walk(executable));operations=set();collections=[];sets=filters=functions=0
    for n in nodes:
        for k,v in n.items():
            if k in COMPARISONS or k.endswith(('_equals','_greater_than','_greater_than_or_equal','_less_than','_less_than_or_equal')):
                operations.add('compare:'+k)
            if k in BOOLEANS:operations.add('boolean:'+k)
            if k in QUANTIFIERS:operations.add(k+':'+str(v))
        if 'capability' in n:operations.add('capability:'+n['capability'])
        if 'function' in n:
            functions+=1;operations.add('function:'+n['function']['name'])
        if 'concat' in n:functions+=1;operations.add('function:concat')
        if 'set' in n:sets+=1;operations.add('set:'+str(n['set'].get('operator')))
        if isinstance(n.get('filters'),list):filters+=len(n['filters']);operations.add('filter')
        if 'traversal' in n:operations.add('traversal')
    def chain(n,seen=()):
        if isinstance(n,dict):
            if isinstance(n.get('variable'),str) and n['variable'] in variables:
                name=n['variable']
                if name in seen:raise ValueError('cyclic variable dependency')
                return 1+chain(variables[name].get('expression',{}),seen+(name,))
            return int('function' in n or 'concat' in n)+max([chain(v,seen) for v in n.values()]+[0])
        if isinstance(n,list):return max([chain(v,seen) for v in n]+[0])
        return 0
    def objects(n):
        found=[]
        for d in walk(n):
            obj=d.get('object')
            if isinstance(obj,str):obj=shared.get(obj)
            if isinstance(obj,dict):found.append(digest(stripped(obj)))
        return found
    for test in tests.values():collections+=objects(test)
    for var in variables.values():collections+=objects(var)
    counts=Counter(collections);repeated=sum(v-1 for v in counts.values())
    edges=set()
    for consumer,test in tests.items():
        # Explicit Test references and producer/consumer coupling through a
        # Variable's collection. Coupling is not an execution-order assertion.
        refs={n['test'] for n in walk(test) if isinstance(n.get('test'),str)}
        for producer in refs & tests.keys():edges.add((producer,consumer,'explicit_test'))
        var_refs={n['variable'] for n in walk(test) if isinstance(n.get('variable'),str)}
        pending=list(var_refs);seen=set();acquisitions=set()
        while pending:
            name=pending.pop()
            if name in seen or name not in variables:continue
            seen.add(name);v=variables[name];acquisitions.update(objects(v))
            pending += [n['variable'] for n in walk(v) if isinstance(n.get('variable'),str)]
        for producer,other in tests.items():
            if producer!=consumer and acquisitions & set(objects(other)):
                edges.add((producer,consumer,'variable_collection_coupling'))
    b=sum(len(BOOLEANS & n.keys()) for n in walk(a.get('evaluate',{})))
    d=bool_depth(a.get('evaluate',{}));l=chain(executable)
    parts={'tests':len(tests),'boolean_nodes':b,'boolean_depth_excess':max(0,d-1),
           'variables_weighted':2*len(variables),'functions':functions,'chain_depth_excess':max(0,l-1),
           'sets_weighted':2*sets,'filters_weighted':2*filters,'cross_test_coupling_weighted':2*len(edges),
           'repeated_collections':repeated,'distinct_semantic_operations':len(operations)}
    return {'score':sum(parts.values()),'parts':parts,'boolean_depth':d,'variable_function_chain_depth':l,
        'set_count':sets,'filter_count':filters,'cross_test_edges':[list(e) for e in sorted(edges)],
        'collection_references':len(collections),'unique_collections':len(counts),'semantic_operations':sorted(operations)}

def inputs(archive,source):
    archive=Path(archive);source=Path(source)
    if sha256(archive.read_bytes()).hexdigest()!=ARCHIVE_SHA:raise ValueError('library SHA mismatch')
    if sha256(source.read_bytes()).hexdigest()!=SOURCE_SHA:raise ValueError('original ZIP SHA mismatch')
    with zipfile.ZipFile(source) as z:
        member,=[n for n in z.namelist() if n.endswith('.xml')];root=ET.fromstring(z.read(member))
    components={e.get('id'):e[0] for e in root if e.tag.endswith('}component')}
    nodes={cid:{n.get('id'):n for n in e.iter() if n.get('id')} for cid,e in components.items()}
    rules={n.get('id'):n for n in root.iter() if n.tag.endswith('}Rule')}
    with zipfile.ZipFile(archive) as z:
        rec=PREFIX+'records/streams/'+KEY
        ledger=json.loads(z.read(rec+'.json'));trace=json.loads(z.read(rec+'.source-trace.json'))
        assessments={n:z.read(n) for n in z.namelist() if n.startswith(PREFIX+'content/assessments/local/'+KEY+'/') and n.endswith('.yaml')}
    return assessments,ledger,trace,rules,nodes

def inventory(archive,source):
    assessments,ledger,trace,rules,nodes=inputs(archive,source)
    bindings={r['assessment']:r for r in trace['rules']};rows=[]
    original_rows={r['source_rule']:r for r in ledger['original_ledger']['rules']}
    for path,raw in sorted(assessments.items()):
        a=yaml.safe_load(raw)['assessment']
        if a['mode']!='automated':continue
        binding=bindings[a['id']];rule=rules[binding['source_rule']]
        if digest(xml_identity(rule))!=binding['source_rule_sha256']:raise ValueError('original Rule mismatch')
        for ident,record in binding['dependencies'].items():
            if digest(xml_identity(nodes[binding['component']][ident]))!=record['sha256']:raise ValueError('OVAL closure mismatch')
        rows.append({'id':a['id'],'title':a['assessment_title'],'path':path,'yaml_sha256':sha256(raw).hexdigest(),
            'retained_historical_evidence':{k:original_rows[binding['source_rule']][k] for k in
                ('proof_level','conversion_status','independent_source_proof','compile_status','program_sha256','scanner_evaluated')},
            'source_rule':binding['source_rule'],'source_rule_sha256':binding['source_rule_sha256'],
            'source_component':binding['component'],'source_definition':binding['definition'],
            'source_dependencies':binding['dependencies'],'source_platforms':binding['source_platforms'],
            'capabilities':sorted({t['capability'] for t in a['tests'].values()}),**metrics(a)})
    scores=sorted(r['score'] for r in rows)
    cutoff=sorted(scores,reverse=True)[math.ceil(.2*len(scores))-1]
    for r in rows:
        r['initial_score_at_least6']=r['score']>=6
        r['complex']=r['score']>=cutoff
        r['triage']='REVIEW' if r['complex'] else 'KEEP_NATIVE_BELOW_REFINED_THRESHOLD'
    return {'format':'rhel9-readonly-complexity/1','metric_version':1,
        'pins':{'library_archive_sha256':ARCHIVE_SHA,'source_zip_sha256':SOURCE_SHA,
                'evidence_commit':'7dc17f0982cdb5b17281f8f8e4373dbd87f86f58','native_export_engine':'03ddc6beda8dcda5ff57439b0c3d7a2d12763d1b',
                'canonical_inspected':'7354a24cdbfe18321153ccaef5d772801a10cd71','tools_base':'c5f5b215000a1f9149ed56541320da5d7918c94a'},
        'qualification':'Latest published pinned65 library is historical grammar, not current-amended0.4 or scanner proof. No conversion/regeneration.',
        'scope':{'original_rules':len(rules),'automated_analyzed':len(rows),'not_converted':len(rules)-len(rows),
                 'manual_only_rules_excluded':sum(not any(c['system']=='http://oval.mitre.org/XMLSchema/oval-definitions-5' for c in r['checks']) for r in original_rows.values()),
                 'native_manual_assessments_excluded':len(assessments)-len(rows)},
        'distribution':dict(sorted(Counter(scores).items())),'initial_threshold6_count':sum(s>=6 for s in scores),
        'refined_top20_cutoff_inclusive':cutoff,'complex_count':sum(r['complex'] for r in rows),'rows':rows}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',required=True);p.add_argument('--source',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    result=inventory(a.archive,a.source);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows',)}))

if __name__=='__main__':main()
