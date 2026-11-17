#!/usr/bin/env python3
"""Read-only source/schema witness; records unsupported relations without promotion."""
import argparse
import json, hashlib
from pathlib import Path
from scap_ng_tools.converter.direct04 import load_runtime, load_pinned_snapshot
from scap_ng_tools.converter.native041_function_lowering import lower_assessment_inplace
from scap_ng_tools.converter._v04_semantic.validation import document_errors

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-root',type=Path,required=True)
parser.add_argument('--schema-root',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
if args.output.exists(): parser.error('output exists; no overwrite permitted')
archive='U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip'
source_sha='76cf6a14fefd077136d9a23a6ba4a30c82a0b254adc8cf2abd88592dc30776a8'
paths=sorted(args.source_root.rglob(archive))
assert paths, 'source archive missing'
candidates=[p for p in paths if hashlib.sha256(p.read_bytes()).hexdigest()==source_sha]
assert candidates, 'source ZIP checksum drift'
source_file=candidates[0]
rules=[
  'xccdf_mil.disa.stig_rule_SV-224867r958388_rule',
  'xccdf_mil.disa.stig_rule_SV-224868r958388_rule',
  'xccdf_mil.disa.stig_rule_SV-224869r982201_rule',
  'xccdf_mil.disa.stig_rule_SV-224870r982200_rule',
  'xccdf_mil.disa.stig_rule_SV-224871r982188_rule',
]
engine=load_runtime()
from v04_direct_scap_source import SourceModel
model=SourceModel(source_file,source_sha,inventory_broken_references=True)
model.native_recovery=True
model.native_specification_version='0.4.1'
snapshot=load_pinned_snapshot(args.schema_root)
mappings=snapshot.supported_mappings(engine.CAPABILITIES)
def relation_sites(node,path=()):
    if isinstance(node,dict):
        if 'relation' in node:
            yield {'path':'/'.join(map(str,path)), 'relation':node['relation'],
                   'siblings':sorted(node), 'parent_excerpt':repr(node)[:750]}
        for k,v in node.items(): yield from relation_sites(v,path+(k,))
    elif isinstance(node,list):
        for k,v in enumerate(node):yield from relation_sites(v,path+(k,))
rows=[]
for ident in rules:
    try:
        docs,binding=engine.convert_rule(model,ident,mappings,
                                         human_compact=True,native_recovery=True)
        witnesses=[]
        for filename,doc in docs.items():
            kind,=doc
            if kind=='assessment':
                lower_assessment_inplace(doc)
            sites=list(relation_sites(doc))
            errs=[{'message':e.message,'path':list(map(str,e.path))}
                  for e in document_errors(snapshot,kind,doc)]
            witnesses.append({'file':filename,'kind':kind,'relations':sites,
                              'schema_errors':errs[:12]})
        rows.append({'source_rule':ident,'witnesses':witnesses})
    except ValueError as exc:
        rows.append({'source_rule':ident,'conversion_error':str(exc)})
out={'format':'issue59-relation-source-witnesses/1','source_zip':archive,
     'source_zip_sha256':source_sha,'schema_sha256':snapshot.manifest()['aggregate_sha256'],
     'source_rules':rows,'scanner_equivalence':False,
     'diagnostic_complete':len(rows)==5,
     'schema_valid':all('conversion_error' not in r and all(not w['schema_errors'] for w in r.get('witnesses',[])) for r in rows)}
args.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
for row in rows:
    print(row['source_rule'])
    for w in row.get('witnesses',[]):
        for site in w['relations']:print('RELATION SITE:',site)
        for err in w['schema_errors'][:3]:print('SCHEMA ERROR:',err)
    if 'conversion_error' in row: print('SOURCE CONVERSION ERROR:',row['conversion_error'])
assert len(rows)==5
