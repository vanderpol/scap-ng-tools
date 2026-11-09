from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import hashlib, json, os, subprocess, sys, zipfile
from pathlib import Path
import yaml

work=Path('/tmp/scap-ng-issue27-20261105'); root=Path('/home/u1239716047117002/Documents/scap-ng-vscode')
tools=Path('/tmp/scap-ng-issue26-20261105/tools'); schema=Path('/tmp/scap-ng-issue26-20261105/schema')
sys.path.insert(0,str(tools/'src'))
from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import validate_native_documents
snapshot=FrozenSchemaSnapshot(schema)
pins=json.loads((work/'source-pins.json').read_text())
verified=json.loads((work/'source-verification.json').read_text())
run=json.loads((work/'stage-a-run.json').read_text())
out=Path(run['output_root'])
meta={s['file']:s for s in pins['sources']}
excluded={'coverage.json','source-trace.json','conversion-scope.json'}

def tree_digest(base):
 h=hashlib.sha256(); rows=[]
 for p in sorted(x for x in base.rglob('*') if x.is_file()):
  rel=p.relative_to(base).as_posix(); raw=p.read_bytes(); d=hashlib.sha256(raw).hexdigest(); rows.append({'path':rel,'bytes':len(raw),'sha256':d}); h.update(rel.encode());h.update(b'\0');h.update(raw);h.update(b'\0')
 return h.hexdigest(),rows

def logical_depth(v, depth=0):
 if isinstance(v,dict):
  d=depth
  for k,x in v.items():
   nd=depth+1 if k in {'and','or','one','xor','not','all','any','exactly_one','operands','conditions','evaluate'} else depth
   d=max(d,logical_depth(x,nd))
  return d
 if isinstance(v,list): return max([logical_depth(x,depth) for x in v] or [depth])
 return depth

def count_key(v,key):
 if isinstance(v,dict): return (1 if key in v else 0)+sum(count_key(x,key) for x in v.values())
 if isinstance(v,list): return sum(count_key(x,key) for x in v)
 return 0

def collect_docs(base, ext):
 result={}
 for p in sorted(base.rglob('*'+ext)):
  if ext=='.json' and p.name in excluded: continue
  v=yaml.safe_load(p.read_text())
  if isinstance(v,dict): result[p.relative_to(base).as_posix()]=v
 return result

streams=[]; root_file_rows=[]; all_ok=True
for s in pins['sources']:
 name=s['file']; target=out/Path(name).stem
 cpath=target/'coverage.json'; spath=target/'source-trace.json'; scopepath=target/'conversion-scope.json'
 ok=True; errors=[]
 if not target.is_dir(): ok=False;errors.append('missing output directory')
 else:
  cov=json.loads(cpath.read_text()); scope=json.loads(scopepath.read_text())
  jdocs=collect_docs(target,'.json'); ydocs=collect_docs(target,'.yaml')
  try: validate_native_documents(snapshot,jdocs)
  except Exception as e: ok=False;errors.append('JSON validation: '+str(e))
  try: validate_native_documents(snapshot,ydocs)
  except Exception as e: ok=False;errors.append('YAML validation: '+str(e))
  summ=cov['summary']; statuses=summ.get('statuses',{})
  if len(cov.get('rules',[])) != summ['source_rules']: ok=False; errors.append('rule ledger count mismatch')
  if statuses.get('converted',0)+statuses.get('blocked',0) != summ['source_rules']: ok=False;errors.append('status accounting mismatch')
  if len(jdocs)!=len(ydocs):ok=False;errors.append('JSON/YAML document count mismatch')
  if not scope.get('independent_semantic_proof') is False: ok=False;errors.append('proof status promoted')
  if scope.get('conversion_status')!='CONVERTED_UNVERIFIED':ok=False;errors.append('unexpected conversion status')
  td,files=tree_digest(target); root_file_rows.extend({'stream':name,**x} for x in files)
  # zip datastream sanity
  with zipfile.ZipFile(work/'sources'/name) as z:
   xml=[n for n in z.namelist() if n.lower().endswith('.xml')]
  if not xml: ok=False;errors.append('no datastream XML member')
  first_block=next((r for r in cov['rules'] if r.get('status')=='blocked'),None)
  assessments=[d for d in jdocs.values() if 'assessment' in d]
  shape={
    'json_documents':len(jdocs),'yaml_documents':len(ydocs),'assessments':len(assessments),
    'tests':sum(len(d.get('assessment',{}).get('tests',{})) for d in assessments),
    'variables':sum(len(d.get('assessment',{}).get('variables',{})) for d in assessments),
    'inputs':sum(len(d.get('assessment',{}).get('inputs',{})) for d in assessments),
    'filters':sum(count_key(d,'filters') for d in assessments), 'sets':sum(count_key(d,'set')+count_key(d,'sets') for d in assessments),
    'max_logical_depth':max([logical_depth(d) for d in assessments] or [0]),
    'max_json_bytes':max([len(json.dumps(d)) for d in jdocs.values()] or [0]),
    'max_yaml_bytes':max([p.stat().st_size for p in target.rglob('*.yaml')] or [0]),
  }
  streams.append({
    'file':name,'source_sha256':s['sha256'],'git_blob_sha':s['git_blob_sha'],'bytes':s['bytes'],'source_member':cov.get('source_member'),'benchmark_component':cov.get('source_benchmark_component'),
    'source_rules':summ['source_rules'],'converted_rules':statuses.get('converted',0),'blocked_rules':statuses.get('blocked',0),'native_json_documents':len(jdocs),'native_yaml_documents':len(ydocs),'schema_validated_json':len(jdocs) if ok else 0,'schema_validated_yaml':len(ydocs) if ok else 0,
    'proof_level_counts':summ.get('proof_levels',{}),'blocker_categories':summ.get('rules_by_blocker_category',{}),'first_blocker':None if not first_block else {'source_rule':first_block.get('source_rule'),'title':first_block.get('title'),'primary_blocker':first_block.get('primary_blocker')},'output_sha256_root':td,'shape':shape,'validation':'PASS' if ok else 'FAIL','errors':errors,
  })
  all_ok &= ok

# stable aggregate root over path and bytes
h=hashlib.sha256()
for x in sorted(root_file_rows,key=lambda x:(x['stream'],x['path'])):
 h.update(x['stream'].encode());h.update(b'\0');h.update(x['path'].encode());h.update(b'\0');h.update(bytes.fromhex(x['sha256']));h.update(b'\0')
aggregate={
 'streams':len(streams),'all_streams_present':len(streams)==65,'all_validation_pass':all_ok,
 'source_rules':sum(x['source_rules'] for x in streams),'converted_rules':sum(x['converted_rules'] for x in streams),'blocked_rules':sum(x['blocked_rules'] for x in streams),
 'native_json_documents':sum(x['native_json_documents'] for x in streams),'native_yaml_documents':sum(x['native_yaml_documents'] for x in streams),'schema_validated_documents':sum(x['schema_validated_json']+x['schema_validated_yaml'] for x in streams),'file_count':len(root_file_rows),'file_checksum_root':h.hexdigest()
}
# worst-case index by shape dimensions
for dim in ['tests','variables','inputs','filters','sets','max_logical_depth','max_json_bytes','max_yaml_bytes']:
 vals=sorted(((x['shape'][dim],x['file']) for x in streams),reverse=True)
 aggregate.setdefault('worst_case_shape',{})[dim]={'value':vals[0][0],'file':vals[0][1]}
report={'stage':'A','status':'PASS' if all_ok else 'PARTIAL','generated_utc':datetime.now(timezone.utc).isoformat(),'pins':{'tools_commit':run['tools_commit'],'schema_commit':run['schema_commit'],'schema_snapshot':snapshot.manifest(),'sources_repository':pins['repository'],'sources_revision':pins['revision']},'output_root':str(out),'aggregate':aggregate,'streams':streams,'source_verification':verified['verification'],'run_results':run['results']}
(work/'stage-a-ledger.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'aggregate':aggregate},indent=2))
for x in streams: print(x['file'],x['source_rules'],x['converted_rules'],x['blocked_rules'],x['native_json_documents'],x['validation'],x['errors'])
if not all_ok: raise SystemExit(1)
