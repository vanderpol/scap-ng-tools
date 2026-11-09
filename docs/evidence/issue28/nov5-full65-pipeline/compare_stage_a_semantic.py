import hashlib,json
from pathlib import Path
A=Path('/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/automated-subset-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105')
B=Path('/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/automated-subset-repeat-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105')
def canon(raw, rel):
 if rel=='coverage.json':
  x=json.loads(raw)
  for r in x.get('rules',[]):
   for k in ('blockers','omissions','needed_constructs','needed_capabilities','needed_source_families'):
    if isinstance(r.get(k),list): r[k]=sorted(r[k],key=lambda v:json.dumps(v,sort_keys=True))
   if isinstance(r.get('blockers'),list) and r['blockers']:
    r['primary_blocker']=r['blockers'][0]
  return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
 return raw
rows=[]; all_equal=True
for x in sorted(p for p in A.iterdir() if p.is_dir()):
 y=B/x.name; ha={};hb={}
 paths={p.relative_to(x).as_posix() for p in x.rglob('*') if p.is_file()} | {p.relative_to(y).as_posix() for p in y.rglob('*') if p.is_file()}
 for rel in paths:
  pa,pb=x/rel,y/rel
  if pa.exists():ha[rel]=hashlib.sha256(canon(pa.read_bytes(),rel)).hexdigest()
  if pb.exists():hb[rel]=hashlib.sha256(canon(pb.read_bytes(),rel)).hexdigest()
 diffs=sorted(set(ha)^set(hb)|{k for k in set(ha)&set(hb) if ha[k]!=hb[k]}); eq=not diffs; all_equal &= eq
 rows.append({'stream':x.name,'equal':eq,'file_count':len(ha),'differences':diffs[:20]})
print('canonical_equal',all_equal,'streams',len(rows),'files',sum(x['file_count'] for x in rows));print([r for r in rows if not r['equal']])
Path('/tmp/scap-ng-issue27-20261105/stage-a-canonical-reproducibility.json').write_text(json.dumps({'canonical_equal':all_equal,'streams':rows},indent=2)+'\n')
