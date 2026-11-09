import hashlib,json
from pathlib import Path
w=Path('/tmp/scap-ng-issue27-20261105'); a=Path('/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/automated-subset-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105'); b=Path('/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/automated-subset-repeat-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105')
def hashes(base):
 d={}
 for p in sorted(base.rglob('*')):
  if p.is_file(): d[p.relative_to(base).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
 return d
rows=[]; all_equal=True
for x in sorted(p for p in a.iterdir() if p.is_dir()):
 y=b/x.name; ha,hb=hashes(x),hashes(y); diffs=sorted(set(ha)^set(hb) | {k for k in set(ha)&set(hb) if ha[k]!=hb[k]}); eq=not diffs; all_equal &= eq
 rows.append({'stream':x.name,'equal':eq,'file_count':len(ha),'diff_count':len(diffs),'differences':diffs[:20]})
print('all_equal',all_equal,'streams',len(rows),'files',sum(x['file_count'] for x in rows));
for r in rows:
 if not r['equal']: print(r)
(w/'stage-a-reproducibility.json').write_text(json.dumps({'first':str(a),'repeat':str(b),'all_equal':all_equal,'streams':rows},indent=2)+'\n')
if not all_equal: raise SystemExit(1)
