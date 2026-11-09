from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib, json, os, subprocess, time
from pathlib import Path

work=Path('/tmp/scap-ng-issue27-20261105')
root=Path('/home/u1239716047117002/Documents/scap-ng-vscode')
tools=Path('/tmp/scap-ng-issue26-20261105/tools')
schema=Path('/tmp/scap-ng-issue26-20261105/schema')
python=Path('/tmp/scap-ng-issue26-20261105/venv/bin/python')
source_root=work/'sources'
out=root/'.external/full65-current/automated-subset-repeat-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105'
logs=work/'stage-a-logs'; logs.mkdir(parents=True,exist_ok=True)
out.parent.mkdir(parents=True,exist_ok=True)
if out.exists() and any(out.iterdir()):
    raise SystemExit(f'output root is non-empty: {out}')
manifest=json.loads((work/'source-pins.json').read_text())

def run(s):
    name=s['file']; src=source_root/name; target=out/Path(name).stem
    sha=s['sha256']
    command=[str(python),'-m','scap_ng_tools.converter.direct04','--schema-root',str(schema),str(src),'--sha256',sha,'--all-rules','--output',str(target)]
    t0=time.monotonic(); start=datetime.now(timezone.utc).isoformat()
    p=subprocess.run(command,cwd=tools,env={**os.environ,'PYTHONPATH':str(tools/'src')},capture_output=True,text=True)
    elapsed=time.monotonic()-t0
    (logs/(Path(name).stem+'.stdout')).write_text(p.stdout)
    (logs/(Path(name).stem+'.stderr')).write_text(p.stderr)
    return {'file':name,'source_sha256':sha,'output':str(target),'returncode':p.returncode,'elapsed_seconds':round(elapsed,3),'started_utc':start,'stdout':p.stdout.strip(),'stderr':p.stderr.strip(),'command':command}

results=[]
with ThreadPoolExecutor(max_workers=4) as pool:
    futures={pool.submit(run,s):s for s in manifest['sources']}
    for i,f in enumerate(as_completed(futures),1):
      result=f.result(); results.append(result); print(f"[{i}/65] rc={result['returncode']} {result['file']} {result['elapsed_seconds']}s {result['stdout']}",flush=True)
results.sort(key=lambda x: next(i for i,s in enumerate(manifest['sources']) if s['file']==x['file']))
report={'stage':'A','started_utc':min(r['started_utc'] for r in results),'finished_utc':datetime.now(timezone.utc).isoformat(),'output_root':str(out),'tools_commit':subprocess.check_output(['git','-C',str(tools),'rev-parse','HEAD'],text=True).strip(),'schema_commit':subprocess.check_output(['git','-C',str(schema),'rev-parse','HEAD'],text=True).strip(),'results':results}
(work/'stage-a-repeat-run.json').write_text(json.dumps(report,indent=2)+'\n')
print('successes',sum(r['returncode']==0 for r in results),'failures',sum(r['returncode']!=0 for r in results),'report',work/'stage-a-repeat-run.json')
