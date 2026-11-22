#!/usr/bin/env python3
"""Optional offline structural check of audit sketches; no equivalence claim."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry,Resource

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--schema-root',type=Path,required=True)
    p.add_argument('--review',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    root=a.schema_root/'schema';paths=sorted(root.glob('*.json'))
    schemas=[json.loads(path.read_text()) for path in paths]
    registry=Registry().with_resources((s['$id'],Resource.from_contents(s)) for s in schemas if '$id' in s)
    schema=json.loads((root/'assessment.schema.json').read_text());validator=Draft202012Validator(schema,registry=registry)
    rows=[]
    for path in sorted(a.review.glob('case-*/proposed-UNAPPROVED.yaml')):
        errors=[{'path':list(e.absolute_path),'message':e.message} for e in validator.iter_errors(yaml.safe_load(path.read_text()))]
        rows.append({'case':path.parent.name,'errors':errors})
    result={'qualification':'JSON Schema structure only; no semantic, compiler or scanner-equivalence claim',
        'schema_sha256':{p.name:sha256(p.read_bytes()).hexdigest() for p in paths},'results':rows}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'sketches':len(rows),'errors':sum(len(r['errors']) for r in rows)}))
    if any(row['errors'] for row in rows):raise SystemExit(1)

if __name__=='__main__':main()
