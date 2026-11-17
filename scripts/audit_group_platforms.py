#!/usr/bin/env python3
"""Audit Group-local XCCDF platform declarations in a pinned source corpus."""
from __future__ import annotations
import argparse, hashlib, json, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET
X = "{http://checklists.nist.gov/xccdf/1.2}"
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
def audit(root: Path, revision: str):
    streams=0; declarations=[]; nested=0; files=[]
    for path in sorted(root.glob('*.zip')):
        with zipfile.ZipFile(path) as archive:
            for member in sorted(n for n in archive.namelist() if n.lower().endswith('.xml')):
                try: parsed=ET.fromstring(archive.read(member))
                except ET.ParseError: continue
                benchmarks=[parsed] if parsed.tag == f'{X}Benchmark' else parsed.findall(f'.//{X}Benchmark')
                for benchmark in benchmarks:
                    streams += 1
                    groups=benchmark.findall(f'.//{X}Group')
                    nested += sum(bool(group.findall(f'{X}Group')) for group in groups)
                    for group in groups:
                        platforms=group.findall(f'{X}platform')
                        if platforms:
                            declarations.append({'source_file': path.name, 'member': member,
                                'benchmark_id': benchmark.get('id'), 'group_id': group.get('id'),
                                'platform_idrefs': [p.get('idref') for p in platforms]})
                    files.append({'source_file': path.name, 'sha256': sha(path)})
    return {'format':'scap-ng/pinned-corpus-group-platform-audit/1', 'corpus_revision':revision,
            'source_zip_count':len(files), 'benchmark_stream_count':streams,
            'nested_group_count':nested, 'group_platform_declaration_count':len(declarations),
            'declarations':declarations, 'source_files':files,
            'qualification': 'NO_GROUP_LOCAL_PLATFORM_DECLARATIONS_FOUND' if not declarations else 'FOUND_GROUP_LOCAL_PLATFORM_DECLARATIONS'}
def main():
    p=argparse.ArgumentParser(); p.add_argument('--corpus-root',type=Path,required=True); p.add_argument('--corpus-revision',required=True); p.add_argument('--output',type=Path,required=True); a=p.parse_args(); r=a.output; r.parent.mkdir(parents=True,exist_ok=True); r.write_text(json.dumps(audit(a.corpus_root,a.corpus_revision),sort_keys=True,indent=2)+'\n'); print(r)
if __name__=='__main__': main()
