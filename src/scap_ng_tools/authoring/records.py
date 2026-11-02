"""Lazy original Rule record navigation; never synthesize native content."""
import json
from pathlib import Path


def original_records(root, *, scope=None, query='', status=None, limit=100):
    if not 1<=limit<=1000:raise ValueError('record query limit must be 1..1000')
    root=Path(root).resolve();folder=root.parent/'records/streams'
    if scope and (Path(scope).name!=scope or scope in ('.','..') or '\\' in scope):
        raise ValueError('record scope must be one declared navigation namespace')
    files=[folder/(scope+'.json')] if scope else sorted(p for p in folder.glob('*.json') if not p.name.endswith('.source-trace.json'))
    result=[]
    for path in files:
        if not path.is_file():continue
        if path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()):
            raise ValueError('record file escapes provenance area')
        record=json.loads(path.read_text())
        original_zip=record['original_ledger'].get('original_zip',{}).get('file','')
        archive_stream=original_zip.removesuffix('.zip') if original_zip else record['source_stream']
        mappings={m['source_path']:m for m in record.get('native_path_mapping',[]) if m['kind']=='assessment'}
        for n,row in enumerate(record['original_ledger']['rules']):
            label=row.get('title','');ident=row['source_rule'];current=row['conversion_status']
            if status and current!=status:continue
            if query.casefold() not in (ident+' '+label).casefold():continue
            source_assessment=row.get('assessment_path')
            key=(record['source_stream']+'/'+source_assessment.removesuffix('.json')+'.yaml') if source_assessment else None
            target=mappings.get(key)
            result.append({'kind':'original-rule-record','id':ident,'title':label,'scope':path.stem,
                'file_uri':path.as_uri(),'source_field':f'/original_ledger/rules/{n}',
                'editable_native_document':False,'conversion_status':current,
                'proof_status':row.get('independent_source_proof','NOT_RUN'),
                'warnings':row.get('conversion_warnings') or [],
                'original_native_assessment_id':target['id'] if target else None,
                'source_rule_sha256':row.get('source_rule_sha256'),
                'source_artifact':record['source_artifact'],
                'archive_member':'all-65-revised-draft/'+archive_stream+'/'+row.get('preserved_original_rule',''),
                'proof_scope':'original frozen source record; not a proof promotion of current edits'})
            if len(result)>=limit:return result
    return result
