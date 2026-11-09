from __future__ import annotations
import argparse, hashlib, json, shutil, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

XCCDF='http://checklists.nist.gov/xccdf/1.2'; OCIL='http://scap.nist.gov/schema/ocil/2'

def sha256(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def safe_id(i): return ''.join(c if c.isalnum() or c in '-_.' else '_' for c in i)[:140]
def write_json(p,v): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n')
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--pins',type=Path,required=True);ap.add_argument('--sources',type=Path,required=True);ap.add_argument('--automated-root',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--select',action='append');args=ap.parse_args()
 pins=json.loads(args.pins.read_text()); selected=set(args.select or [s['file'] for s in pins['sources']]); args.output.mkdir(parents=True,exist_ok=False)
 rows=[]; total={'source_rules':0,'converted_rules':0,'blocked_rules':0,'manual_ocil_rules':0,'source_rule_xml_count':0,'native_json_documents':0,'native_yaml_documents':0}
 for pin in pins['sources']:
  if pin['file'] not in selected: continue
  stem=Path(pin['file']).stem; src=args.sources/pin['file']; native=args.automated_root/stem; target=args.output/stem
  if not native.is_dir(): raise SystemExit(f'missing Stage A output {native}')
  target.mkdir(); shutil.copytree(native,target/'native-automated-subset')
  preservation=target/'source-preservation'; preservation.mkdir()
  shutil.copy2(src,preservation/pin['file'])
  with zipfile.ZipFile(src) as z:
   members=z.namelist(); xml_members=[n for n in members if n.lower().endswith('.xml')]
   if not xml_members: raise SystemExit(f'{pin["file"]}: no XML datastream')
   for m in xml_members: (preservation/'datastreams'/m).parent.mkdir(parents=True,exist_ok=True); (preservation/'datastreams'/m).write_bytes(z.read(m))
   xml_name=xml_members[0]; xml_raw=z.read(xml_name)
  root=ET.fromstring(xml_raw); rules=root.findall('.//{%s}Rule'%XCCDF)
  rule_map={r.get('id'):r for r in rules if r.get('id')}
  cov=json.loads((native/'coverage.json').read_text()); coverage_rows=cov['rules']; covered={r['source_rule'] for r in coverage_rows}
  source_rule_index={}; missing=[]
  for n,r in enumerate(rules,1):
   rid=r.get('id'); rel=f'rules/{n:04d}-{hashlib.sha1(rid.encode()).hexdigest()[:12]}-{safe_id(rid)}.xml'; (preservation/rel).parent.mkdir(parents=True,exist_ok=True); (preservation/rel).write_bytes(ET.tostring(r,encoding='utf-8',xml_declaration=True)); source_rule_index[rid]={'id':rid,'title':r.findtext('{%s}title'%XCCDF,''),'path':'source-preservation/'+rel}
  for rid in sorted(covered-set(rule_map)): missing.append(rid)
  manual=[]
  for row in coverage_rows:
   if any(c.get('system')==OCIL for c in row.get('checks',[])): manual.append(row['source_rule'])
  statuses=cov['summary']['statuses']; native_json=sum(1 for p in (target/'native-automated-subset').rglob('*.json') if p.name not in {'coverage.json','source-trace.json','conversion-scope.json'}); native_yaml=sum(1 for p in (target/'native-automated-subset').rglob('*.yaml'))
  preservation_index={'format':'scap-ng-current-draft-source-preservation/1','source':pin,'xml_members':xml_members,'xccdf_rule_count':len(rules),'rules':source_rule_index,'coverage_rule_count':len(coverage_rows),'coverage_rules_missing_xml':missing,'manual_ocil_rule_ids':manual,'complete_source_metadata':'preserved inside original datastream XML; no policy/CPE/profile/remediation fields were synthesized'}
  write_json(preservation/'index.json',preservation_index)
  manifest={'format':'scap-ng-current-draft/1','draft_status':'SOURCE_PRESERVING_AUTOMATED_SUBSET','source':pin,'tools_commit':'c5f5b215000a1f9149ed56541320da5d7918c94a','schema_commit':'7354a24cdbfe18321153ccaef5d772801a10cd71','schema_validation':'native automated JSON/YAML validated against current flat 0.4 schema','native_scope':'automated subset only; no fabricated manual Assessment','statuses':statuses,'source_rules':len(coverage_rows),'converted_automated_rules':statuses.get('converted',0),'blocked_automated_rules':statuses.get('blocked',0),'manual_ocil_rules':len(manual),'source_rule_xml_count':len(rules),'source_rule_xml_preservation':'PASS' if not missing and len(rules)==len(coverage_rows) else 'CHECK','coverage_rules_missing_xml':missing,'native_json_documents':native_json,'native_yaml_documents':native_yaml,'applicability_status':'SOURCE_PRESERVED_NATIVE_NOT_QUALIFIED','compile_status':'NOT_RUN_PUBLIC_PORT_NOT_MIGRATED','independent_source_proof':False,'scanner_runtime':False,'preservation_index':'source-preservation/index.json'}
  write_json(target/'draft-manifest.json',manifest)
  (target/'README.md').write_text('# Current 0.4 source-preserving DRAFT\n\nThis local DRAFT was generated from the pinned original datastream. Native files under `native-automated-subset/` are the current-schema automated subset. All original Rule XML, manual/OCIL checks, Profiles, CPE/applicability, fix/remediation and publisher metadata remain under `source-preservation/`; no manual Assessment or applicability claim was fabricated.\n\nStatus: SOURCE_PRESERVING_AUTOMATED_SUBSET; not scanner/proof qualified.\n')
  item={'file':pin['file'],'source_rules':len(coverage_rows),'converted_rules':statuses.get('converted',0),'blocked_rules':statuses.get('blocked',0),'manual_ocil_rules':len(manual),'native_json_documents':native_json,'native_yaml_documents':native_yaml,'source_rule_xml_count':len(rules),'coverage_rules_missing_xml':missing,'validation':'PASS' if not missing and len(rules)==len(coverage_rows) else 'FAIL'}; rows.append(item)
  for k in total: total[k]+=item.get(k,0)
 write_json(args.output/'stage-b-manifest.json',{'format':'scap-ng-current-draft-library/1','status':'SOURCE_PRESERVING_AUTOMATED_SUBSET','tools_commit':'c5f5b215000a1f9149ed56541320da5d7918c94a','schema_commit':'7354a24cdbfe18321153ccaef5d772801a10cd71','streams':rows,'totals':total,'limitations':['Manual/OCIL and complete policy are preserved as original source records, not translated to native manual Assessments.','Native applicability remains unqualified fixture/direct-slice output.','Public compile/proof/scanner modes are not migrated.']})
 print(json.dumps({'streams':len(rows),'totals':total},indent=2))
if __name__=='__main__': main()
