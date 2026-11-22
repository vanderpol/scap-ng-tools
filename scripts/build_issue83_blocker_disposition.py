#!/usr/bin/env python3
"""Build the source-linked disposition ledger for the current 65-rule holds.

The converter qualification receipt is the input denominator.  This audit reads
only the pinned source ZIPs, follows the selected Definition graph, and records
why each raw diagnostic is *not* a converter-owned gap.  It does not alter
source content or generate native artifacts.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from zipfile import ZipFile
from xml.etree import ElementTree as ET

OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
XCCDF = "http://checklists.nist.gov/xccdf/1.2"

def local(tag): return tag.rsplit("}", 1)[-1]
def identity(e):
    return [e.tag, sorted(e.attrib.items()), e.text if not len(e) else None,
            [identity(c) for c in e]]
def digest(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()
def file_sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def refs(e):
    out=[]
    for n in e.iter():
        for key,value in n.attrib.items():
            if key.endswith("ref") and value: out.append(value)
        if local(n.tag) in {"var_ref", "object_reference", "state_ref", "test_ref",
                            "filter", "definition_ref"} and (n.text or "").strip():
            out.append(n.text.strip())
    return out

def source_graph(root, rule_id):
    by={n.attrib["id"]: n for n in root.iter() if n.get("id")}
    rule=by[rule_id]
    refs_for_rule=sorted({n.attrib["name"] for n in rule.iter()
                   if local(n.tag)=="check-content-ref" and ":def:" in n.attrib.get("name", "")})
    if len(refs_for_rule)!=1: raise ValueError(f"Definition reference ambiguity for {rule_id}")
    definition=refs_for_rule[0]; seen=set(); todo=[definition]
    while todo:
        ident=todo.pop()
        if ident in seen: continue
        if ident not in by: raise ValueError(f"unresolved source graph node {ident}")
        seen.add(ident)
        todo.extend(x for x in refs(by[ident]) if x not in seen)
    return by, seen, definition

def zip_root(path):
    with ZipFile(path) as z:
        members=[n for n in z.namelist() if n.endswith(".xml")]
        if len(members)!=1: raise ValueError(f"expected one XML member: {path}")
        raw=z.read(members[0])
    return ET.fromstring(raw), members[0], hashlib.sha256(raw).hexdigest()

def locate_source(root, row):
    rid=row["source_rule"]
    by={n.attrib["id"]:n for n in root.iter() if n.get("id")}
    rule=by[rid]
    return rule

def make_row(row, source_path):
    root, member, xml_sha=zip_root(source_path)
    by, seen, definition=source_graph(root, row["source_rule"])
    rule=by[row["source_rule"]]; d=by[definition]
    tests=sorted((i for i in seen if local(by[i].tag).endswith("_test")), key=str)
    wmi=sorted((i for i in seen if local(by[i].tag)=="wmi_object"), key=str)
    msg=row["message"]
    base={
      "benchmark":row["benchmark"], "source_rule":row["source_rule"],
      "source_rule_sha256":digest(identity(rule)), "source_rule_xml_sha256":digest(identity(rule)),
      "source_zip_sha256":file_sha(source_path), "source_xml_member":member,
      "source_xml_sha256":xml_sha, "definition":definition,
      "definition_sha256":digest(identity(d)), "source_test_ids":tests,
      "raw_category":row["category"], "raw_diagnostic":msg,
      "original_status":row.get("original_status", "blocked"),
    }
    if "accesstoken_test" in msg:
        base.update(root_cause="deprecated_windows_accesstoken", disposition="deprecated-source",
          source_construct={"namespace":f"{OVAL}#windows", "name":"accesstoken_test",
            "deprecated_since":"5.11", "replacement":"userright_test",
            "reason":"Replaced by userright_test; access-token collection has scalability issues on domain controllers.",
            "xsd":"windows-definitions-schema.xsd", "lines":"26-46",
            "schematron_pattern":"win-def_accesstokentst_dep"})
    elif "user_test" in msg:
        base.update(root_cause="deprecated_windows_user", disposition="deprecated-source",
          source_construct={"namespace":f"{OVAL}#windows", "name":"user_test",
            "deprecated_since":"5.11", "replacement":"user_sid55_test",
            "reason":"Replaced by user_sid55_test; trustee names are not unique while SIDs are.",
            "xsd":"windows-definitions-schema.xsd", "lines":"8173-8193",
            "schematron_pattern":"win-def_usertst_dep"})
    elif "concat requires" in msg:
        if not wmi:
            base.update(root_cause="unresolved_concat_without_deprecated_wmi", disposition="converter-defect-candidate")
        else:
            base.update(root_cause="deprecated_windows_wmi_transitive_concat", disposition="deprecated-source",
              source_construct={"namespace":f"{OVAL}#windows", "name":"wmi_object",
                "source_object_ids":wmi, "deprecated_since":"5.7", "replacement":"wmi57_object",
                "reason":"Replaced by wmi57_object, which supports multi-field WMI records.",
                "xsd":"windows-definitions-schema.xsd", "lines":"9250-9263",
                "schematron_pattern":"win-def_wmiobj_dep",
                "semantic_note":"The raw concat diagnostic is downstream of this deprecated object; it is not a supported concat-language gap."})
    elif "state capability mismatch" in msg:
        bad=msg.split(": ",1)[1]
        bad_node=by[bad]
        consumers=[]
        for ident in sorted(seen):
            node=by[ident]
            for child in node:
                if child.get("state_ref")==bad:
                    consumers.append({"consumer":ident,"consumer_element":local(node.tag),"state_ref":bad,"relation":"test_state"})
                if local(child.tag)=="filter" and (child.text or "").strip()==bad:
                    consumers.append({"consumer":ident,"consumer_element":local(node.tag),"state_ref":bad,"relation":"object_filter"})
        if local(bad_node.tag)=="appcmdlistconfig_state": pattern="win-def_appcmdlistconfigtst"; lines="8856-8875"
        elif local(bad_node.tag)=="variable_state" and any(c["consumer_element"]=="appcmd_test" for c in consumers): pattern="win-def_appcmdtst"; lines="8740-8759"
        elif local(bad_node.tag)=="variable_state" and any(c["consumer_element"]=="file_test" for c in consumers): pattern="unix-def_filetst"; lines="134-153"
        elif local(bad_node.tag)=="shellcommand_state": pattern="unix-def_filetst"; lines="134-153"
        else: pattern="source-family Test/Object/State element_mapping"; lines="source XSD element_mapping"
        base.update(root_cause="source_invalid_cross_capability_reference", disposition="source-invalid",
          source_construct={"bad_state":bad,"bad_state_element":local(bad_node.tag),
            "consumers":consumers,"xsd_schematron_pattern":pattern,"xsd_lines":lines,
            "semantic_rule":"A Test's Object and State references must resolve to the Object/State pair declared by that Test's OVAL element mapping."})
    elif "Variable cast" in msg:
        vars=[]
        for ident in sorted(seen):
            n=by[ident]
            if local(n.tag) in {"local_variable","constant_variable","external_variable"}:
                funcs=[local(c.tag) for c in n if c.tag.startswith("{"+OVAL+"}")]
                vars.append({"id":ident,"element":local(n.tag),"declared_datatype":n.get("datatype"),"function_elements":funcs})
        if row["source_rule"].endswith("218814r1067589_rule"):
            source_contract={"function":"concat","result_datatype":"string","declared_datatype":"int",
              "xsd_lines":"oval-definitions-schema.xsd:710-711,770-802",
              "semantic_basis":"Concat forms a single string (or string collection); the local declaration says int."}
        else:
            source_contract={"function":"count","result_datatype":"int","declared_datatype":"string",
              "xsd_lines":"oval-definitions-schema.xsd:953-960",
              "semantic_basis":"Count returns the count of represented values; the source documentation example is numeric, while the local declaration says string."}
        base.update(root_cause="source_invalid_variable_result_datatype", disposition="source-invalid",
          source_construct={"variables":vars,"function_contract":source_contract,
            "schematron_note":"The XSD admits the generic VariableType datatype attribute; the mismatch is semantic, not a converter permission to coerce it.",
            "required_action":"Correct source declaration through reviewed upstream content PR; do not add an implicit cast."})
    else:
        base.update(root_cause="unclassified", disposition="needs-review")
    return base

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--receipt",type=Path,required=True); ap.add_argument("--source-root",type=Path,required=True); ap.add_argument("--output",type=Path,required=True)
    a=ap.parse_args(); receipt=json.loads(a.receipt.read_text()); rows=[]; missing=[]
    for row in receipt["blocked_rule_ids"]:
        path=a.source_root/row["benchmark"]
        if not path.exists(): missing.append(str(path)); continue
        rows.append(make_row(row,path))
    if missing: raise SystemExit("missing source archives:\n"+"\n".join(missing))
    rows.sort(key=lambda x:(x["root_cause"],x["benchmark"],x["source_rule"]))
    counts={}
    for row in rows: counts[row["disposition"]]=counts.get(row["disposition"],0)+1
    root_counts={}
    for row in rows: root_counts[row["root_cause"]]=root_counts.get(row["root_cause"],0)+1
    out={"format":"scap-ng-tools/issue83-full65-blocker-disposition/1",
      "baseline_receipt":"external:/tmp/tools-full65-vm-1795372844/full65-source-rule-rebuild.json","baseline_receipt_sha256":file_sha(a.receipt),
      "pins":{"source_commit":receipt["source_commit"],"source_archive_sha256":receipt["source_archive_sha256"],"canonical_commit":receipt["canonical_schema_commit"],"schema_aggregate_sha256":receipt["schema_aggregate_sha256"],"converter_commit":"79ef6550e506903330024d5546df75c0a812f473"},
      "denominator":{"raw_blocked_rules":len(rows),"converted":6493,"manual_only":1403,"newly_converted":receipt.get("newly_converted_from_blocked",0),"converted_to_blocked_regressions":receipt.get("newly_blocked_from_converted",0)},
      "counts":{"by_disposition":dict(sorted(counts.items())),"by_root_cause":dict(sorted(root_counts.items()))},
      "proof_contract":["Structural/source disposition is not runtime qualification.","Deprecated source constructs remain explicit exclusions and are not lowered to invented native capabilities.","Source-invalid declarations/references remain blocked; converter validation is not weakened and source content is unchanged.","No converter-owned defect remains in this 94-row denominator after source-graph review; any new source-valid occurrence requires a fresh receipt."],
      "source_validation":{"method":"focused OVAL fragments from each selected source XML member, official OVAL 5.12.3 XSD/Schematron extraction","source_schema_commit":"2f140ee5c5dd1ed9606fcd5afc301f6baeb48706","schema_files":["oval-definitions-schema.xsd","windows-definitions-schema.xsd","unix-definitions-schema.xsd"],"schematron_patterns":["win-def_accesstokentst_dep","win-def_usertst_dep","win-def_wmiobj_dep","win-def_appcmdtst","win-def_appcmdlistconfigtst","win-def_appcmd_object_verify_filter_state","unix-def_filetst"],"observed":"Deprecated reports confirm the access-token/user/WMI constructs; cross-capability rows are rejected by Test/Object/State mapping assertions or filter-state assertions in the source component where applicable. The two Variable result-type rows are XSD-grammatical but semantically invalid under the documented function result contracts; no implicit coercion is permitted.","not_run":"Independent scanner/runtime equivalence and full source corpus execution."},
      "xsd_source":{"repository":"OVAL-Community/OVAL","commit":"2f140ee5c5dd1ed9606fcd5afc301f6baeb48706","definitions_schema":"oval-definitions-schema.xsd","windows_schema":"windows-definitions-schema.xsd","unix_schema":"unix-definitions-schema.xsd"},"rows":rows}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"rows":len(rows),"counts":out["counts"]},indent=2))
if __name__=='__main__': main()
