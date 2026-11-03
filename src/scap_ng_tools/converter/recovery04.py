"""Explicit current-0.4 DRAFT recovery, separate from frozen strict admission.

Preserves bounded OCIL choices and source selection/provenance. Compilation and
independent source proof are external qualification; this is not a scanner.
"""
from collections import Counter
from copy import deepcopy
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from .direct04 import load_runtime, validate_native_documents
from ._v04_semantic.validation import document_errors
from .ocil_manual import manual_assessment


def _identifier(source, element, suffix, title=None):
    from v04_direct_scap_source import native_identifier, ensure, local_name
    original = element.get('id')
    ensure(original, 'recovery naming requires original identity')
    # A readable local source discriminator, never a promoted semantic identity.
    tail = original.split(':')[-1].removeprefix('xccdf_mil.disa.stig_value_')
    token = re.sub('[^a-z0-9]+', '-', tail.lower()).strip('-')
    if len(token)>40:
        peers=sorted(n.get('id') for nodes in source.nodes.values() for n in nodes.values()
                     if n.tag==element.tag and n.get('id'))
        token=token[:17].rstrip('-')+'-'+token[-17:].lstrip('-')+'-'+str(peers.index(original)+1)
    base = native_identifier(element, suffix, title).removesuffix('-'+suffix)
    budget = 64-len(suffix)-len(token)-2
    ensure(budget >= 8, 'source discriminator too long for readable native name')
    result = base[:budget].rstrip('-')+'-'+token+'-'+suffix
    names = getattr(source, '_recovery_names', {})
    ensure((suffix,result) not in names or names[suffix,result] == original,
           'ambiguous source-derived native identity: '+result)
    names[suffix,result] = original; source._recovery_names = names
    return result


def _classes(engine, *, binary32_contract=None):
    from v04_direct_scap_source import SourceModel, XCCDF, OVAL, OCIL, ensure, attributes

    class RecoverySource(SourceModel):
        def automated_check(self, rule):
            ensure(not rule.findall('{'+XCCDF+'}complex-check'), 'XCCDF complex-check unsupported')
            targets = []; selectors = set()
            for check in rule.findall('{'+XCCDF+'}check'):
                attributes(check, {'system','selector'})
                selector = check.get('selector',''); system = check.get('system')
                ensure(selector in ('','automated','manual') and selector not in selectors,
                       'unsupported/duplicate source selector')
                selectors.add(selector)
                if system == OCIL:
                    ensure(selector in ('','manual'), 'OCIL automated selector is ambiguous'); continue
                ensure(system == OVAL and selector in ('','automated'), 'unsupported check system/selector')
                refs = check.findall('{'+XCCDF+'}check-content-ref')
                ensure(len(refs)==1 and all(n.tag in {'{'+XCCDF+'}check-export','{'+XCCDF+'}check-content-ref'} for n in check),
                       'OVAL check-import/result binding or complex check unsupported')
                ref=refs[0];attributes(ref,{'href','name'})
                ensure(ref.get('href') in self.catalog,'unresolved checklist catalog href')
                targets.append((self.catalog[ref.get('href')],ref.get('name')))
            ensure('' in selectors and targets and len(set(targets))==1, 'unambiguous source default/OVAL target required')
            return *targets[0], []

    class RecoveryVisitor(engine.AssessmentConverter):
        preserve_value_warnings = True
        preserve_redundant_value_operator = True
        def native_name(self, element, suffix, title=None):
            ident=_identifier(self.source,element,suffix,title)
            self.native_names[suffix,ident]=element.get('id')
            return ident
        def binding_name(self, element, suffix, title=None):
            return _identifier(self.source,element,suffix,title)

        def predicate(self, element, mapping, selector=False, *, record_field=False):
            from v04_direct_scap_source import local_name, digest, xml_identity
            if binary32_contract is not None and element.get('datatype') == 'float':
                from .binary32 import OPERATIONS, finite_literal, lexical_bits
                ensure(not selector and not record_field and not len(element),
                       'binary32 recovery supports scalar State fields only')
                attributes(element, {'datatype', 'operation', 'entity_check', 'check_existence'})
                ensure(element.tag == '{' + mapping['source']['namespace'] + '}' + local_name(element)
                       and local_name(element) in mapping['native']['state_field_map'],
                       'unsupported binary32 State field')
                source_operation = element.get('operation', 'equals')
                ensure(source_operation in {op.replace('_', ' ') for op in OPERATIONS},
                       'unsupported binary32 source comparison')
                operation = source_operation.replace(' ', '_')
                existence = element.get('check_existence', 'at_least_one_exists')
                matching = element.get('entity_check', 'all')
                ensure(existence in engine.FIELD_EXISTENCE and existence != 'none_exist'
                       and matching in engine.MATCHING, 'unsupported binary32 field controls')
                value = finite_literal(element.text)
                result = {'float_' + operation: value,
                          'values_found': engine.FIELD_EXISTENCE[existence],
                          'values_matching': engine.MATCHING[matching]}
                self.conversion_warnings.append({'code': 'native_binary32_comparison_v1',
                    'source_sha256': digest(xml_identity(element)), 'source_lexical': element.text,
                    'source_attributes': dict(element.attrib), 'binary32_bits': f'{lexical_bits(element.text):08x}',
                    'contract': binary32_contract, 'native_predicate_sha256': digest(result),
                    'independent_static_proof': 'UNPROVED', 'scanner_evaluated': False})
                return result
            # OVAL EntityAttributeGroup explicitly defaults operation to equals.
            # This exact empty State form already has an approved absence AST.
            # Keep pattern/values/Variables/extra controls and selectors strict.
            if (not selector and not record_field and not len(element) and not element.text
                    and dict(element.attrib) == {'check_existence': 'none_exist', 'operation': 'equals'}
                    and element.tag == '{' + mapping['source']['namespace'] + '}' + local_name(element)
                    and local_name(element) in mapping['native']['state_field_map']):
                original = element
                element = deepcopy(element)
                del element.attrib['operation']
                result = super().predicate(element, mapping)
                self.conversion_warnings.append({'code': 'explicit_absence_equals_default',
                    'source_sha256': digest(xml_identity(original)),
                    'source_attributes': dict(original.attrib),
                    'native_predicate_sha256': digest(result),
                    'basis': 'OVAL-5.12.3 EntityAttributeGroup operation default equals',
                    'independent_static_proof': 'UNPROVED', 'scanner_evaluated': False})
                return result
            return super().predicate(element, mapping, selector, record_field=record_field)

        def function(self, element):
            from v04_direct_scap_source import local_name, digest, xml_identity
            operation = local_name(element)
            if operation not in ('arithmetic', 'substring', 'split'):
                return super().function(element)
            ensure(element.tag == '{' + OVAL + '}' + operation, 'function namespace mismatch')
            required = ({'arithmetic_operation'} if operation == 'arithmetic' else
                        {'substring_start', 'substring_length'} if operation == 'substring' else {'delimiter'})
            attributes(element, required)
            ensure(set(element.attrib) == required, 'explicit complete function options required')
            ensure(len(element) >= 2 if operation == 'arithmetic' else len(element) == 1,
                   'function arity mismatch')
            options = dict(element.attrib)
            if operation == 'arithmetic':
                ensure(options['arithmetic_operation'] in ('add', 'multiply'), 'unsupported arithmetic operation')
            elif operation == 'substring':
                for key, text in options.items():
                    ensure(re.fullmatch(r'[+-]?[0-9]+', text.strip()) is not None, 'substring option must be xsd:int')
                    number = int(text)
                    ensure(-2147483648 <= number <= 2147483647, 'substring option outside xsd:int')
                    options[key] = number
            expression = {'function': {'name': operation,
                'arguments': [self.function(child) for child in element], 'options': options}}
            self.conversion_warnings.append({'code': 'native_function_contract_v1',
                'source_function': operation, 'source_sha256': digest(xml_identity(element)),
                'source_options': dict(element.attrib), 'native_expression_sha256': digest(expression),
                'independent_static_proof': 'UNPROVED', 'scanner_evaluated': False})
            return expression

        def convert_object(self, element):
            from v04_direct_scap_source import attributes, ensure, digest, xml_identity
            mapping=self.capability(element,'object')
            if mapping['native'].get('test_source',{}).get('kind')!='variable':
                return super().convert_object(element)
            refs=element.findall('{'+mapping['source']['namespace']+'}var_ref')
            ensure(len(element)==len(refs)==1 and not len(refs[0]),
                   'Variable source requires one plain var_ref; Sets/Filters unsupported')
            ref=refs[0];attributes(ref,{'datatype','operation'})
            ensure(ref.get('datatype','string')=='string' and ref.get('operation','equals')=='equals',
                   'nondefault variable reference datatype/comparator requires an adapter')
            result={'capability':mapping['capability'],'variable':self.named_variable((ref.text or '').strip())}
            if ref.attrib:
                self.conversion_warnings.append({'code':'explicit_var_ref_defaults_retained',
                    'source_object':element.get('id'),'source_sha256':digest(xml_identity(element)),
                    'source_reference_attributes':dict(ref.attrib),'independent_static_proof':'UNPROVED'})
            return result

    return RecoverySource, RecoveryVisitor


def recover_benchmark(*, schema_root, source, sha256_pin, organization_parameters=False, rule_ids=None,
                      binary32_comparisons=False, approved_oracle_absence=False, approved_absence_corrections=False):
    """Return native DRAFT documents, complete source trace and per-Rule ledger.

    Original selection/applicability XML remains in provenance. Native platform
    execution and full policy equivalence are explicitly unqualified.
    """
    snapshot=FrozenSchemaSnapshot(schema_root);engine=load_runtime()
    from v04_direct_scap_source import XCCDF, OVAL, OCIL, ensure, digest, xml_identity, native_identifier
    binary32_contract = None
    if binary32_comparisons:
        from .binary32 import require_contract
        binary32_contract = require_contract(snapshot.schema_root)
    RecoverySource,RecoveryVisitor=_classes(engine, binary32_contract=binary32_contract)
    model=RecoverySource(Path(source),sha256_pin,inventory_broken_references=True,draft_compatibility=True)
    mappings=snapshot.supported_mappings(engine.CAPABILITIES)
    selected=list(model.rules) if rule_ids is None else list(rule_ids)
    ensure(selected and len(selected)==len(set(selected)) and set(selected)<=set(model.rules),
           'distinct resolved source Rules required for recovery')
    docs={};bindings=[];rows=[]
    for rid in selected:
        rule=model.rules[rid]
        title=rule.findtext('{'+XCCDF+'}title',''); control=re.search(r'SV-\d+',rid)
        label=(control.group().lower() if control else native_identifier(rule,'rule'))
        row={'source_rule':rid,'source_rule_sha256':digest(xml_identity(rule)),
             'status':'BLOCKED','automated_draft':False,'manual':False,'rule_emitted':False,
             'schema_validated':False,'semantic_validated':False,'compiled':False,
             'independent_source_proof':False,'scanner_execution':False,'blockers':[],
             'source_checks':[xml_identity(c) for c in rule.findall('{'+XCCDF+'}check')]}
        native={};binding={'source_rule':rid,'source_rule_sha256':row['source_rule_sha256'],'native_rule':native_identifier(rule,'rule',title+' '+label),
                          'policy_parameters':{},'dependencies':{},'manual_choices':[]}
        native_rule={'id':binding['native_rule'],'version':rule.findtext('{'+XCCDF+'}version',''),
                     'title':title,'severity':rule.get('severity','unknown'),'role':'full',
                     'weight':float(rule.get('weight','1')),'requires':[],'conflicts':[],
                     'applicability':[],'parameters':{},'organizational_input_requirements':{},
                     'assessment_choices':{},'default_assessment_choice':'manual'}
        checks=rule.findall('{'+XCCDF+'}check');seen=set();default=None
        for check in checks:
            selector=check.get('selector','');system=check.get('system')
            if selector in seen or selector not in ('','automated','manual') or system not in (OVAL,OCIL):
                row['blockers'].append('unsupported/duplicate source selector');continue
            seen.add(selector)
            if not selector:default='manual' if system==OCIL else 'automated'
            if system==OVAL:continue
            try:
                aid=label+'-manual-assessment'
                manual,provenance=manual_assessment(model,check,assessment_id=aid,title=title)
                if 'manual' in native_rule['assessment_choices']:
                    ensure(native['authoring/direct-slice/assessments/'+aid+'.json']==manual,
                           'conflicting default/manual OCIL choices')
                native['authoring/direct-slice/assessments/'+aid+'.json']=manual
                native_rule['assessment_choices']['manual']={'assessment':aid}
                binding['manual_choices'].append({'selector':selector,**provenance});row['manual']=True
            except ValueError as error:row['blockers'].append(str(error))
        if any(c.get('system')==OVAL for c in checks):
            try:
                factory=RecoveryVisitor
                if approved_oracle_absence:
                    from .approved_absence import oracle_visitor
                    factory=oracle_visitor(factory,model,rid)
                if approved_absence_corrections:
                    from .approved_absence import approved_visitor
                    factory=approved_visitor(factory,model,rid)
                automatic,auto_binding=engine.convert_rule(model,rid,mappings,converter_factory=factory)
                ensure(not any(w.get('code')=='test_all_exist_unproved' for w in auto_binding.get('conversion_warnings',[])),
                       'all_exist recovery requires separately qualified population semantics')
                for name,doc in automatic.items():
                    for error in document_errors(snapshot,next(iter(doc)),doc):raise ValueError(error.message)
                auto_rule=next(d['rule'] for d in automatic.values() if 'rule' in d)
                native.update({p:d for p,d in automatic.items() if 'rule' not in d})
                native_rule.update({k:v for k,v in auto_rule.items() if k not in ('assessment_choices','default_assessment_choice')})
                native_rule['assessment_choices'].update(auto_rule['assessment_choices'])
                binding.update(auto_binding);row['automated_draft']=True
                if approved_absence_corrections:
                    corrections=[w for w in auto_binding.get('conversion_warnings',[]) if w.get('source_correction')]
                    if corrections:
                        row['owner_normalized']=True
                        row['source_corrections']=[w['code'] for w in corrections]
            except ValueError as error:row['blockers'].append(str(error))
        if native_rule['assessment_choices']:
            # A missing/unsupported source default is not replaced by another choice.
            if default not in native_rule['assessment_choices']:
                row['blockers'].append('source default choice unavailable')
                # Keep a supported manual method as an unbound document; never
                # switch the source default to hide missing automation.
                manuals={p:d for p,d in native.items() if d.get('assessment',{}).get('mode')=='manual'}
                ensure(not set(manuals)&set(docs),'duplicate standalone manual identity')
                docs.update(manuals)
            else:
                native_rule['default_assessment_choice']=default
                binding['native_rule']=native_rule['id']
                native['authoring/direct-slice/rules/'+native_rule['id']+'.json']={'rule':native_rule}
                for name,doc in native.items():
                    for error in document_errors(snapshot,next(iter(doc)),doc):raise ValueError(error.message)
                ensure(not set(native)&set(docs),'duplicate recovered document identity')
                docs.update(native);bindings.append(binding)
                row['rule_emitted']=True
                row.update(status=('BLOCKED' if row['blockers'] else 'AUTOMATED_DRAFT' if row['automated_draft'] else 'MANUAL'),
                           schema_validated=True,semantic_validated=True)
        rows.append(row)
    # Use the existing exact source profile projection; no selection flattening.
    docs,trace=engine.assemble_subset(model,docs,bindings,mappings)
    bid=native_identifier(model.benchmark,'benchmark')
    appid=bid.removesuffix('-benchmark')+'-applicability'
    for doc in docs.values():
        if 'benchmark' in doc:
            benchmark=doc['benchmark'];benchmark['id']=bid
            benchmark['title']=[{'text':model.benchmark.findtext('{'+XCCDF+'}title',''),'language':'en'}]
            benchmark['applicability_catalog']=appid
            benchmark['platform']['title']='Source applicability retained in source trace; execution unqualified'
            benchmark['metadata'].update(recovery_draft=True,full_policy_equivalence=False)
            if organization_parameters:
                for parameter in benchmark['parameters']:
                    parameter['resolution']='organization';parameter.pop('value',None)
        if 'applicability' in doc:doc['applicability']['id']=appid
    if organization_parameters and any('benchmark' in d for d in docs.values()):
        from scap_ng_tools.authoring.input_discovery import derive_choice
        benchmark=next(d['benchmark'] for d in docs.values() if 'benchmark' in d)
        parameters={p['id']:p for p in benchmark['parameters']}
        assessments={d['assessment']['id']:d['assessment'] for d in docs.values() if 'assessment' in d}
        for doc in docs.values():
            if 'rule' not in doc:continue
            rule=doc['rule'];rule['organizational_input_requirements']={}
            for selector,choice in rule['assessment_choices'].items():
                uses=derive_choice(assessments[choice['assessment']],choice.get('inputs',{}),parameters)
                if uses:rule['organizational_input_requirements'][selector]=uses
    docs={p.replace('authoring/direct-slice/','authoring/'+bid+'/'):d for p,d in docs.items()}
    validate_native_documents(snapshot,docs)
    trace['format']='native-recovery-trace/1'
    trace['scope']='Current native DRAFT automatic/manual projection; original source retained; full policy/CPE execution unqualified'
    trace['source_benchmark_xml']=ET.tostring(model.benchmark,encoding='unicode')
    trace['source_rule_records']=[{'id':rid,'xml':ET.tostring(rule,encoding='unicode')} for rid,rule in model.rules.items()]
    trace['source_components']={cid:{'sha256':model.component_hashes[cid],'root_tag':node.tag} for cid,node in model.components.items()}
    trace['controlled_organization_derivative']=organization_parameters
    trace['qualification']={'current_native_draft':True,'full_policy_equivalence':False,
                            'applicability_execution':False,'independent_source_proof':False,'scanner_execution':False}
    ledger={'format':'native-recovery-ledger/1','source_zip_sha256':model.zip_sha256,
            'source_xml_sha256':model.xml_sha256,'component_hashes':model.component_hashes,
            'schema_family_sha256':snapshot.manifest()['aggregate_sha256'],
            'controlled_organization_derivative':organization_parameters,
            'original_source_rules':len(model.rules),'selected_rules':selected,
            'rules':rows,'summary':{'source_rules':len(rows),'statuses':dict(Counter(r['status'] for r in rows)),
                'automated_draft':sum(r['automated_draft'] for r in rows),
                'manual_choices':sum(r['manual'] and r['rule_emitted'] for r in rows),
                'manual_assessments':sum(r['manual'] for r in rows),
                'independently_source_proved':0,'scanner_executed':0}}
    if binary32_contract is not None:
        trace['binary32_comparison_contract'] = binary32_contract
        ledger['binary32_comparison_contract'] = binary32_contract
    if approved_oracle_absence:
        trace['approved_oracle_absence_enabled']=True
        ledger['approved_oracle_absence_enabled']=True
    if approved_absence_corrections:
        trace['approved_absence_corrections_enabled']=True
        ledger['approved_absence_corrections_enabled']=True
    return docs,trace,ledger
