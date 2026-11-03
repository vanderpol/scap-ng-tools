"""Source-attested Oracle-only and eight-case owner-correction profiles.

This is an explicit owner-normalized DRAFT, never a general proof that a
comparator-bearing absence is equivalent to comparator-free native absence.
"""
PIN='6733abd693380b43b2350c2692775e4ff902f895f16899db97b34fecf7fba74d'
RULE='xccdf_mil.disa.stig_rule_SV-271844r1184222_rule'
RULE_HASH='3e3a4a2456fdc7b9fc0476bc1f5d2d057f8537ebda1a1e55b94fff85b20c2d97'
COMPONENT='scap_navy.navwar.niwcatlantic.scc_comp_U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-oval2.xml'
PREFIX='oval:navy.navwar.niwcatlantic.scc.rhel8:'
NODES={
    PREFIX+'def:271844':'e4a8d309809278db0a65db19ed3bcd88823f8577851ed6ec12d71300eb3b2c54',
    PREFIX+'tst:27184401':'8afa1a93d5de093509ac2cfb640765fcf25b4eea511c7d6c542865caaf81c6a0',
    PREFIX+'obj:27184401':'35bfa2c3252215f07437067836160b93af8a258e5d360dd09d3fe52e8f0bec30',
    PREFIX+'ste:27184401':'6a157df96f01dc0ee861e86350766a8bb74c093c8d74e4ad1876b381a97771a5'}


def oracle_visitor(base,source,rule_id):
    """All other sources/Rules retain the exact preceding strict recovery path."""
    if source.zip_sha256!=PIN or rule_id!=RULE:return base
    from v04_direct_scap_source import digest,xml_identity,ensure
    def attest():
        ensure(digest(xml_identity(source.rules[RULE]))==RULE_HASH,'approved Oracle Rule changed')
        cid,did,_=source.automated_check(source.rules[RULE])
        ensure(cid==COMPONENT and did==PREFIX+'def:271844','approved Oracle binding changed')
        for ident,expected in NODES.items():
            ensure(ident in source.nodes[cid] and digest(xml_identity(source.nodes[cid][ident]))==expected,
                   'approved Oracle source node changed: '+ident)
        return source.nodes[cid][PREFIX+'ste:27184401'][0]
    field=attest()
    class ApprovedOracleVisitor(base):
        def predicate(self,element,mapping,selector=False,*,record_field=False):
            if element is field and not selector and not record_field and mapping['capability']=='independent.shellcommand':
                attest()  # Guard model changes after Visitor construction too.
                result={'values_found':'none'}
                self.conversion_warnings.append({'code':'approved_oracle_absence_20261024',
                    'decision':'Existing owner-approved Oracle SV-271844 source correction, 2026-10-24',
                    'decision_record':'https://github.com/vanderpol/scap-ng-research/blob/855c6023d55d882b55c0507d5492e6f4e4946023/docs/audit/v04-six-stig-current-schema-20261024.md',
                    'source_zip_sha256':PIN,'source_rule':RULE,'source_rule_sha256':RULE_HASH,
                    'source_nodes':dict(NODES),'source_entity':xml_identity(element),
                    'source_entity_sha256':digest(xml_identity(element)),'native_predicate':dict(result),
                    'native_predicate_sha256':digest(result),'source_correction':True,
                    'independent_static_proof':'UNPROVED','scanner_evaluated':False})
                return result
            return super().predicate(element,mapping,selector,record_field=record_field)
    return ApprovedOracleVisitor


def approved_visitor(base,source,rule_id):
    """Explicit eight-case profile; the old Oracle-only profile stays bounded."""
    from .approved_absence_cases import CASES
    base=oracle_visitor(base,source,rule_id)
    case=CASES.get(rule_id)
    if case is None or source.zip_sha256!=case['source_zip_sha256']:return base
    from v04_direct_scap_source import digest,xml_identity,ensure
    def attest():
        ensure(digest(xml_identity(source.rules[rule_id]))==case['source_rule_sha256'],
               'approved absence Rule changed')
        cid,did,_=source.automated_check(source.rules[rule_id])
        ensure((cid,did)==(case['component'],case['definition']),'approved absence binding changed')
        for ident,expected in case['source_nodes'].items():
            ensure(ident in source.nodes[cid] and digest(xml_identity(source.nodes[cid][ident]))==expected,
                   'approved absence source node changed: '+ident)
        state=source.nodes[cid][case['state']]
        ensure(len(state)==1 and digest(xml_identity(state[0]))==case['field_sha256'],
               'approved absence field changed')
        return state[0]
    field=attest()
    class ApprovedAbsenceVisitor(base):
        def predicate(self,element,mapping,selector=False,*,record_field=False):
            if element is field and not selector and not record_field and mapping['capability']=='independent.shellcommand':
                attest()
                result={'values_found':'none'}
                self.conversion_warnings.append({'code':'approved_absence_20261103',
                    'decision':'Owner-approved exact-source intended-policy correction, 2026-11-03',
                    'decision_record':'https://github.com/vanderpol/scap-ng-tools/issues/14#issuecomment-6615375024',
                    'source_zip_sha256':case['source_zip_sha256'],'source_rule':rule_id,
                    'source_rule_sha256':case['source_rule_sha256'],'source_nodes':dict(case['source_nodes']),
                    'source_entity':xml_identity(element),'source_entity_sha256':digest(xml_identity(element)),
                    'native_predicate':dict(result),'native_predicate_sha256':digest(result),
                    'source_correction':True,'owner_normalized':True,
                    'independent_static_proof':'UNPROVED','scanner_evaluated':False})
                return result
            return super().predicate(element,mapping,selector,record_field=record_field)
    return ApprovedAbsenceVisitor
