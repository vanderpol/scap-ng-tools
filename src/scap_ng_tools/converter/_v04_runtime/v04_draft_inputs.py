"""Bounded, explicit XCCDF export -> Parameter -> Assessment Input drafting."""
from v04_direct_scap_source import XCCDF, OVAL, attributes, ensure, native_identifier, digest, xml_identity, local_name
from v04_direct_datatypes import native_datatype
from v04_draft_compatibility import DECISION


def source_disambiguated_identifier(visitor, element, suffix, peers):
    """Keep readable names unless source descriptors actually collide.

    XCCDF Values and OVAL external Variables are globally benchmark-scoped,
    while their titles/comments are not identities.  Add a deterministic
    source-ID token only for duplicate descriptors so shared uses of the same
    source node retain the original native name.
    """
    identifier = native_identifier(element, suffix)
    descriptors = [native_identifier(peer, suffix) for peer in peers]
    if descriptors.count(identifier) <= 1:
        return identifier
    token = digest(element.get('id'))[:10]
    stem = identifier.removesuffix('-' + suffix)
    budget = 64 - len(suffix) - len(token) - 2
    ensure(budget >= 1, 'native source discriminator exceeds identifier budget')
    return stem[:budget].rstrip('-') + '-' + token + '-' + suffix


def value_parameter_identifier(visitor, value):
    nodes = visitor.source.nodes.get(visitor.source.benchmark_component, {})
    peers = [node for node in nodes.values() if node.tag == '{' + XCCDF + '}Value']
    return source_disambiguated_identifier(visitor, value, 'parameter', peers)


def external_input_identifier(visitor, element):
    nodes = visitor.source.nodes.get(visitor.component_id, {})
    peers = [node for node in nodes.values() if local_name(node) == 'external_variable']
    return source_disambiguated_identifier(visitor, element, 'input', peers)


def check_exports(source, rule):
    mappings=[]
    for check in rule.findall('{'+XCCDF+'}check'):
        if check.get('system') != OVAL:
            continue
        exports={}
        for node in check.findall('{'+XCCDF+'}check-export'):
            attributes(node, {'value-id','export-name'})
            variable,value=node.get('export-name'),node.get('value-id')
            ensure(variable and value and variable not in exports and not len(node), 'ambiguous/malformed check-export')
            target=source.nodes[source.benchmark_component].get(value)
            ensure(target is not None and target.tag=='{'+XCCDF+'}Value', 'unresolved check-export Value')
            exports[variable]=target
        mappings.append(exports)
    ensure(not mappings or all({k:digest(xml_identity(v)) for k,v in m.items()} ==
        {k:digest(xml_identity(v)) for k,v in mappings[0].items()} for m in mappings),
        'conflicting default/automated check-export bindings')
    return mappings[0] if mappings else {}


def external_input(visitor, element):
    recovery = getattr(visitor, 'native_recovery', False)
    ident=element.get('id');value=visitor.bound_exports.get(ident)
    ensure(value is not None and all(n.tag=='{'+OVAL+'}possible_value' for n in element),
           'unbound external Variable or unsupported possible_restriction')
    attributes(value, {'id','type','operator','interactive','interfaceHint','hidden'})
    ensure(value.get('operator','equals')=='equals', 'XCCDF Value operator requires an explicit constraint adapter')
    allowed_names = ['title', 'description', 'value', 'reference']
    if recovery:
        allowed_names.append('warning')
    allowed_children = {'{'+XCCDF+'}'+name for name in allowed_names}
    ensure(all(n.tag in allowed_children for n in value),
           'XCCDF Value constraints require a supported Parameter adapter')
    # XCCDF warning text is non-executable guidance. It is retained in the
    # source Value XML provenance below; it must not be mistaken for an
    # allowed-value or relational constraint in the native Parameter.
    if recovery:
        for warning in value.findall('{'+XCCDF+'}warning'):
            attributes(warning, {'category', '{http://www.w3.org/XML/1998/namespace}lang'})
            ensure(not len(warning), 'complex XCCDF warning is unsupported')
    datatype=element.get('datatype')
    source_type=value.get('type','string')
    ensure(source_type=={'string':'string','boolean':'boolean','int':'number','float':'number'}.get(datatype),
           'check-export source/Variable datatype mismatch')
    defaults=[n for n in value.findall('{'+XCCDF+'}value') if not n.get('selector')]
    ensure(len(defaults)<=1 and all(not len(n) for n in value.findall('{'+XCCDF+'}value')), 'ambiguous/complex XCCDF default')
    input_id=(external_input_identifier(visitor, element) if recovery else
              native_identifier(element, 'input'))
    parameter_id=(value_parameter_identifier(visitor, value) if recovery else
                  native_identifier(value, 'parameter'))
    contract={'datatype':native_datatype(datatype),'cardinality':'exactly_one','required':True,
              'description':value.findtext('{'+XCCDF+'}description','')}
    parameter={'id':parameter_id,'datatype':native_datatype(datatype),'cardinality':'one','required':True,
               'resolution':'publisher' if defaults else 'organization',
               'title':value.findtext('{'+XCCDF+'}title',''), 'description':contract['description']}
    if defaults:
        parameter['value']=visitor.literal(datatype,defaults[0].text or '')
    allowed=[]
    for node in element:
        attributes(node,{'hint'})
        ensure(not len(node),'complex possible_value unsupported')
        allowed.append(visitor.literal(datatype,node.text or ''))
    if allowed:
        contract['constraints']={'allowed':allowed}
        parameter['constraints']={'allowed':allowed}
        ensure(not defaults or parameter['value'] in allowed,'publisher default violates external Variable allowed values')
    visitor.inputs[input_id]=contract
    visitor.policy_parameters[parameter_id]=parameter
    visitor.input_bindings[input_id]={'parameter':parameter_id}
    native = getattr(visitor, 'native_recovery', False)
    visitor.conversion_warnings.append({
        'code': 'native_input_binding_unproved' if native else 'check_export_binding_unproved',
        'owner_decision': ('https://github.com/vanderpol/scap-ng/issues/8#issuecomment-6587857027'
                           if native else DECISION),
        'source_external_variable': ident,
        'source_variable_sha256': digest(xml_identity(element)),
        'source_value': value.get('id'),
        'source_value_sha256': digest(xml_identity(value)),
        'source_value_xml': xml_identity(value),
        'input': input_id,
        'parameter': parameter_id,
        'resolution': parameter['resolution'],
        'independent_static_proof': 'UNPROVED',
        'scanner_runtime': 'NOT_RUN',
        'message': ('Explicit typed native 0.4 Input/Parameter binding retained; '
                    'policy/runtime binding equivalence independently unproved.'
                    if native else
                    'Explicit typed expected-value binding retained; policy/runtime '
                    'binding equivalence independently unproved.'),
    })
    return {'input':input_id}
