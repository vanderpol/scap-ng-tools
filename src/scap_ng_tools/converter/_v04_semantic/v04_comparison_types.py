"""Deterministic comparison type constraints; no runtime coercion (#255/#268).

Native contract, self-describing operator, explicit compatible tag, YAML
literal and declared Variable/Input constrain one domain. No values execute.
"""
from functools import lru_cache
import json
from pathlib import Path

from . import capability_contract
TEXT_TYPES = {'string', 'binary', 'version', 'ipv4', 'ipv6', 'rpm_evr', 'debian_evr',
              'fileset_revision', 'ios_version'}
TYPED = sorted(TEXT_TYPES - {'string'} | {'float'}, key=len, reverse=True)


@lru_cache(maxsize=100)
def contract(capability):
    mapping, generated = capability_contract(capability)
    return generated['fields'], set(generated['records']), generated['selectors'], mapping['native']


def scalar_type(value):
    if isinstance(value, bool): return 'boolean'
    if isinstance(value, int): return 'integer'
    if isinstance(value, float): return 'float'
    if isinstance(value, str): return 'string'
    raise ValueError('comparison operand is not a typed scalar or declared reference')


def predicate_type(predicate, allowed, assessment, path):
    if set(predicate) == {'values_found'} and predicate['values_found'] == 'none':
        return None
    controls = {'datatype', 'values_found', 'values_matching', 'value_match', 'redact_result', 'selection_match'}
    operations = set(predicate) - controls
    if len(operations) != 1:
        raise ValueError(path + ': expected one comparison operation')
    operation, = operations
    value = predicate[operation]
    typed = next((domain for domain in TYPED if operation.startswith(domain + '_')), None)
    explicit = predicate.get('datatype')
    if typed and explicit and typed != explicit:
        raise ValueError(path + ': explicit datatype conflicts with typed operator')
    chosen = typed or explicit
    constraints = set(allowed)
    if chosen:
        constraints &= {chosen}
    elif len(constraints) == 1:
        chosen = next(iter(constraints))
    values = value if isinstance(value, list) else [value]
    inferred = set()
    for item in values:
        if isinstance(item, dict):
            if len(item) != 1 or not (set(item) & {'variable', 'input'}):
                raise ValueError(path + ': unsupported comparison reference shape')
            kind, identity = next(iter(item.items()))
            section = 'variables' if kind == 'variable' else 'inputs'
            declaration = assessment.get(section, {}).get(identity)
            if not isinstance(declaration, dict) or not isinstance(declaration.get('datatype'), str):
                raise ValueError(path + ': unresolved or untyped ' + kind + ' ' + str(identity))
            domain = declaration['datatype']
        else:
            domain = scalar_type(item)
            # String-backed semantic domains retain lexical text. This is not
            # conversion of text to numbers/Boolean, nor generic string order.
            if chosen in TEXT_TYPES and domain == 'string': domain = chosen
            if chosen == 'float' and domain == 'integer': domain = 'float'
        inferred.add(domain)
    if len(inferred) != 1:
        raise ValueError(path + ': mixed/ambiguous comparison operand types')
    domain, = inferred
    constraints &= {domain}
    if len(constraints) != 1:
        raise ValueError(path + ': operand/explicit datatype conflicts with capability contract')
    return domain


def condition_types(node, fields, records, assessment, path, *, member=False, flat=False):
    """Only condition/record grammar is traversed; literal data is opaque."""
    rows=[]
    for operator in ('and', 'or', 'one', 'xor'):
        for i, child in enumerate(node.get(operator, [])):
            rows.extend(condition_types(child,fields,records,assessment,path+'/'+operator+'/'+str(i),member=member,flat=flat))
    predicates=node.get('fields', {})
    if flat and not (set(node) & {'fields','and','or','one','xor'}):
        predicates={k:v for k,v in node.items() if k!='field_requirement'}
    for field,predicate in predicates.items():
        route=path+'/fields/'+field
        if not member and field not in fields:
            raise ValueError(route+': field absent from capability contract')
        if 'record' in predicate:
            if not member and field not in records:
                raise ValueError(route+': record conflicts with scalar capability field')
            rows.extend(condition_types(predicate['record'],fields,records,assessment,route+'/record',member=True))
            continue
        allowed=set(fields[field]) if not member else TEXT_TYPES | {'integer','float','boolean'}
        rows.append({'path':route,'datatype':predicate_type(predicate,allowed,assessment,route)})
    return rows


def assessment_comparison_types(assessment):
    from .v04_input_presence import presence_contract
    presence_contract(assessment)  # Includes transitive optional-use dominance.
    rows=[]
    for test_id,test in assessment.get('tests',{}).items():
        fields,records,_,_=contract(test.get('capability'))
        rows.extend(condition_types(test.get('require',{}),fields,records,assessment,'/tests/'+test_id+'/require'))
    # Acquisition and collection-value comparisons have distinct contracts.
    # Visit grammar-owned sites, including shared/Set/Variable Objects; never
    # traverse literal payloads or infer a universal selector datatype.
    from .v04_object_contract import object_sites
    for site in object_sites(assessment):
        fields, records, selectors, native = contract(site.capability)
        parameters = native.get('collection_parameters', {})
        parameter_types = {name: ([spec['semantic_datatype']] if spec.get('semantic_datatype') else
                                  ['integer','float'] if spec['type']=='number' else [spec['type']])
                           for name, spec in parameters.items()
                           if spec.get('type') in ('string', 'integer', 'float', 'number', 'boolean')}
        domains = {**native.get('field_datatypes', {}), **selectors, **parameter_types}
        for name,spec in parameters.items():
            value=site.node.get(name)
            if spec.get('schema_ref')=='object_record' and isinstance(value,dict):
                condition_types(value,fields,records,assessment,'/'+ '/'.join(map(str,site.path))+'/'+name,member=True)
        def filters(node,path):
            for i,operand in enumerate(node.get('operands',[])):
                route=path+'/operands/'+str(i)
                for j,flt in enumerate(operand.get('filters',[])):
                    for action,payload in flt.items():
                        if action in ('include','exclude'):
                            condition_types(payload,fields,records,assessment,route+'/filters/'+str(j)+'/'+action,flat=True)
                if isinstance(operand.get('set'),dict):filters(operand['set'],route+'/set')
        if isinstance(site.node.get('set'),dict):filters(site.node['set'],'/'+ '/'.join(map(str,site.path))+'/set')
        for name, value in site.node.items():
            if name not in domains or value is None or 'record' in domains[name]:
                continue
            route = '/' + '/'.join(map(str, site.path)) + '/' + name
            if isinstance(value, dict) and (set(value) & {'for_each', 'from_item'}):
                continue  # Source projection lineage has its own checked gate.
            if not isinstance(value, dict) or set(value) <= {'variable', 'input'}:
                predicate = {'equals': value}
            else:
                predicate = value
            predicate_type(predicate, set(domains[name]), assessment, route)
    return rows


def comparison_errors(document):
    from jsonschema import ValidationError
    assessment = document.get('assessment')
    if not isinstance(assessment, dict) or assessment.get('mode') != 'automated': return
    if (assessment.get('specification') or {}).get('version') != '0.4.0': return
    try:
        assessment_comparison_types(assessment)
    except (ValueError, KeyError, TypeError) as error:
        yield ValidationError('Native comparison datatype: ' + str(error), validator='native_comparison_datatype')
