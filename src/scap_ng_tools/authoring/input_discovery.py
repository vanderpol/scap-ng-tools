"""Approved pre-release 0.4 discovery derivation, without evaluation or I/O.

This index is not a substitute for schema, binding/type, reference closure or
optional-use dominance validation. Callers must run their version-pinned gates.
Literal payloads and descriptive metadata are data, never executable references.
"""


def input_locations(assessment):
    result=[]
    def walk(node,path):
        if isinstance(node,list):
            for index,child in enumerate(node):walk(child,path+[str(index)])
        elif isinstance(node,dict):
            if set(node)=={'literal'} and (not path or path[-1]!='fields'):return
            for key,child in node.items():
                route=path+[key]
                if isinstance(child,str) and ((key=='input' and set(node)=={'input'}) or (key=='input_provided' and set(node)=={'input_provided'})):
                    pointer='/'+'/'.join(str(p).replace('~','~0').replace('/','~1') for p in route)
                    result.append({'input':child,'source_path':pointer,
                                   'kind':'presence' if key=='input_provided' else 'value'})
                else:walk(child,route)
    for section in ('tests','variables','shared_objects','evaluate','applicability'):
        walk(assessment.get(section),[section])
    return result


def derive_choice(assessment,bindings,parameters):
    """Derive all value/presence sites grouped by organization Parameter ID."""
    locations=input_locations(assessment);grouped={}
    for name,binding in bindings.items():
        parameter=binding if isinstance(binding,str) else binding.get('parameter') if isinstance(binding,dict) else None
        if name not in assessment.get('inputs',{}) or parameter not in parameters:
            raise ValueError('discovery derivation requires resolved Input/Parameter bindings')
        declaration=assessment['inputs'][name]
        if type(declaration.get('required')) is not bool:
            raise ValueError('discovery derivation requires explicit Input required flag')
        if parameters[parameter].get('resolution')!='organization':continue
        uses=[{k:site[k] for k in ('kind','source_path')} for site in locations if site['input']==name]
        if not uses:raise ValueError('bound organizational Input has no native reference')
        row=grouped.setdefault(parameter,{'input':parameter,'required':False,'uses':[]})
        row['required']=row['required'] or declaration['required'];row['uses'].extend(uses)
    result=[]
    for parameter,row in sorted(grouped.items()):
        row['uses'].sort(key=lambda use:(use['source_path'],use['kind']));result.append(row)
    return result
