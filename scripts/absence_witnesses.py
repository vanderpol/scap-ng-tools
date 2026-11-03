#!/usr/bin/env python3
"""Independent pinned-XSD status-table witnesses; no Rule/scanner evaluation."""
import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def rows(text,width):
    result=[]
    for line in text.splitlines():
        parts=line.split('||')
        if len(parts)!=3:continue
        tokens=[token.strip() for token in parts[1].split('|')]
        outcome=parts[2].strip().lower().replace(' ','_')
        if len(tokens)==width and all(re.fullmatch(r'[0-9]+\+?',token) for token in tokens):
            result.append((tokens,outcome))
    return result


def evaluate(table,counts):
    matches=[]
    for tokens,outcome in table:
        if all(count>=int(token[:-1]) if token.endswith('+') else count==int(token)
               for token,count in zip(tokens,counts)):
            matches.append(outcome)
    if len(matches)>1:raise ValueError('ambiguous chart row')
    return matches[0] if matches else None


def witnesses(oval_root):
    path=Path(oval_root)/'oval-schemas/oval-common-schema.xsd'
    root=ET.parse(path).getroot()
    charts=[''.join(node.itertext()) for node in root.iter() if node.tag.rsplit('}',1)[-1]=='evaluation_chart']
    none,=[chart for chart in charts if 'none_exist' in chart]
    all_values,=[chart for chart in charts if re.search(r'\bALL\s+\|\|',chart)]
    existence=rows(none,4);aggregate=rows(all_values,6)
    if len(existence)!=4 or len(aggregate)!=6:raise ValueError('pinned table shape changed')
    cases=[]
    for ex,de,err,nc in product(range(3),repeat=4):
        actual=evaluate(existence,(ex,de,err,nc))
        independent='false' if ex else 'error' if err else 'unknown' if nc else 'true'
        if actual!=independent:raise AssertionError((ex,de,err,nc,actual))
        cases.append({'exists':ex,'does_not_exist':de,'error':err,'not_collected':nc,'existence_piece':actual})
    if evaluate(aggregate,(0,0,0,0,0,0)) is not None:raise AssertionError('empty ALL chart unexpectedly resolved')
    values=['','\n','ordinary text','permission denied','nonmatching-looking content']
    lexical=[{'value':value,'universal_pattern_matches':re.search('.*',value) is not None,
              'exists':1,'none_exist_piece':evaluate(existence,(1,0,0,0))} for value in values]
    return {'format':'issue14-absence-status-witnesses/1','oval_commit':'2f140ee5c5dd1ed9606fcd5afc301f6baeb48706',
        'schema_sha256':sha256(path.read_bytes()).hexdigest(),'none_exist_chart':existence,
        'population_cases':cases,'lexical_cases':lexical,
        'empty_all_value_aggregate':'NO_ROW_IN_PINNED_NORMATIVE_CHART',
        'qualification':'81 existence-piece cases independently checked. Regex universality does not resolve zero-value aggregation or prove complete source equivalence.',
        'source_semantic_proof':False,'scanner_execution':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--oval-root',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('refusing existing output')
    result=witnesses(a.oval_root);a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'population_cases':len(result['population_cases']),'lexical_cases':len(result['lexical_cases']),
                      'empty_all_value_aggregate':result['empty_all_value_aggregate']}))


if __name__=='__main__':main()
