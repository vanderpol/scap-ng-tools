"""Translate OVAL YAML record key escaping to approved native key identity.

Only yamlfilecontent uses this encoding. Other record capabilities keep their
own key contracts. This is not YAML Path parsing or scanner execution.
"""
from v04_direct_scap_source import ensure


def yaml_record_key(name):
    result, offset = [], 0
    while offset < len(name):
        character = name[offset]
        if character == '^':
            offset += 1
            ensure(offset < len(name) and (name[offset] == '^' or 'a' <= name[offset] <= 'z'),
                   'unsupported/noncanonical original YAML record key escape')
            character = name[offset] if name[offset] == '^' else name[offset].upper()
        result.append(character)
        offset += 1
    return ''.join(result)


def yaml_acquisition(acquisition, behaviors):
    """Reject unsupported/invalid combinations before generic file lowering."""
    selectors = set(acquisition) & {'full_path', 'directory', 'name', 'content', 'yamlpath'}
    ensure(selectors in ({'full_path', 'yamlpath'}, {'directory', 'name', 'yamlpath'},
                         {'content', 'yamlpath'}), 'invalid original YAML acquisition alternatives')
    for field in ('content', 'yamlpath'):
        if field in acquisition:
            ensure('equals' in acquisition[field], 'YAML ' + field + ' requires equality')
    if 'content' in acquisition:
        ensure(behaviors is None, 'inline YAML content with file behaviors is not supported')
    elif behaviors is not None:
        values = behaviors.attrib
        if 'full_path' in acquisition:
            ensure(not set(values) & {'max_depth', 'recurse_direction'},
                   'invalid original YAML filepath recursion attributes')
        selector = acquisition.get('full_path', acquisition.get('directory'))
        ensure(values.get('recurse_file_system') != 'defined' or 'equals' in selector,
               'invalid original YAML defined-filesystem pattern selection')
