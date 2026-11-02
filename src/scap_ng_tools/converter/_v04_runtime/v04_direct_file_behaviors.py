"""Shared file traversal and text regex behaviors, separate from predicates.

Each handler receives its disjoint source attributes after complete validation.
Unknown/deprecated traversal/view attributes fail closed rather than disappearing.
"""
from v04_direct_scap_source import UnsupportedSource, attributes, ensure

BOOLEAN_DEFAULTS = {'ignore_case': False, 'multiline': True, 'singleline': False}
ITEM_CREATION = {'all_object_elements_fullfilled', 'filepath_exists'}
FILESYSTEMS = {'all': 'all', 'local': 'local', 'defined': 'same'}


def textfile_path_controls(element, acquisition):
    """Preserve original Textfilecontent54 path/behavior Schematron boundaries."""
    values = {} if element is None else element.attrib
    full_path, directory = acquisition.get('full_path'), acquisition.get('directory')
    if full_path is not None:
        ensure(not set(values) & {'max_depth', 'recurse_direction'},
               'invalid original textfile filepath recursion attributes')
    if directory is not None and 'equals' not in directory:
        ensure(not set(values) & {'max_depth', 'recurse_direction', 'recurse'},
               'invalid original textfile pattern-path recursion attributes')
    selector = full_path if full_path is not None else directory
    ensure(values.get('recurse_file_system') != 'defined' or isinstance(selector, dict) and 'equals' in selector,
           'invalid original textfile defined-filesystem pattern selection')


def hierarchy_behaviors(element, acquisition):
    """Approved downward Registry traversal; group/view controls stay blocked."""
    values = {} if element is None else element.attrib
    if element is not None:
        attributes(element, {'max_depth', 'recurse_direction'})
        ensure(not len(element) and not (element.text or '').strip(), 'behaviors must have no content')
    try:
        depth = int(values.get('max_depth', '-1'))
    except ValueError as error:
        raise UnsupportedSource('invalid original hierarchy max_depth') from error
    ensure(depth >= -1, 'original hierarchy max_depth must be -1 or nonnegative')
    direction = values.get('recurse_direction', 'none')
    ensure(direction in ('none', 'down'), 'unsupported/deprecated hierarchy recursion direction')
    if direction == 'none':
        return {}
    key = acquisition.get('key')
    ensure('key' in acquisition and (key is None or isinstance(key, dict) and 'equals' in key),
           'hierarchy recursion requires an equality key or hive-root selector')
    return {'traversal': {'max_depth': 'unlimited' if depth == -1 else depth}}


def traversal_behaviors(element, acquisition, *, windows=False):
    """Translate shared FileBehaviors without changing a selector's meaning.

    OVAL defaults recursion to none. Downward traversal applies only to an
    equality path selector, never a full filepath. Deprecated upward recursion
    and unimplemented platform-view controls remain explicit blockers.
    """
    values = {} if element is None else element.attrib
    if element is not None:
        attributes(element, {'max_depth', 'recurse', 'recurse_direction', 'recurse_file_system'})
        ensure(not len(element) and not (element.text or '').strip(), 'behaviors must have no content')
    try:
        depth = int(values.get('max_depth', '-1'))
    except ValueError as error:
        raise UnsupportedSource('invalid original max_depth') from error
    ensure(depth >= -1, 'original max_depth must be -1 or nonnegative')
    direction = values.get('recurse_direction', 'none')
    ensure(direction in ('none', 'down'), 'unsupported/deprecated recursion direction')
    options = ({'directories': 'directories', 'junctions': 'junctions',
                'junctions and directories': 'junctions_and_directories'} if windows else
               {'directories': 'directories', 'symlinks': 'symlinks',
                'symlinks and directories': 'symlinks_and_directories'})
    recurse = values.get('recurse', 'directories' if windows else 'symlinks and directories')
    ensure(recurse in options, 'unsupported/deprecated original recurse value')
    scope = values.get('recurse_file_system', 'all')
    ensure(scope in FILESYSTEMS, 'unsupported original filesystem scope')
    if windows:
        # Keep the original Windows Schematron boundary: these attributes
        # cannot be supplied on a pattern path, even if recursion would be
        # ignored. Do not turn invalid original input into admitted authoring.
        directory = acquisition.get('directory')
        full_path = acquisition.get('full_path')
        if directory is not None and 'equals' not in directory:
            ensure(not set(values) & {'max_depth', 'recurse', 'recurse_direction'},
                   'invalid original pattern-path recursion attributes')
        if full_path is not None:
            ensure(not set(values) & {'max_depth', 'recurse_direction'},
                   'invalid original filepath recursion attributes')
        selector = full_path if full_path is not None else directory
        ensure(scope != 'defined' or isinstance(selector, dict) and 'equals' in selector,
               'invalid original defined-filesystem pattern selection')
    result = {'filesystem': FILESYSTEMS[scope]}
    directory = acquisition.get('directory')
    if direction == 'down' and 'full_path' not in acquisition and isinstance(directory, dict) and 'equals' in directory:
        result['traversal'] = {'max_depth': 'unlimited' if depth == -1 else depth, 'recurse': options[recurse]}
    return result


def file_behaviors(element):
    """An optional original behaviors element -> explicit native parameters."""
    values = {} if element is None else element.attrib
    if element is not None:
        attributes(element, set(BOOLEAN_DEFAULTS) | {'item_creation', 'recurse_file_system'})
        ensure(not len(element) and not (element.text or '').strip(), 'behaviors must have no content')
    result = {}
    for name, default in BOOLEAN_DEFAULTS.items():
        value = values.get(name, 'true' if default else 'false')
        ensure(value in ('true', 'false', '1', '0'), 'invalid original behavior boolean: ' + name)
        result[name] = value in ('true', '1')
    creation = values.get('item_creation', 'all_object_elements_fullfilled')
    ensure(creation in ITEM_CREATION, 'unsupported item_creation')
    filesystem = values.get('recurse_file_system', 'all')
    ensure(filesystem in FILESYSTEMS, 'unsupported original filesystem scope')
    result.update(item_creation=creation, filesystem=FILESYSTEMS[filesystem])
    return result
