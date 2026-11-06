"""Shared file traversal and text regex behaviors, separate from predicates.

Each handler receives its disjoint source attributes after complete validation.
Unknown/deprecated traversal/view attributes fail closed rather than disappearing.
"""
from v04_direct_scap_source import UnsupportedSource, attributes, ensure, digest, xml_identity

BOOLEAN_DEFAULTS = {'ignore_case': False, 'multiline': True, 'singleline': False}
ITEM_CREATION = {'all_object_elements_fullfilled', 'filepath_exists'}
FILESYSTEMS = {'all': 'all', 'local': 'local', 'defined': 'same'}


def _drop_invalid_path_recursion(values, element, removed, warnings, *, path_kind):
    """Drop only source-invalid recursion controls from a non-equality path.

    OVAL Schematron disallows these controls on pattern/full paths. In native
    recovery the path selector remains the source acquisition boundary; the
    invalid controls cannot be represented without inventing traversal over a
    pattern population, so they are removed and retained as an explicit
    provenance warning. The historical/default path remains fail-closed.
    """
    if not removed:
        return values
    # Mutation is the recovery operation; warning emission is optional for
    # direct callers that do not have a converter provenance sink.
    for key in sorted(removed):
        values.pop(key, None)
    if warnings is not None:
        warnings.append({
            'code': 'oval_invalid_path_recursion_removed',
            'source_element': element.tag if element is not None else None,
            'source_element_sha256': digest(xml_identity(element)) if element is not None else None,
            'path_kind': path_kind,
            'removed_attributes': {key: element.get(key) for key in sorted(removed)},
            'semantic_basis': 'OVAL path recursion controls are invalid on non-equality selectors; native path population is retained without traversal',
            'independent_static_proof': 'SOURCE_SCHEMATRON_REPAIR_UNPROVED',
            'scanner_evaluated': False,
        })
    return values


def textfile_path_controls(element, acquisition, *, native_recovery=False, warnings=None):
    """Preserve original Textfilecontent54 path/behavior Schematron boundaries."""
    values = {} if element is None else dict(element.attrib)
    full_path, directory = acquisition.get('full_path'), acquisition.get('directory')
    if full_path is not None:
        removed = set(values) & {'max_depth', 'recurse_direction'}
        if native_recovery:
            values = _drop_invalid_path_recursion(values, element, removed, warnings, path_kind='full_path')
        else:
            ensure(not removed, 'invalid original textfile filepath recursion attributes')
    directory_equality = ({'equals', 'case_insensitive_equals'} if native_recovery
                         else {'equals'})
    if directory is not None and not (directory_equality & set(directory)):
        removed = set(values) & {'max_depth', 'recurse_direction', 'recurse'}
        if native_recovery:
            values = _drop_invalid_path_recursion(values, element, removed, warnings, path_kind='pattern_path')
        else:
            ensure(not removed, 'invalid original textfile pattern-path recursion attributes')
    selector = full_path if full_path is not None else directory
    ensure(values.get('recurse_file_system') != 'defined' or
           isinstance(selector, dict) and bool(directory_equality & set(selector)),
           'invalid original textfile defined-filesystem pattern selection')


def hierarchy_behaviors(element, acquisition, *, native_recovery=False):
    """Approved downward Registry traversal; group/view controls stay blocked.

    The recovery contract treats a typed case-insensitive equality selector as
    an equality path only when the capability mapping uses the same lookup
    domain. Pattern selectors remain non-recursive and the historical path
    keeps its stricter literal-equality admission.
    """
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
    equality = {'equals', 'case_insensitive_equals'} if native_recovery else {'equals'}
    ensure('key' in acquisition and (key is None or isinstance(key, dict) and equality & set(key)),
           'hierarchy recursion requires an equality key or hive-root selector')
    return {'traversal': {'max_depth': 'unlimited' if depth == -1 else depth}}


def traversal_behaviors(element, acquisition, *, windows=False, selector_map=None, native_recovery=False, warnings=None):
    """Translate shared FileBehaviors without changing a selector's meaning.

    OVAL defaults recursion to none. Downward traversal applies only to an
    equality path selector, never a full filepath. Deprecated upward recursion
    and unimplemented platform-view controls remain explicit blockers.
    """
    values = {} if element is None else dict(element.attrib)
    selector_map = selector_map or {}
    filepath_key = selector_map.get('filepath', 'full_path')
    path_key = selector_map.get('path', 'directory')
    equality_ops = ({'equals', 'case_insensitive_equals'} if native_recovery
                    else {'equals'})
    if element is not None:
        attributes(element, {'max_depth', 'recurse', 'recurse_direction', 'recurse_file_system'})
        ensure(not len(element) and not (element.text or '').strip(), 'behaviors must have no content')
    directory = acquisition.get(path_key)
    full_path = acquisition.get(filepath_key)
    if windows:
        # Keep the original Windows Schematron boundary in historical mode.
        # Native recovery has an explicit, narrow repair for source-invalid
        # recursion controls: retain the selector and filesystem scope, but
        # remove only controls that cannot describe a pattern/full-path
        # population. This is not a general compatibility fallback.
        if directory is not None and not equality_ops & set(directory):
            removed = set(values) & {'max_depth', 'recurse', 'recurse_direction'}
            if native_recovery:
                values = _drop_invalid_path_recursion(values, element, removed, warnings,
                                                       path_kind='pattern_path')
            else:
                ensure(not removed, 'invalid original pattern-path recursion attributes')
        if full_path is not None:
            removed = set(values) & {'max_depth', 'recurse_direction'}
            if native_recovery:
                values = _drop_invalid_path_recursion(values, element, removed, warnings,
                                                       path_kind='full_path')
            else:
                ensure(not removed, 'invalid original filepath recursion attributes')
        scope = values.get('recurse_file_system', 'all')
        ensure(scope in FILESYSTEMS, 'unsupported original filesystem scope')
        selector = full_path if full_path is not None else directory
        ensure(scope != 'defined' or isinstance(selector, dict) and equality_ops & set(selector),
               'invalid original defined-filesystem pattern selection')
    # Parse only after recovery removed path-invalid controls. A malformed or
    # deprecated value on an attribute that the source schema itself forbids
    # must not turn a recoverable source Rule into a fabricated traversal.
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
    result = {'filesystem': FILESYSTEMS[scope]}
    if direction == 'down' and filepath_key not in acquisition and isinstance(directory, dict) and equality_ops & set(directory):
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
