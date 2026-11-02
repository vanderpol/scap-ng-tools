"""Owner-authorized draft compatibility; never an independent proof (#260)."""
from collections import defaultdict

from v04_direct_scap_source import DS, digest, xml_identity

CAT = 'urn:oasis:names:tc:entity:xmlns:xml:catalog'
DECISION = 'https://github.com/vanderpol/scap-ng/issues/260#issuecomment-6510844015'


def resolve_draft_catalog(source):
    """Follow only named original entries; never search components by suffix/ID.

    Broken unused entries remain diagnostics. A missing, duplicate or conflicting
    binding for a requested name stays unresolved, even if another component
    happens to contain its requested Definition.
    """
    groups = defaultdict(lambda: {'standard': [], 'extension': []})
    for catalog in source.checklist.findall('.//{' + CAT + '}catalog'):
        for entry in catalog:
            if entry.tag in ('{' + CAT + '}uri', '{' + DS + '}uri'):
                groups[entry.get('name')]['standard' if entry.tag == '{' + CAT + '}uri' else 'extension'].append(entry)
    bindings, errors, warnings = {}, {}, {}
    for name, choices in groups.items():
        try:
            if not name or any(len(entries) > 1 for entries in choices.values()):
                raise ValueError('ambiguous/missing catalog name')
            resolved = {}
            for kind, entries in choices.items():
                if not entries:
                    continue
                entry = entries[0]
                uri = entry.get('uri', '')
                if not uri.startswith('#') or len(uri) == 1:
                    raise ValueError('nonlocal/missing catalog target')
                resolved[kind] = source.component_for_reference(uri[1:])
            if len(set(resolved.values())) != 1:
                raise ValueError('conflicting standard/extension catalog targets')
            component = next(iter(resolved.values()))
            bindings[name] = component
            if 'standard' not in resolved:
                entry = choices['extension'][0]
                warnings[name] = {
                    'code': 'niwc_ds_uri_compatibility', 'owner_decision': DECISION,
                    'original_element_qname': entry.tag, 'source_entry_sha256': digest(xml_identity(entry)),
                    'href': name, 'component_ref': entry.get('uri'), 'component': component,
                    'component_sha256': source.component_hashes[component],
                    'message': 'Exact NIWC ds:uri extension chain resolved; standard catalog equivalence not independently proved.',
                    'independent_static_proof': 'UNPROVED', 'scanner_runtime': 'NOT_RUN',
                }
        except ValueError as error:
            errors[name] = {'message': str(error), 'entries': [
                {'qname': entry.tag, 'uri': entry.get('uri')} for entries in choices.values() for entry in entries]}
    return bindings, errors, warnings


def all_exist_warning(source, component, test, obj, native_test):
    """Preserve source controls and collection context outside native authoring."""
    return {
        'code': 'test_all_exist_unproved', 'owner_decision': DECISION,
        'scope': 'Test existence only; field and record operators unchanged',
        'component': component, 'source_test': test.get('id'), 'source_object': obj.get('id'),
        'source_test_sha256': digest(xml_identity(test)), 'source_object_sha256': digest(xml_identity(obj)),
        'original_check_existence': 'all_exist', 'source_test_attributes': dict(test.attrib),
        'native_test': native_test, 'native_items_found': 'one_or_more',
        'object_variable_references': sorted({n.get('var_ref') for n in obj.iter() if n.get('var_ref')}),
        'object_has_set_or_filter': any(n.tag.endswith(('}set', '}filter')) for n in obj.iter()),
        'message': 'Draft Test all_exist lowering; complete actual-Items equivalence only, broader population semantics unproved.',
        'collection_obligations': ['no synthetic nonexistent Items', 'missing expected targets remain distinguishable',
            'material collection/Item error or unknown evidence is retained',
            'incomplete/not-collected populations cannot become an ordinary verified PASS from a positive Item'],
        'independent_static_proof': 'UNPROVED', 'scanner_runtime': 'NOT_RUN',
    }
