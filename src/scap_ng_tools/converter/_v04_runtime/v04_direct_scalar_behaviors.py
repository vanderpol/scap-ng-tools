"""Route scalar acquisition behaviors through reviewed metadata and original XSD.

Defaults come from the source declaration, never from prose or a guessed false.
Traversal, command errors and records keep their existing specialized handlers.
"""
from functools import lru_cache
from pathlib import Path
import xml.etree.ElementTree as ET

from v04_direct_scap_source import attributes, ensure

ROOT = Path(__file__).resolve().parents[1]
XS = '{http://www.w3.org/2001/XMLSchema}'


def behavior_routes(mapping):
    migration = mapping.get('migration_crosswalk', {})
    routes = {name: target.removeprefix('object.') for name, target in migration.get('behaviors', {}).items()
              if target.startswith('object.') and target.removeprefix('object.') in mapping['native'].get('collection_parameters', {})}
    for name, target in migration.get('object', {}).items():
        if name.startswith('behaviors.') and target.startswith('object.'):
            field = name.removeprefix('behaviors.')
            ensure(field not in routes or routes[field] == target.removeprefix('object.'), 'inconsistent scalar behavior routes')
            routes[field] = target.removeprefix('object.')
    return routes


@lru_cache(maxsize=None)
def original_attributes(schema_path, object_name):
    schema = ET.parse(ROOT / schema_path).getroot()
    obj = schema.find(XS + 'element[@name="' + object_name + '"]')
    declarations = obj.findall('.//' + XS + 'element[@name="behaviors"]')
    ensure(len(declarations) == 1, 'one original behavior declaration required')
    name = declarations[0].get('type', '').split(':')[-1]
    declaration = schema.find(XS + 'complexType[@name="' + name + '"]')
    ensure(declaration is not None, 'original behavior type unavailable')
    def attributes_for(node, active):
        name = node.get('name')
        ensure(name not in active, 'cyclic original behavior inheritance')
        result = {}
        extension = node.find(XS + 'complexContent/' + XS + 'extension')
        if extension is not None:
            base = schema.find(XS + 'complexType[@name="' + extension.get('base').split(':')[-1] + '"]')
            ensure(base is not None, 'unavailable original behavior base')
            result.update(attributes_for(base, active | {name}))
        result.update({a.get('name'): dict(a.attrib) for a in node.findall('.//' + XS + 'attribute')})
        return result
    return attributes_for(declaration, set())


def split_behaviors(element, scalar_names, traversal_names):
    """Validate the full source element once, then route disjoint attributes.

    Neither handler may silently drop attributes owned by the other. Source
    nodes stay immutable; required/default attributes are still read from XSD.
    """
    ensure(not set(scalar_names) & set(traversal_names), 'overlapping acquisition behavior routes')
    if element is None:
        return None, None
    attributes(element, set(scalar_names) | set(traversal_names))
    ensure(not len(element) and not (element.text or '').strip(), 'acquisition behaviors must have no content')
    return tuple(ET.Element(element.tag, {k: v for k, v in element.attrib.items() if k in names})
                 for names in (scalar_names, traversal_names))


def scalar_behaviors(element, mapping):
    routes = behavior_routes(mapping)
    if element is not None:
        attributes(element, routes)
        ensure(not len(element) and not (element.text or '').strip(), 'scalar behaviors must have no content')
    declarations = original_attributes(mapping['source']['definitions_schema'], mapping['source']['object'])
    result = {}
    for source, target in routes.items():
        ensure(source in declarations, 'behavior absent from original XSD: ' + source)
        declaration = declarations[source]
        raw = element.get(source) if element is not None else None
        if raw is None:
            ensure(declaration.get('use') != 'required', 'required original behavior missing: ' + source)
            raw = declaration.get('default', declaration.get('fixed'))
        ensure(raw is not None, 'original behavior has no materializable default: ' + source)
        spec = mapping['native']['collection_parameters'][target]
        if spec['type'] == 'boolean':
            ensure(declaration.get('type', '').split(':')[-1] == 'boolean' and raw in ('true', 'false', '1', '0'),
                   'invalid original Boolean behavior: ' + source)
            value = raw in ('true', '1')
        else:
            ensure(spec['type'] == 'string', 'unsupported scalar behavior type')
            value = raw
        ensure('enum' not in spec or value in spec['enum'], 'unsupported original behavior value: ' + source)
        result[target] = value
    return result
