"""Standalone pinned OVAL Definitions through the production 0.4 visitor.

This lane preserves named constants and alias dependencies. No fabricated SCAP
datastream, collector Object, function interpreter or expected result is used.
"""
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from .direct04 import (QualifiedConversionError, conversion_identity, load_runtime,
                       validate_native_documents)

OVAL = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
INDEPENDENT = OVAL + '#independent'


class OvalSource:
    """File-local index implementing the production visitor's source protocol."""
    def __init__(self, raw, component):
        from v04_direct_scap_source import SourceModel, ensure
        ensure(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'OVAL XML declarations forbidden')
        root = ET.fromstring(raw)
        ensure(root.tag == '{' + OVAL + '}oval_definitions', 'expected original OVAL Definitions XML')
        ensure(set(root.attrib) <= {'{http://www.w3.org/2001/XMLSchema-instance}schemaLocation'},
               'unsupported OVAL root attributes')
        self.components, self.nodes = {component: root}, {component: {}}
        allowed = {
            'definitions': {'{' + OVAL + '}definition'},
            'tests': {'{' + INDEPENDENT + '}variable_test'},
            'objects': {'{' + INDEPENDENT + '}variable_object'},
            'states': {'{' + INDEPENDENT + '}variable_state'},
            'variables': {'{' + OVAL + '}' + name for name in
                          ('constant_variable', 'local_variable', 'external_variable')},
        }
        generators = root.findall('{' + OVAL + '}generator')
        ensure(len(generators) == 1 and generators[0].findtext(
            '{http://oval.mitre.org/XMLSchema/oval-common-5}schema_version') == '5.12.3',
            'standalone source must declare OVAL 5.12.3')
        seen = set()
        for group in root:
            if group.tag == '{' + OVAL + '}generator':
                continue
            ensure(group.tag.startswith('{' + OVAL + '}') and group.tag.split('}')[-1] in allowed,
                   'unsupported OVAL document section')
            ensure(group.tag not in seen and not group.attrib, 'duplicate/unsupported OVAL section')
            seen.add(group.tag)
            for node in group:
                ensure(node.tag in allowed[group.tag.split('}')[-1]], 'unsupported OVAL declaration kind/namespace')
                ident = node.get('id')
                ensure(ident and ident not in self.nodes[component], 'duplicate/missing original OVAL ID')
                self.nodes[component][ident] = node
        self.node = SourceModel.node.__get__(self)
        self.object_uses = SourceModel.object_uses.__get__(self)


def convert_definition(*, schema_root, source, sha256_pin, definition_id,
                       source_commit, source_path):
    """Return a whole Definition and validated native/provenance documents.

    Commit/path are declared provenance; the exact XML SHA and frozen schema
    digest are enforced. No source signature or execution equivalence is claimed.
    """
    snapshot = FrozenSchemaSnapshot(schema_root)
    raw = Path(source).read_bytes()
    if sha256(raw).hexdigest() != sha256_pin:
        raise QualifiedConversionError('original OVAL SHA-256 mismatch')
    if len(source_commit) != 40 or any(c not in '0123456789abcdef' for c in source_commit):
        raise QualifiedConversionError('exact source commit required')
    engine = load_runtime()
    from v04_direct_scap_source import ensure, local_name, native_identifier
    original = OvalSource(raw, source_path)
    nodes = original.nodes[source_path]
    definition = original.node(source_path, definition_id, 'definition')
    variables = [node for node in nodes.values() if local_name(node).endswith('_variable')]
    for node in variables:
        ensure(node.get('datatype') in ('int', 'string'), 'standalone Variable datatype held: ' + str(node.get('datatype')))
        if local_name(node) == 'constant_variable':
            continue
        ensure(local_name(node) == 'local_variable' and len(node) == 1 and
               node[0].tag == '{' + OVAL + '}variable_component',
               'standalone functions, Object components and external Variables remain held')
        target = original.node(source_path, node[0].get('var_ref'), 'variable')
        ensure(target.get('datatype') == node.get('datatype'), 'standalone alias datatype conversion held')
    for test in nodes.values():
        if not local_name(test).endswith('_test'):
            continue
        ensure(test.tag == '{' + INDEPENDENT + '}variable_test', 'standalone lane requires Variable Tests')
        obj_ref = test.find('{' + INDEPENDENT + '}object')
        ensure(obj_ref is not None, 'Variable Test Object reference required')
        obj = original.node(source_path, obj_ref.get('object_ref'), 'object')
        selected = obj.find('{' + INDEPENDENT + '}var_ref')
        ensure(selected is not None, 'standalone Variable Object Sets/Filters held')
        datatype = original.node(source_path, selected.text, 'variable').get('datatype')
        for ref in test.findall('{' + INDEPENDENT + '}state'):
            state = original.node(source_path, ref.get('state_ref'), 'state')
            for value in state.findall('{' + INDEPENDENT + '}value'):
                ensure(value.get('datatype', 'string') == datatype,
                       'standalone observed/State datatype conversion held')
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    visitor = engine.AssessmentConverter(original, source_path, mappings, human_compact=False,
                                        preserve_variable_references=True)
    expression = visitor.reference(definition_id, 'definition')
    ensure(all(test['capability'] == 'variable.value' and 'object' not in test
               for test in visitor.tests.values()), 'standalone lane requires direct Variable Tests')
    # Preserve every original Variable declaration, including unused aliases.
    for node in variables:
        visitor.named_variable(node.get('id'))
    assessment = {
        'id': native_identifier(definition, 'assessment', definition_id),
        'version': int(definition.get('version')),
        'assessment_title': definition.findtext('{' + OVAL + '}metadata/{' + OVAL + '}title'),
        'mode': 'automated', 'class': definition.get('class'),
        'specification': {'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.0'},
        'variables': visitor.variables, 'tests': visitor.tests, 'evaluate': expression,
    }
    documents = {'assessment.json': {'assessment': assessment}}
    validate_native_documents(snapshot, documents)
    # Existing semantic checks cover type compatibility, references and guards.
    from ._v04_semantic.validation import document_errors
    errors = list(document_errors(snapshot, 'assessment', documents['assessment.json']))
    if errors:
        raise QualifiedConversionError('standalone semantic validation failed: ' + '; '.join(e.message for e in errors[:4]))
    native_tests = {source_id: name for (kind, name), source_id in visitor.native_names.items() if kind == 'test'}
    def references(node):
        result = [{'attribute': key, 'id': value} for descendant in node.iter()
                  for key, value in descendant.attrib.items() if key.endswith('_ref')]
        if local_name(node) == 'variable_object':
            result.extend({'attribute': 'var_ref_text', 'id': child.text}
                          for child in node if child.tag == '{' + INDEPENDENT + '}var_ref')
        return result

    trace = {
        'source_commit': source_commit, 'source_path': source_path, 'source_sha256': sha256_pin,
        'definition_id': definition_id,
        'source_nodes': {ident: {**row, 'references': references(nodes[ident])}
            for ident, row in sorted(visitor.used.items())},
        'native_identities': [{'kind': kind, 'native_id': name, 'source_id': source_id}
                              for (kind, name), source_id in sorted(visitor.native_names.items())],
        'test_bindings': [{
            'source_test': ident, 'native_test': name,
            'source_object': nodes[ident].find('{' + INDEPENDENT + '}object').get('object_ref'),
            'source_states': [child.get('state_ref') for child in nodes[ident]
                              if child.tag == '{' + INDEPENDENT + '}state'],
        } for ident, name in sorted(native_tests.items())],
        'qualification': 'CONVERTED_UNVERIFIED', 'schema_validated': True,
        'semantic_validated': True, 'scanner_execution': False,
        **conversion_identity(snapshot),
    }
    import os
    import subprocess
    root = subprocess.run(['git', '-C', str(Path(source).resolve().parent), 'rev-parse', '--show-toplevel'],
                          capture_output=True, text=True)
    trace['source_commit_blob_verified'] = False
    if root.returncode == 0:
        blob = subprocess.run(['git', '-C', root.stdout.strip(), 'show', source_commit + ':' + source_path],
                              capture_output=True, env=dict(os.environ, GIT_NO_LAZY_FETCH='1'))
        ensure(blob.returncode == 0 and blob.stdout == raw, 'source commit/path does not match original XML bytes')
        trace['source_commit_blob_verified'] = True
    return documents, trace


