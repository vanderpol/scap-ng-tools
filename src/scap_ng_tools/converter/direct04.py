"""Focused offline 0.4 converter using an explicit frozen flat schema snapshot.

The audited source engine is staged without semantic edits under _v04_runtime.
Only strict --rule conversion is qualified here; legacy compile/verify and
whole-benchmark modes are not silently weakened or claimed to have moved.
"""

import argparse
from hashlib import sha256
import importlib
import json
from pathlib import Path, PurePosixPath
import sys

from scap_ng_tools.contracts import FrozenSchemaSnapshot


class QualifiedConversionError(ValueError):
    """Requested conversion is outside the explicitly qualified tool scope."""


def load_runtime():
    """Load immutable-source modules in their isolated package-owned directory.

    This transition allows historical absolute imports to remain byte-perfect
    without taking a dependency on the original research repository. Reject an
    already-loaded same-named module from an unrelated source checkout.
    """
    directory = Path(__file__).resolve().parent / '_v04_runtime'
    for name, module in list(sys.modules.items()):
        if name.startswith('v04_') and getattr(module, '__file__', None):
            if Path(module.__file__).resolve().parent != directory:
                raise QualifiedConversionError(f'conflicting external converter module: {name}')
    path = str(directory)
    if path not in sys.path:
        sys.path.insert(0, path)
    engine = importlib.import_module('v04_direct_converter')
    if Path(engine.__file__).resolve().parent != directory:
        raise QualifiedConversionError('loaded converter from an unexpected source path')
    return engine


def validate_native_documents(snapshot, documents):
    """Draft 2020-12 structural validation; not independent semantic proof."""
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError as error:
        raise QualifiedConversionError('install the converter dependencies (jsonschema and referencing)') from error

    resources = {}
    root = snapshot.schema_root
    for path in sorted((*root.glob('*.json'),
                        *(root / 'capability-mappings').rglob('*.json'))):
        document = json.loads(path.read_bytes())
        if '$schema' not in document:
            continue
        resource = Resource.from_contents(document)
        resources['https://scap-ng.dev/schema/v0.4.0/' +
                  path.relative_to(root).as_posix()] = resource
        if '$id' in document:
            resources[document['$id']] = resource
    registry = Registry().with_resources(resources.items())
    validators = {}
    for name in {kind + '.schema.json' for document in documents.values() for kind in document}:
        schema = json.loads((root / name).read_bytes())
        validators[name] = Draft202012Validator(schema, registry=registry)
    findings = []
    for filename, document in documents.items():
        for kind in document:
            findings.extend(f'{filename}: {error.message}' for error in
                            validators[kind + '.schema.json'].iter_errors(document))
    if findings:
        raise QualifiedConversionError('generated authoring failed flat JSON Schema: ' + '; '.join(findings[:8]))


def convert_focused(*, schema_root, source, sha256_pin, rule_ids,
                    human_compact=True):
    """Return a verified-structure native document set and original source trace.

    Output provenance may truthfully say schema-validated and source-traced, but
    never independently verified, compiled, or runtime-scanner qualified.
    """
    snapshot = FrozenSchemaSnapshot(schema_root)
    if not rule_ids or len(rule_ids) != len(set(rule_ids)):
        raise QualifiedConversionError('one or more distinct source Rule IDs required')
    if sha256(Path(source).read_bytes()).hexdigest() != sha256_pin:
        raise QualifiedConversionError('original source archive does not match supplied SHA-256')
    engine = load_runtime()
    from v04_direct_scap_source import SourceModel
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    previous = engine.load_mappings
    try:
        engine.load_mappings = lambda: mappings
        source_model = SourceModel(Path(source), sha256_pin)
        documents, trace = engine.convert(source_model, list(rule_ids),
                                          human_compact=human_compact)
    finally:
        engine.load_mappings = previous
    validate_native_documents(snapshot, documents)
    return documents, trace


def safe_relative_filename(root, relative):
    filename = PurePosixPath(relative)
    if not relative or filename.is_absolute() or '..' in filename.parts or '\\' in relative:
        raise QualifiedConversionError(f'unsafe converter output path: {relative}')
    target = root.joinpath(*filename.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise QualifiedConversionError(f'converter path escapes output directory: {relative}')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root', type=Path, required=True,
                        help='exact offline SCAP-NG 0.4 checkout or flat schema/ directory')
    parser.add_argument('source', nargs='?', type=Path,
                        help='original CLI positional source ZIP')
    parser.add_argument('--source', dest='source_option', type=Path,
                        help='equivalent explicit source ZIP path')
    parser.add_argument('--sha256', required=True, help='exact SHA-256 of original source ZIP')
    parser.add_argument('--rule', action='append', required=True, help='selected source Rule ID; repeatable')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--human-compact', action=argparse.BooleanOptionalAction, default=True)
    for option in ('--verify', '--compile', '--all-rules', '--inventory-only', '--draft'):
        parser.add_argument(option, action='store_true')
    arguments = parser.parse_args()
    if (arguments.source is None) == (arguments.source_option is None):
        parser.error('supply exactly one source ZIP (positional or --source)')
    selected_source = arguments.source or arguments.source_option
    if any((arguments.verify, arguments.compile, arguments.all_rules,
            arguments.inventory_only, arguments.draft)):
        parser.error('only strict focused conversion is migrated; compile/proof, draft and '
                     'benchmark modes require separate owner-qualified ports')
    if arguments.output.exists():
        parser.error('output path already exists; refusing overwrite')
    try:
        documents, trace = convert_focused(
            schema_root=arguments.schema_root, source=selected_source,
            sha256_pin=arguments.sha256, rule_ids=arguments.rule,
            human_compact=arguments.human_compact)
        from v04_direct_yaml import authoring_yaml
        targets = {name: safe_relative_filename(arguments.output, name)
                   for name in documents}
        arguments.output.mkdir(parents=True, exist_ok=False)
        for name, document in documents.items():
            target = targets[name]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
            target.with_suffix('.yaml').write_text(authoring_yaml(document), encoding='utf-8')
        (arguments.output / 'source-trace.json').write_text(
            json.dumps(trace, indent=2) + '\n', encoding='utf-8')
        (arguments.output / 'conversion-scope.json').write_text(json.dumps({
            'schema_version': '0.4.0',
            'conversion_status': 'CONVERTED_UNVERIFIED',
            'structural_validation': 'Draft 2020-12 local pinned schema',
            'independent_semantic_proof': False,
            'scanner_execution': False,
            'compile_and_verify_modes': 'not_migrated',
            'source_sha256': arguments.sha256,
            'rule_ids': arguments.rule,
        }, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
    print(json.dumps({'documents': len(documents), 'source_sha256': arguments.sha256,
                      'status': 'CONVERTED_UNVERIFIED', 'schema_validated': True}))


if __name__ == '__main__':
    main()
