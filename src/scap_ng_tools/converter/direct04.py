"""Focused offline 0.4 converter using an explicit frozen flat schema snapshot.

The audited source engine is staged without semantic edits under _v04_runtime.
Strict --rule conversion and benchmark-wide automatic authoring admission are
qualified separately; legacy compile/verify/draft remain deliberately blocked.
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
        # Schema validator traversal can expose independent anyOf failures in
        # hash/set-derived order. Keep published blocker diagnostics stable
        # across converter subprocesses and deterministic ledger rebuilds.
        findings = sorted(findings)
        raise QualifiedConversionError('generated authoring failed flat JSON Schema: ' + '; '.join(findings[:8]))


def native_variable_datatype_required(snapshot):
    """Read the exact pinned 0.4 declaration grammar, never a hidden default.

    Historical schema snapshots require Variable datatype. The coordinated
    inferred-type candidate removes both the required entry and the property.
    A transitional half-migrated pack is rejected rather than guessed.
    """
    variable_schema = json.loads(
        (snapshot.schema_root / 'variable-expression.schema.json').read_text(encoding='utf-8'))
    declaration = variable_schema['$defs']['declaration']
    required = 'datatype' in declaration.get('required', [])
    allowed = 'datatype' in declaration.get('properties', {})
    if required != allowed:
        raise QualifiedConversionError('inconsistent pinned native Variable datatype grammar')
    return required


def convert_focused(*, schema_root, source, sha256_pin, rule_ids,
                    human_compact=True, native_recovery=False, include_applicability=False):
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
        source_model.native_recovery = native_recovery
        source_model.native_variable_datatype_required = native_variable_datatype_required(snapshot)
        documents, trace = engine.convert(source_model, list(rule_ids),
                                          human_compact=human_compact,
                                          native_recovery=native_recovery)
    finally:
        engine.load_mappings = previous
    if include_applicability:
        from .applicability import build_applicability
        documents, applicability_trace = build_applicability(
            source_model, documents, {'rules': [
                {'source_rule': binding['source_rule'], 'status': 'manual_only' if binding.get('source_selection_policy') is None else 'converted',
                 'artifacts': sorted(documents)} for binding in trace.get('rules', [])
            ]}, mappings, human_compact=human_compact, native_recovery=native_recovery)
        trace['applicability'] = applicability_trace
    validate_native_documents(snapshot, documents)
    return documents, trace


def inventory_benchmark(*, schema_root, source, sha256_pin):
    """Read every source Rule without admitting conversion or proving results."""
    snapshot = FrozenSchemaSnapshot(schema_root)
    if sha256(Path(source).read_bytes()).hexdigest() != sha256_pin:
        raise QualifiedConversionError('original source archive does not match supplied SHA-256')
    engine = load_runtime()
    from v04_direct_scap_source import SourceModel
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    previous = engine.load_mappings
    try:
        engine.load_mappings = lambda: mappings
        original = SourceModel(Path(source), sha256_pin,
                               inventory_broken_references=True)
        documents, trace, coverage = engine.convert_benchmark(
            original, inventory_only=True, mappings=mappings)
    finally:
        engine.load_mappings = previous
    if documents or coverage.get('mode') != 'inventory':
        raise QualifiedConversionError('inventory unexpectedly admitted native documents')
    return trace, coverage


def convert_benchmark(*, schema_root, source, sha256_pin, human_compact=True,
                      native_recovery=False, include_applicability=False, applicability_rule_ids=None):
    """Admit automated Rules through a pinned, strictly version-local semantic gate.

    Blocked Rules retain original inventory diagnostics. Admitted Rules are
    authoring validated only, never source-proved or scanner-qualified.
    """
    snapshot = FrozenSchemaSnapshot(schema_root)
    if sha256(Path(source).read_bytes()).hexdigest() != sha256_pin:
        raise QualifiedConversionError('original source archive does not match supplied SHA-256')
    engine = load_runtime()
    from v04_direct_scap_source import SourceModel
    from ._v04_semantic.validation import document_errors
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    original = SourceModel(Path(source), sha256_pin, inventory_broken_references=True)
    original.native_recovery = native_recovery
    original.native_variable_datatype_required = native_variable_datatype_required(snapshot)
    documents, trace, coverage = engine.convert_benchmark(
        original, mappings=mappings, human_compact=human_compact,
        validate_document=lambda kind, doc: document_errors(snapshot, kind, doc),
        native_recovery=native_recovery)
    if (coverage.get('mode') != 'automatic' or
            any(row['proof_level'] not in ('none', 'authoring_validated')
                for row in coverage['rules'])):
        raise QualifiedConversionError('unexpected promotion beyond unverified authoring')
    if include_applicability:
        from .applicability import build_applicability
        documents, applicability_trace = build_applicability(
            original, documents, coverage, mappings, human_compact=human_compact,
            native_recovery=native_recovery, rule_ids=applicability_rule_ids)
        trace['applicability'] = applicability_trace
        validate_native_documents(snapshot, documents)
    return documents, trace, coverage


def render_native_documents(snapshot, documents):
    """Validate the actual JSON/YAML payloads before any native file is written."""
    import yaml
    load_runtime()
    from v04_direct_yaml import authoring_yaml
    class UniqueKeys(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in result:
                    raise QualifiedConversionError('duplicate key in serialized native YAML')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    validate_native_documents(snapshot, documents)
    rendered = {}
    for name, document in documents.items():
        json_text = json.dumps(document, indent=2, allow_nan=False) + '\n'
        yaml_text = authoring_yaml(document)
        try:
            decoded_json, decoded_yaml = json.loads(json_text), yaml.load(yaml_text, Loader=UniqueKeys)
        except (ValueError, yaml.YAMLError) as error:
            raise QualifiedConversionError('invalid serialized native output: ' + name) from error
        if decoded_json != document or decoded_yaml != document:
            raise QualifiedConversionError('serialized native output differs from validated document: ' + name)
        validate_native_documents(snapshot, {name: decoded_json})
        validate_native_documents(snapshot, {name: decoded_yaml})
        rendered[name] = (json_text, yaml_text)
    return rendered


def conversion_identity(snapshot):
    """Record actual source bytes/revisions without inferring release identity."""
    import subprocess
    
    package = Path(__file__).resolve().parents[1]
    root = package.parent.parent
    source_checkout = package.parent.name == 'src' and (root / 'pyproject.toml').is_file()

    def revision(path):
        result = subprocess.run(['git', '-C', str(path), 'rev-parse', 'HEAD'],
                                capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None

    checksum = sha256()
    for path in sorted(package.rglob('*')):
        if path.is_file() and path.suffix in ('.py', '.json'):
            checksum.update(path.relative_to(package.parent).as_posix().encode() + b'\0' + path.read_bytes())
    dirty = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--', 'src', 'pyproject.toml'],
                           capture_output=True, text=True) if source_checkout else None
    return {'converter_commit': revision(root) if source_checkout else None,
            'converter_source_sha256': checksum.hexdigest(),
            'converter_worktree_dirty': bool(dirty.stdout) if dirty and dirty.returncode == 0 else None,
            'schema_commit': revision(snapshot.schema_root),
            'schema_family_sha256': snapshot.manifest()['aggregate_sha256']}


def convert_oval_definition(**arguments):
    """Convert a standalone OVAL Definition through the production visitor.

    No parser, Test whitelist, secondary evaluator or datatype/function
    converter is permitted here. The standalone source adapter validates the
    original XML, then uses the same AssessmentConverter as benchmark Rules.
    """
    from .oval_platform import convert_definition
    return convert_definition(**arguments)


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
                        help='original source ZIP or standalone OVAL XML')
    parser.add_argument('--source', dest='source_option', type=Path,
                        help='equivalent explicit source path')
    parser.add_argument('--sha256', required=True, help='exact SHA-256 of original source ZIP')
    parser.add_argument('--rule', action='append', help='selected source Rule ID; repeatable')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--human-compact', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--oval-definition', help='original OVAL Definition ID in standalone source XML')
    parser.add_argument('--source-commit', help='pinned original source Git commit')
    parser.add_argument('--source-path', help='original XML repository-relative source path')
    parser.add_argument('--recover-native', action='store_true', help='opt into owner-review native recovery candidates')
    parser.add_argument('--include-applicability', action='store_true', help='lower source platform applicability into shared native Assessments')
    for option in ('--verify', '--compile', '--all-rules', '--inventory-only', '--draft'):
        parser.add_argument(option, action='store_true')
    arguments = parser.parse_args()
    if (arguments.source is None) == (arguments.source_option is None):
        parser.error('supply exactly one source ZIP (positional or --source)')
    selected_source = arguments.source or arguments.source_option
    if any((arguments.verify, arguments.compile, arguments.draft)):
        parser.error('compile/proof and draft modes are not migrated; '
                     'these modes require separate owner-qualified ports')
    if arguments.inventory_only and arguments.rule:
        parser.error('--inventory-only must not be combined with --rule')
    if sum(bool(x) for x in (arguments.inventory_only, arguments.all_rules, arguments.rule, arguments.oval_definition)) != 1:
        parser.error('select exactly one of --inventory-only, --all-rules, --rule or --oval-definition')
    if arguments.oval_definition and not (arguments.source_commit and arguments.source_path):
        parser.error('standalone OVAL requires --source-commit and --source-path')
    if not arguments.oval_definition and (arguments.source_commit or arguments.source_path):
        parser.error('--source-commit/--source-path require --oval-definition')
    if arguments.oval_definition and (arguments.all_rules or arguments.include_applicability or arguments.recover_native):
        parser.error('standalone OVAL is not benchmark or native-recovery mode')
    if arguments.output.exists():
        parser.error('output path already exists; refusing overwrite')
    try:
        if arguments.inventory_only:
            trace, coverage = inventory_benchmark(
                schema_root=arguments.schema_root, source=selected_source,
                sha256_pin=arguments.sha256)
            from v04_direct_inventory import coverage_markdown
            arguments.output.mkdir(parents=True, exist_ok=False)
            (arguments.output / 'coverage.json').write_text(
                json.dumps(coverage, indent=2) + '\n', encoding='utf-8')
            (arguments.output / 'coverage.md').write_text(
                coverage_markdown(coverage), encoding='utf-8')
            (arguments.output / 'source-trace.json').write_text(
                json.dumps(trace, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'source_rules': coverage['summary']['source_rules'],
                              'status': 'INVENTORIED_UNVERIFIED', 'native_documents': 0}))
            return
        if arguments.oval_definition:
            documents, trace = convert_oval_definition(
                schema_root=arguments.schema_root, source=selected_source,
                sha256_pin=arguments.sha256, definition_id=arguments.oval_definition,
                source_commit=arguments.source_commit, source_path=arguments.source_path)
        elif arguments.all_rules:
            documents, trace, coverage = convert_benchmark(
                schema_root=arguments.schema_root, source=selected_source,
                sha256_pin=arguments.sha256, human_compact=arguments.human_compact,
                native_recovery=arguments.recover_native, include_applicability=arguments.include_applicability)
        else:
            documents, trace = convert_focused(
                schema_root=arguments.schema_root, source=selected_source,
                sha256_pin=arguments.sha256, rule_ids=arguments.rule,
                human_compact=arguments.human_compact, native_recovery=arguments.recover_native,
                include_applicability=arguments.include_applicability)
        snapshot = FrozenSchemaSnapshot(arguments.schema_root)
        rendered = render_native_documents(snapshot, documents)
        targets = {name: safe_relative_filename(arguments.output, name)
                   for name in documents}
        arguments.output.mkdir(parents=True, exist_ok=False)
        for name, (json_text, yaml_text) in rendered.items():
            target = targets[name]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json_text, encoding='utf-8')
            target.with_suffix('.yaml').write_text(yaml_text, encoding='utf-8')
        (arguments.output / 'source-trace.json').write_text(
            json.dumps(trace, indent=2) + '\n', encoding='utf-8')
        if arguments.all_rules:
            from v04_direct_inventory import coverage_markdown
            (arguments.output / 'coverage.json').write_text(
                json.dumps(coverage, indent=2) + '\n', encoding='utf-8')
            (arguments.output / 'coverage.md').write_text(
                coverage_markdown(coverage), encoding='utf-8')
        (arguments.output / 'conversion-scope.json').write_text(json.dumps({
            'schema_version': '0.4.0',
            'conversion_status': 'CONVERTED_UNVERIFIED',
            'structural_validation': 'Draft 2020-12 local pinned schema',
            'independent_semantic_proof': False,
            'scanner_execution': False,
            'compile_and_verify_modes': 'not_migrated',
            'source_sha256': arguments.sha256,
            'rule_ids': arguments.rule,
            'oval_definition': arguments.oval_definition,
            'automatic_benchmark_subset': bool(arguments.all_rules),
            'semantic_validation': ('frozen 0.4 capability contract and semantic gates'
                                    if arguments.all_rules or arguments.oval_definition else 'not independently qualified'),
        }, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
    print(json.dumps({'documents': len(documents), 'source_sha256': arguments.sha256,
                      'source_rules': coverage['summary']['source_rules'] if arguments.all_rules else None,
                      'status': 'CONVERTED_UNVERIFIED', 'schema_validated': True}))


if __name__ == '__main__':
    main()
