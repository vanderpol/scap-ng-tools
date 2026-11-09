"""One publication boundary for current native output and historical research.

Current admission reproduces the whole candidate with an isolated, hash-pinned
production facade. A manifest alone is never proof of how bytes were produced.
Historical sealing preserves bytes but cannot issue current qualification.
"""
import argparse
from hashlib import sha256
import importlib.metadata
import io
import glob
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from urllib.parse import urlsplit

POLICY = Path(__file__).with_name('policy.json')
MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 100000


class AdmissionError(ValueError):
    pass


def ensure(condition, message):
    if not condition:
        raise AdmissionError(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        ensure(key not in result, 'duplicate mapping key: ' + str(key))
        result[key] = value
    return result


def json_read(raw):
    def invalid(value):
        raise AdmissionError('non-finite JSON value: ' + value)
    return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=invalid)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(raw):
    return sha256(raw).hexdigest()


def git(root, *arguments):
    proc = subprocess.run(['git', '-C', str(root), *arguments], capture_output=True,
                          env=dict(os.environ, GIT_NO_LAZY_FETCH='1'), timeout=60)
    ensure(proc.returncode == 0, 'Git source unavailable: ' + ' '.join(arguments[:2]))
    return proc.stdout


def clean_revision(root, allowed=None):
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    ensure(len(commit) == 40 and (allowed is None or commit in allowed), 'unapproved source/schema revision')
    ensure(not git(root, 'status', '--porcelain', '--untracked-files=all'), 'dirty source/schema checkout')
    return commit


def safe_name(name):
    path = PurePosixPath(name)
    ensure(name and not path.is_absolute() and '..' not in path.parts and '\\' not in name,
           'unsafe publication member')
    ensure(path.as_posix() == name and name not in ('.', '..'), 'noncanonical publication member')
    return name


def read_tree(root):
    root = Path(root)
    ensure(root.is_dir() and not root.is_symlink(), 'publication directory required')
    result, total = {}, 0
    for path in sorted(root.rglob('*')):
        ensure(not path.is_symlink(), 'symlink in publication')
        if path.is_dir():
            continue
        ensure(path.is_file(), 'nonregular publication member')
        raw = path.read_bytes()
        total += len(raw)
        ensure(total <= MAX_BYTES and len(result) < MAX_FILES, 'publication budget exceeded')
        result[safe_name(path.relative_to(root).as_posix())] = raw
    return result


def schema_identity(root, policy):
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    commit = clean_revision(root, policy['schema']['commits'])
    snapshot = FrozenSchemaSnapshot(root)
    return snapshot, {'commit': commit, 'version': '0.4.0',
                      'family_sha256': policy['schema']['family_sha256']}


def producer_snapshot(root, target, policy):
    expected = policy['producer']
    commit = clean_revision(root, [expected['commit']])
    paths = git(root, 'ls-tree', '-r', '--name-only', commit, 'src/scap_ng_tools', 'pyproject.toml').decode().splitlines()
    files = {}
    for name in paths:
        if not (name.endswith(('.py', '.json')) or name == 'pyproject.toml'):
            continue
        raw = git(root, 'show', commit + ':' + name)
        # Compare the actual checkout as well as Git objects. No cached bytecode
        # is copied into the isolated source snapshot.
        ensure(not (Path(root) / name).is_symlink() and (Path(root) / name).read_bytes() == raw,
               'producer checkout bytes differ from pinned Git source')
        files[name] = digest(raw)
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    tree_digest = digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())
    ensure(tree_digest == expected['source_tree_sha256'], 'producer source fingerprint mismatch')
    project = tomllib.loads((target / 'pyproject.toml').read_text())['project']
    ensure(project['name'] == expected['distribution'] and project['version'] == expected['distribution_version'],
           'converter distribution metadata mismatch')
    ensure(project['scripts']['scapng-convert-v04'] == 'scap_ng_tools.converter.direct04:main',
           'unapproved converter entrypoint')
    return dict(expected, dirty=False, execution='isolated-pinned-source-distribution',
                interpreter_version=sys.version.split()[0], interpreter_sha256=digest(Path(sys.executable).read_bytes()))


def source_identity(root, request):
    ensure(set(request) == {'mode', 'source_commit', 'source_path', 'source_sha256', 'selection'},
           'missing/unknown conversion request provenance')
    ensure(request['mode'] in ('focused', 'benchmark', 'oval-definition'),
           'unsupported publication mode; no qualified full-65 reproduction')
    path = safe_name(request['source_path'])
    commit = request['source_commit']
    ensure(isinstance(commit, str) and len(commit) == 40 and all(c in '0123456789abcdef' for c in commit),
           'exact original source commit required')
    raw = git(root, 'show', commit + ':' + path)
    actual = Path(root) / path
    ensure(not actual.is_symlink() and actual.is_file() and actual.read_bytes() == raw,
           'original input differs from immutable source blob')
    ensure(digest(raw) == request['source_sha256'], 'original source digest mismatch')
    selection = request['selection']
    if request['mode'] == 'focused':
        ensure(isinstance(selection, list) and selection and all(isinstance(s, str) for s in selection),
               'explicit source Rule selection required')
    elif request['mode'] == 'benchmark':
        ensure(selection == 'automatic_subset', 'full coverage claim unsupported; only automated subset is admitted')
    else:
        ensure(isinstance(selection, str) and selection.startswith('oval:'), 'original OVAL Definition ID required')
    repositories = json_read(POLICY.read_bytes())['source_repositories']
    ensure(commit in repositories, 'original source revision/repository is not admitted')
    observed = subprocess.run(['git', '-C', str(root), 'config', '--get', 'remote.origin.url'], capture_output=True, text=True)
    remote = observed.stdout.strip()
    if remote.startswith('git@github.com:'):
        remote = 'https://github.com/' + remote[len('git@github.com:'):]
    repository = repositories[commit]
    if remote:
        url = urlsplit(remote)
        ensure(url.scheme == 'https' and url.hostname and not url.username and not url.password
               and not url.query and not url.fragment, 'auditable HTTPS original repository URI required')
        ensure('https://' + url.hostname + url.path.removesuffix('.git') == repository, 'original repository URI mismatch')
    return actual, {'repository': repository, 'commit': commit, 'path': path,
                    'sha256': digest(raw), 'blob_verified': True, 'origin_observed': bool(remote),
                    'repository_binding': 'approved immutable source revision catalog; not publisher authentication'}


def reproduce(*, producer_root, schema_root, source_root, request):
    policy = json_read(POLICY.read_bytes())
    snapshot, schema = schema_identity(schema_root, policy)
    source, original = source_identity(source_root, request)
    with tempfile.TemporaryDirectory(prefix='scapng-current-producer-') as directory:
        stage = Path(directory)
        producer = producer_snapshot(producer_root, stage / 'producer', policy)
        output = stage / 'converted'
        argv = ['--schema-root', str(Path(schema_root).resolve()), '--source', str(source.resolve()),
                '--sha256', original['sha256'], '--output', str(output)]
        if request['mode'] == 'focused':
            for rule in request['selection']:
                argv += ['--rule', rule]
        elif request['mode'] == 'benchmark':
            argv += ['--all-rules']
        else:
            argv += ['--oval-definition', request['selection'], '--source-commit', original['commit'],
                     '--source-path', original['path']]
        bootstrap = ('import sys,runpy;sys.path.insert(0,sys.argv.pop(1));'
                     'runpy.run_module("scap_ng_tools.converter.direct04",run_name="__main__")')
        command = [sys.executable, '-I', '-B', '-c', bootstrap, str(stage / 'producer/src'), *argv]
        proc = subprocess.run(command, capture_output=True, timeout=600, cwd=stage)
        ensure(proc.returncode == 0, 'approved converter rejected original source: ' + proc.stderr.decode()[-2000:])
        files = read_tree(output)
        validate_payloads(snapshot, files)
        # Verify pinned inputs after execution as well; no arbitrary wrapper or
        # executable path is accepted from a candidate manifest.
        clean_revision(producer_root, [policy['producer']['commit']])
        clean_revision(schema_root, policy['schema']['commits'])
        source_identity(source_root, request)
    return files, producer, schema, original


def validate_payloads(snapshot, files):
    import yaml
    from scap_ng_tools.converter.direct04 import validate_native_documents

    class UniqueYaml(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            return unique_pairs((self.construct_object(k, deep=deep), self.construct_object(v, deep=deep))
                                for k, v in node.value)

    native = 0
    for name, raw in files.items():
        if name.endswith('.yaml'):
            pair = name[:-5] + '.json'
            ensure(pair in files, 'native YAML lacks JSON counterpart')
            document = json_read(files[pair])
            ensure(yaml.load(raw, Loader=UniqueYaml) == document, 'final JSON/YAML mismatch')
            validate_native_documents(snapshot, {pair: document})
            native += 1
        elif name.endswith('.json'):
            document = json_read(raw)
            if isinstance(document, dict) and set(document) & {'assessment', 'benchmark', 'rule', 'applicability'}:
                ensure(name[:-5] + '.yaml' in files, 'native JSON lacks YAML counterpart')
    ensure(native > 0, 'no final native documents')


def prepare(*, output, **inputs):
    output = Path(output)
    ensure(not output.exists(), 'refusing to overwrite publication candidate')
    files, producer, schema, source = reproduce(**inputs)
    manifest = {'format': 'scap-ng-current-native-publication/1', 'producer': producer,
                'schema': schema, 'source': source, 'request': inputs['request'],
                'qualification': {'tier': 'authoring_validated', 'scope': inputs['request']['mode'],
                                  'converted_status': 'CONVERTED_UNVERIFIED', 'schema_validated': True,
                                  'final_serializations_validated': True, 'source_proved': False,
                                  'ri_executed': False, 'scanner_equivalent': False, 'full_65_complete': False},
                'files': {n: {'sha256': digest(b), 'bytes': len(b)} for n, b in sorted(files.items())}}
    output.mkdir(parents=True)
    for name, raw in files.items():
        destination = output / 'payload' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    raw = canonical(manifest)
    (output / 'publication-manifest.json').write_bytes(raw)
    (output / 'manifest.sha256').write_text(digest(raw) + '\n')
    return manifest


def admit(*, candidate, output, producer_root, schema_root, source_root):
    candidate, output = Path(candidate), Path(output)
    ensure(not output.exists(), 'refusing to overwrite admitted publication')
    all_files = read_tree(candidate)
    ensure({'publication-manifest.json', 'manifest.sha256'} <= set(all_files), 'publication provenance missing')
    raw = all_files.pop('publication-manifest.json')
    ensure(all_files.pop('manifest.sha256').decode().strip() == digest(raw), 'manifest digest mismatch')
    manifest = json_read(raw)
    ensure(set(manifest) == {'format', 'producer', 'schema', 'source', 'request', 'qualification', 'files'},
           'publication provenance missing/unknown')
    ensure(manifest['format'] == 'scap-ng-current-native-publication/1', 'historical publication is not current native')
    policy = json_read(POLICY.read_bytes())
    for key, value in policy['producer'].items():
        ensure(manifest['producer'].get(key) == value, 'historical/unapproved producer: ' + key)
    ensure(manifest['producer'].get('dirty') is False, 'dirty/missing producer provenance')
    ensure(manifest['schema']['commit'] in policy['schema']['commits'] and
           manifest['schema']['family_sha256'] == policy['schema']['family_sha256'], 'unapproved schema provenance')
    expected_qualification = {'tier': 'authoring_validated', 'scope': manifest['request'].get('mode'),
                              'converted_status': 'CONVERTED_UNVERIFIED', 'schema_validated': True,
                              'final_serializations_validated': True, 'source_proved': False,
                              'ri_executed': False, 'scanner_equivalent': False, 'full_65_complete': False}
    ensure(canonical(manifest['qualification']) == canonical(expected_qualification), 'unproved qualification/coverage claim')
    payload = {n.removeprefix('payload/'): b for n, b in all_files.items() if n.startswith('payload/')}
    ensure(len(payload) == len(all_files) and set(payload) == set(manifest['files']), 'missing/extra/swapped publication members')
    for name, row in manifest['files'].items():
        ensure(row == {'sha256': digest(payload[name]), 'bytes': len(payload[name])}, 'mutated artifact after validation: ' + name)
    snapshot, schema = schema_identity(schema_root, policy)
    validate_payloads(snapshot, payload)
    expected, producer, actual_schema, source = reproduce(producer_root=producer_root, schema_root=schema_root,
                                                         source_root=source_root, request=manifest['request'])
    ensure(canonical(manifest['producer']) == canonical(producer) and canonical(manifest['schema']) == canonical(actual_schema)
           and canonical(manifest['source']) == canonical(source),
           'reproduced provenance mismatch')
    ensure(payload == expected, 'candidate bytes do not reproduce through approved current converter')
    # Package the exact checked byte buffers. A later filesystem mutation cannot
    # substitute a payload between validation and the publication archive.
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted({'publication-manifest.json': raw, 'manifest.sha256': (digest(raw) + '\n').encode(),
                                  **{'payload/' + n: b for n, b in payload.items()}}.items()):
            z.writestr(name, data)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream:
        stream.write(archive.getvalue())
    return {'status': 'ADMITTED_CURRENT_NATIVE_AUTHORING_VALIDATED', 'archive_sha256': digest(archive.getvalue()),
            'manifest_sha256': digest(raw), 'tier': 'authoring_validated', 'scanner_equivalent': False}


def stage_historical(*, patterns, output, receipt, include_hidden=False, missing='error'):
    """Copy the declared upload selection, preserving relative payload paths.

    The receipt stays outside the payload so existing proof aggregators consume
    unchanged files. The trusted uploader forces an unqualified artifact name.
    A historical artifact has no current admission manifest and is never admitted.
    """
    output, receipt = Path(output).absolute(), Path(receipt).absolute()
    ensure(not output.exists() and not receipt.exists(), 'refusing to overwrite historical staging')
    inputs = [line.strip() for line in patterns.splitlines() if line.strip()]
    ensure(inputs and all(not line.startswith('#') for line in inputs), 'explicit artifact paths required')
    roots, paths, exclusions = [], set(), []
    for pattern in inputs:
        if pattern.startswith('!'):
            exclusions.extend(glob.glob(os.path.abspath(pattern[1:]), recursive=True, include_hidden=include_hidden))
            continue
        absolute = os.path.abspath(pattern)
        prefix = absolute
        for i, character in enumerate(absolute):
            if character in '*?[':
                prefix = os.path.dirname(absolute[:i])
                break
        if not glob.has_magic(absolute):
            prefix = absolute if Path(absolute).is_dir() else str(Path(absolute).parent)
        roots.append(prefix)
        ensure(not output.is_relative_to(Path(prefix)) or not glob.has_magic(absolute),
               'historical staging overlaps a recursive upload selection')
        for matched in glob.glob(absolute, recursive=True, include_hidden=include_hidden):
            p = Path(matched)
            if p.is_dir():
                paths.update(q for q in p.rglob('*') if q.is_file() or q.is_symlink())
            else:
                paths.add(p)
    paths = {p for p in paths if not any(p == Path(e) or p.is_relative_to(Path(e)) for e in exclusions)}
    ensure(roots, 'artifact inclusions required')
    root = Path(os.path.commonpath(roots))
    if not include_hidden:
        paths = {p for p in paths if not any(part.startswith('.') for part in p.relative_to(root).parts)}
    if not paths:
        ensure(missing in ('ignore', 'warn'), 'no historical artifact files')
        return {'status': 'NO_FILES_NOT_PUBLISHED', 'files': 0}
    total, payload = 0, {}
    for path in sorted(paths):
        ensure(path.is_file() and not path.is_symlink(), 'nonregular historical input')
        ensure(not any(p.is_symlink() for p in path.parents), 'historical input traverses symlink')
        raw = path.read_bytes()
        total += len(raw)
        ensure(total <= MAX_BYTES and len(payload) < MAX_FILES, 'historical upload budget exceeded')
        payload[safe_name(path.relative_to(root).as_posix())] = raw
    manifest = {'format': 'scap-ng-historical-publication/1', 'tier': 'historical_unqualified',
                'current_native': False, 'proofs': 'preserved_without_promotion_or_transfer',
                'files': {n: {'sha256': digest(b), 'bytes': len(b)} for n, b in payload.items()}}
    output.mkdir(parents=True)
    for name, raw in payload.items():
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_bytes(canonical(manifest))
    return {'status': 'HISTORICAL_DRAFT_UNQUALIFIED', 'directory': str(output),
            'receipt': str(receipt), 'manifest_sha256': digest(canonical(manifest)), 'files': len(payload)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    create = sub.add_parser('prepare')
    create.add_argument('--request', type=Path, required=True)
    check = sub.add_parser('admit')
    check.add_argument('--candidate', type=Path, required=True)
    for p in (create, check):
        p.add_argument('--producer-root', type=Path, required=True)
        p.add_argument('--schema-root', type=Path, required=True)
        p.add_argument('--source-root', type=Path, required=True)
        p.add_argument('--output', type=Path, required=True)
    sub.add_parser('deny-legacy-publication')
    historical = sub.add_parser('stage-historical')
    historical.add_argument('--patterns', required=True)
    historical.add_argument('--output', type=Path, required=True)
    historical.add_argument('--receipt', type=Path, required=True)
    historical.add_argument('--include-hidden', action='store_true')
    historical.add_argument('--missing', choices=('error', 'warn', 'ignore'), default='error')
    args = vars(parser.parse_args())
    action = args.pop('action')
    try:
        if action == 'deny-legacy-publication':
            raise AdmissionError('legacy direct publication is blocked; use current admission or explicitly historical sealing')
        if action == 'stage-historical':
            print(json.dumps(stage_historical(**args)))
            return
        if action == 'prepare':
            args['request'] = json_read(args['request'].read_bytes())
            result = prepare(**args)
            print(json.dumps({'status': 'PREPARED_NOT_PUBLISHED', 'tier': result['qualification']['tier']}))
        else:
            print(json.dumps(admit(**args)))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        parser.exit(2, 'publication rejected: ' + str(error) + '\n')
