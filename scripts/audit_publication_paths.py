"""Inventory structured workflow sinks and their referenced Python entrypoints.

The inventory is conservative: opaque/dynamic transports and historical refs are
not proved safe by matching a filename. Runtime admission is a separate gate.
"""
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
import yaml

DENY_PRELUDE = '''# SCAP-NG publication boundary: historical body retained, direct publication denied.
python -I -B -c 'import os,sys; sys.path.insert(0,os.environ["SCAPNG_PUBLICATION_GATE_SRC"]); from scap_ng_tools.publication.gate import main; sys.argv=["publication","deny-legacy-publication"]; main()' || exit $?
'''
TRANSPORT = re.compile(r'\bgh\s+release\s+(?:create|upload)\b|\bgit\s+push\b|\bgh\s+api\b[^\n]*(?:--method\s+(?:PUT|POST|PATCH)|-X\s*(?:PUT|POST|PATCH))|\bcurl\b[^\n]*(?:--upload-file|-T\s|--request\s+(?:PUT|POST))')
BUILDER = re.compile(r'ZipFile|make_archive|tarfile|export-draft|build_v04_full_draft|package_v04_human_library')


def python_transport(text):
    """Inspect actual subprocess argv/HTTP calls, including quoted Python PUTs."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple)):
            tokens = [value.value if isinstance(value, ast.Constant) and isinstance(value.value, str)
                      else '<dynamic>' for value in node.elts]
            if TRANSPORT.search(' '.join(tokens)):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ('requests', 'httpx') and node.func.attr in ('put', 'post', 'patch'):
                return True
    return False


def run_transport(text):
    if TRANSPORT.search(text) or python_transport(text):
        return True
    for match in re.finditer(r"\bpython(?:3)?[^\n]*<<\s*['\"]?(\w+)['\"]?\s*\n(.*?)^\1\s*$", text, re.M | re.S):
        if python_transport(match.group(2)):
            return True
    return False


def inventory(root, repository, trusted_commit=None):
    root = Path(root)
    commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    writers = set()
    for folder in ('tools', 'scripts', 'src'):
        for file in (root / folder).rglob('*.py'):
            if python_transport(file.read_text()):
                writers.add(file.relative_to(root).as_posix())
    workflows, scripts = [], []
    for file in sorted((root / '.github/workflows').glob('*')):
        if file.suffix not in ('.yml', '.yaml'):
            continue
        raw = file.read_bytes()
        document = yaml.load(raw, Loader=yaml.BaseLoader)
        for job_id, job in document.get('jobs', {}).items():
            if 'uses' in job:
                workflows.append({'path': file.relative_to(root).as_posix(), 'job': job_id,
                                  'kind': 'reusable_workflow', 'target': job['uses'], 'status': 'BLOCKER_REVIEW_REUSABLE'})
            for number, step in enumerate(job.get('steps', [])):
                target, run = step.get('uses', ''), step.get('run', '')
                upload = any(name in target for name in ('upload-artifact', 'action-gh-release', 'release-action', 'deploy-pages'))
                shared = 'vanderpol/scap-ng-tools/.github/actions/' in target
                references = sorted(set(re.findall(r'(?:tools|scripts)/[\w/.-]+\.py', run)))
                direct = run_transport(run) or any(reference in writers for reference in references)
                if not (upload or shared or direct):
                    continue
                status = 'BLOCKER_UNGUARDED'
                if shared and trusted_commit and target.endswith('@' + trusted_commit):
                    leaf = target.split('/.github/actions/', 1)[1].split('@')[0]
                    status = {'historical-upload': 'HISTORICAL_SEALED',
                              'current-publication': 'CURRENT_ADMISSION',
                              'configure-gate': 'GATE_BOOTSTRAP'}.get(leaf, 'BLOCKER_UNKNOWN_SHARED_ACTION')
                elif target == './.github/actions/current-publication' and repository == 'vanderpol/scap-ng-tools':
                    status = 'CURRENT_ADMISSION_LOCAL_REVIEW_TREE'
                elif direct and run.startswith(DENY_PRELUDE):
                    status = 'DIRECT_PUBLICATION_DENIED'
                workflows.append({'repository': repository, 'commit': commit,
                                  'path': file.relative_to(root).as_posix(), 'sha256': sha256(raw).hexdigest(),
                                  'events': document.get('on'), 'job': job_id, 'job_if': job.get('if'),
                                  'step': number, 'step_name': step.get('name'), 'step_if': step.get('if'),
                                  'uses': target, 'kind': 'upload' if upload or shared else 'direct_write',
                                  'status': status,
                                  'referenced_python': references})
    for folder in ('tools', 'scripts', 'src'):
        for file in sorted((root / folder).rglob('*.py')):
            raw = file.read_bytes()
            text = raw.decode('utf-8')
            if not (BUILDER.search(text) or TRANSPORT.search(text) or '"PUT"' in text):
                continue
            try:
                tree = ast.parse(text)
                imports = sorted({node.module or '' for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} |
                                 {name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names})
                calls = sorted({ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)})
                error = None
            except SyntaxError as exception:
                imports, calls, error = [], [], str(exception)
            scripts.append({'repository': repository, 'commit': commit, 'path': file.relative_to(root).as_posix(),
                            'sha256': sha256(raw).hexdigest(), 'imports': imports, 'calls': calls,
                            'parse_error': error, 'role': 'builder_or_publication_candidate',
                            'qualification': 'Not admitted merely because it builds or hashes an archive.'})
    return {'repository': repository, 'commit': commit, 'workflow_sinks': workflows,
            'python_entrypoint_candidates': scripts,
            'unprotected_workflow_sinks': sum(row['status'].startswith('BLOCKER') for row in workflows),
            'limits': ['Dynamic scripts, server permissions and historical-ref execution need separate evidence.',
                       'Hashing/inventory is not runtime admission, scanner proof or deployed enforcement.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--trusted-gate-commit')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = inventory(args.root, args.repository, args.trusted_gate_commit)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('repository', 'commit', 'unprotected_workflow_sinks')}))
    if args.check and result['unprotected_workflow_sinks']:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
