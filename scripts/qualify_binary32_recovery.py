#!/usr/bin/env python3
"""Optional pinned native package checks for explicit ten-case recovery.

Fresh process only; the research toolchain is not a runtime dependency. Native
identity/program checks do not establish original OVAL or scanner equivalence.
"""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler-root', type=Path, required=True)
    parser.add_argument('--compiler-commit', required=True)
    parser.add_argument('--recovery', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('refusing existing output')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.compiler_root, text=True).strip()
    if actual != args.compiler_commit: parser.error('compiler commit mismatch')
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--', 'tools', 'schema', 'docs/metadata'],
                   cwd=args.compiler_root, check=True, stdout=subprocess.DEVNULL)
    source_report = (args.recovery/'recovery.json').read_bytes()
    report = json.loads(source_report)
    if report['counts_after'] != {'AUTOMATED_DRAFT': 10} or report['recovered'] != 10:
        parser.error('not the ten recovered source cases')
    files = sorted(args.recovery.glob('documents-*.json'))
    if len(files) != 9: parser.error('expected nine source Benchmark groups')
    sys.path.insert(0, str(args.compiler_root/'tools'))
    from v04_native_bundle_compiler import build_bundle, verify_bundle, compile_assessment_program
    from verify_v04_package_consumer import verify, program_contract
    from audit_v04_eight_assessment_pilot import verify_program
    args.output.mkdir(parents=True)
    rows, programs, tests, mutants, manuals = [], 0, 0, 0, 0
    for index, file in enumerate(files):
        case = json.loads(file.read_bytes()); docs = case['documents']
        raw, _ = build_bundle(docs); local = verify_bundle(raw)
        path = args.output/f'benchmark-{index}.scapng'; path.write_bytes(raw)
        source = {(next(iter(d)), next(iter(d.values()))['id']): (name, d) for name, d in docs.items()}
        independent = verify(path, source=source)
        for doc in docs.values():
            a = doc.get('assessment', {})
            if a.get('mode') == 'manual': manuals += 1
            if a.get('mode') != 'automated': continue
            program = compile_assessment_program(a); program_contract(a, program); verify_program(a, program)
            programs += 1; tests += len(a['tests'])
            for kind in ('contract', 'operand'):
                wrong = deepcopy(program)
                if kind == 'contract': wrong['binary32_comparison_contract']['sha256'] = '0'*64
                else: wrong['test_instructions'][0]['operands']['capability'] = 'invalid.binary32'
                try: verify_program(a, wrong)
                except ValueError: mutants += 1
                else: raise AssertionError('independent reader accepted ' + kind + ' mutant')
        rows.append({'source_archive': case['filename'], 'documents_file_sha256': sha256(file.read_bytes()).hexdigest(),
            'bundle_sha256': sha256(raw).hexdigest(), 'bundle_bytes': len(raw),
            'native_verification_status': local['status'], 'documents': independent['documents'],
            'programs': independent['programs'], 'tests': independent['tests'],
            'external_native_source_compared': independent['external_source_compared']})
    if (programs, tests, mutants, manuals) != (10, 19, 20, 10):
        raise AssertionError('qualification count mismatch')
    result = {'format': 'issue14-binary32-native-qualification/1', 'compiler_commit': actual,
        'source_recovery_report_sha256': sha256(source_report).hexdigest(), 'contract': report['contract'],
        'packages': len(rows), 'documents': sum(row['documents'] for row in rows),
        'programs': programs, 'tests': tests, 'independent_mutants_rejected': mutants,
        'manual_assessments': manuals, 'benchmarks': rows, 'independent_source_proof': False,
        'scanner_execution': False,
        'qualification': 'Native package/schema/graph/program and independent source/program identity only; not original OVAL/source or scanner equivalence.'}
    (args.output/'qualification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ('packages', 'documents', 'programs', 'tests', 'manual_assessments', 'independent_mutants_rejected')}))


if __name__ == '__main__': main()
