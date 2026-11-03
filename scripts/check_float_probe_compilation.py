#!/usr/bin/env python3
"""Optional pinned native compilation of UNQUALIFIED syntax probes only.

Run in a fresh process; the external research toolchain is not a dependency.
This does not update the production ledger or establish OVAL/runtime precision.
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
    parser.add_argument('--probes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('refusing existing output')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.compiler_root, text=True).strip()
    if actual != args.compiler_commit:
        parser.error('external compiler commit mismatch')
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--', 'tools', 'schema'],
                   cwd=args.compiler_root, check=True, stdout=subprocess.DEVNULL)
    raw = args.probes.read_bytes()
    probes = json.loads(raw)
    if (probes.get('format') != 'issue14-UNQUALIFIED-float-syntax-probes/1'
            or probes.get('production_admitted') is not False or len(probes['assessments']) != 10):
        parser.error('not the ten unqualified float syntax probes')
    sys.path.insert(0, str(args.compiler_root / 'tools'))
    from v04_native_bundle_compiler import compile_assessment_program
    from audit_v04_eight_assessment_pilot import verify_program
    rows = []
    for row in probes['assessments']:
        assessment = row['document']['assessment']
        program = compile_assessment_program(assessment)
        verify_program(assessment, program)
        mutant = deepcopy(program)
        mutant['test_instructions'][0]['operands']['capability'] = 'invalid.float_probe'
        try:
            verify_program(assessment, mutant)
        except ValueError:
            pass
        else:
            raise AssertionError('independent reader accepted divergent native operands')
        rows.append({'source_rule': row['source_rule'], 'assessment': assessment['id'],
                     'test_count': len(assessment['tests']), 'compiled': True,
                     'independent_program_operand_check': True, 'operand_mutant_rejected': True,
                     'program_sha256': sha256(json.dumps(program, sort_keys=True, separators=(',', ':'),
                                                        allow_nan=False).encode()).hexdigest()})
    report = {'format': 'issue14-float-syntax-compilation/1', 'compiler_commit': actual,
              'probe_file_sha256': sha256(raw).hexdigest(), 'programs': len(rows),
              'tests': sum(row['test_count'] for row in rows), 'rules': rows,
              'production_admitted': False, 'independent_source_proof': False,
              'scanner_execution': False,
              'qualification': 'Native compilation and independent operand identity of experimental syntax only; no float evaluation or original-source equivalence.'}
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({key: report[key] for key in ('programs', 'tests', 'production_admitted')}))


if __name__ == '__main__':
    main()
