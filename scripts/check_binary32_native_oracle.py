#!/usr/bin/env python3
"""Optional independent C strtof/IEEE comparison experiment, not a scanner."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

C_SOURCE = r'''
#include <fenv.h>
#include <float.h>
#include <inttypes.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    if (sizeof(float)!=4 || sizeof(uint32_t)!=4 || FLT_RADIX!=2 ||
        FLT_MANT_DIG!=24 || FLT_MAX_EXP!=128 || fesetround(FE_TONEAREST)) return 2;
    setlocale(LC_NUMERIC, "C");
    char line[16384];
    while (fgets(line, sizeof(line), stdin)) {
        char *tab=strchr(line, '\t'); if (!tab) return 3; *tab++='\0';
        float a=strtof(line, NULL), b=strtof(tab, NULL); uint32_t bits;
        memcpy(&bits, &a, sizeof(bits));
        printf("%08" PRIx32 " %d %d %d %d %d %d\n", bits,
               a==b, a!=b, a>b, a>=b, a<b, a<=b);
    }
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('refusing existing output')
    compiler = shutil.which('cc')
    if not compiler:
        parser.error('C compiler unavailable; no independent native arithmetic claim')
    from scap_ng_tools.converter.binary32 import require_contract, compare_observed
    require_contract(args.schema_root/'schema')
    rows = json.loads((args.schema_root/'tests/fixtures/binary32-vectors.json').read_text())
    experiments = [(row, expected) for row in rows for expected in (0.0, 1.0, 10.0)]
    source = ''.join(row['lexical'] + '\t' + str(expected) + '\n' for row, expected in experiments)
    with tempfile.TemporaryDirectory(prefix='binary32-native-') as temp:
        cfile, program = Path(temp)/'oracle.c', Path(temp)/'oracle'
        cfile.write_text(C_SOURCE)
        subprocess.run([compiler, '-std=c99', '-O0', str(cfile), '-lm', '-o', str(program)], check=True)
        result = subprocess.run([str(program)], input=source, capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()
    if len(lines) != len(experiments):
        raise AssertionError('native oracle row count mismatch')
    operations = ('equals', 'not_equal', 'greater_than', 'greater_than_or_equal', 'less_than', 'less_than_or_equal')
    for (row, expected), line in zip(experiments, lines):
        actual, *booleans = line.split()
        if len(booleans) != len(operations):
            raise AssertionError('native oracle comparison count mismatch')
        if row['lexical'] == 'NaN':
            bits = int(actual, 16)
            if not (bits & 0x7f800000 == 0x7f800000 and bits & 0x7fffff):
                raise AssertionError('native oracle NaN classification mismatch')
        else:
            if actual != row['bits']:
                raise AssertionError((row, actual))
        for operation, value in zip(operations, booleans):
            if compare_observed(row['lexical'], operation, expected) != bool(int(value)):
                raise AssertionError((row, operation))
    report = {'qualification': 'Independent C strtof/binary32 numerical experiment only; no OVAL evaluator, scanner or complete Rule proof.',
        'compiler': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
        'c_source_sha256': sha256(C_SOURCE.encode()).hexdigest(), 'fixed_vectors': len(rows),
        'native_cast_checks': len(experiments), 'native_comparison_checks': len(experiments)*len(operations),
        'passed': True, 'source_semantic_proof': False, 'scanner_execution': False}
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
