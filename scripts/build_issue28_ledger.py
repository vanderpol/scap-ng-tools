#!/usr/bin/env python3
"""Build the mutually-exclusive all-65 Issue #28 conversion ledger."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_issue28_blockers import compact


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--include-sqlext', action='store_true')
    parser.add_argument('--historical-default', action='store_true',
                        help='disable owner-approved native all_exist/Input recovery')
    args = parser.parse_args()
    report = compact(args.source_dir, args.schema_root,
                     exclude_sqlext=not args.include_sqlext,
                     native_recovery=not args.historical_default)
    report['format'] = 'scap-ng-tools/issue28-complete-ledger/1'
    report['ledger_contract'] = {
        'categories': ['automated_converted_proved', 'automated_converted_unproved',
                       'manual_only', 'genuinely_blocked', 'intentionally_excluded'],
        'mutually_exclusive': True,
        'source_ids_and_hashes_retained': True,
        'proof_note': 'authoring conversion and compilation do not promote a Rule to proved.'
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report['classification'], sort_keys=True))


if __name__ == '__main__':
    main()
