#!/usr/bin/env python3
"""Reconcile the public Issue #28 active-candidate ledger pair.

The candidate digest is SHA-256 of canonical JSON containing the rules payload
(format, scope and rules) before the ``candidate`` metadata member is added.
That definition avoids a self-referential digest while pinning both files to
exactly the same source and schema commits.
"""
from __future__ import annotations
import argparse, gzip, hashlib, json
from pathlib import Path

SOURCE_REPO = 'niwc-atlantic/scap-content-library'
SCHEMA_FAMILY = '910beeebfb90a63c773615907289a0e4b93095ee41cd1ad41b33652363900c74'

def canonical_digest(rules: dict) -> str:
    core = {k: rules[k] for k in ('format', 'scope', 'rules')}
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(',', ':')).encode() + b'\n').hexdigest()

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--ledger', type=Path, required=True)
    ap.add_argument('--rules', type=Path, required=True)
    ap.add_argument('--source-commit', required=True)
    ap.add_argument('--schema-commit', required=True)
    args = ap.parse_args()
    ledger = json.loads(args.ledger.read_text(encoding='utf-8'))
    with gzip.open(args.rules, 'rt', encoding='utf-8') as stream:
        rules = json.load(stream)
    for obj in (ledger, rules): obj.pop('candidate', None)
    for rule in rules['rules']: rule.pop('disposition_reason', None)
    for rule in rules['rules']:
        if rule['status'] == 'blocked':
            primary = rule.get('primary_blocker') or (rule.get('blockers') or [{}])[0]
            rule['disposition_reason'] = 'blocked: ' + primary.get('message', 'reported blocker without message')
        elif rule['status'] == 'intentionally_excluded':
            rule['disposition_reason'] = ('intentionally excluded from active modernization: SQLEXT is outside '
                                          'the supported SCAP-NG 0.4 capability contract; no conversion was attempted.')
    for scope in (ledger['scope'], rules['scope']):
        scope['source_revision'] = SOURCE_REPO + '@' + args.source_commit
        scope['schema_commit'] = args.schema_commit
        scope['schema_family_sha256'] = SCHEMA_FAMILY
    # Digest the final rules core, including the reconciled pins and explicit
    # disposition reasons; both ledger and rules must verify this exact value.
    digest = canonical_digest(rules)
    candidate = {'source_commit': args.source_commit, 'schema_commit': args.schema_commit,
                 'schema_family_sha256': SCHEMA_FAMILY, 'candidate_digest': digest}
    rules['candidate'] = candidate; ledger['candidate'] = candidate
    blocked, excluded = [], []
    for rule in rules['rules']:
        if rule['status'] not in ('blocked', 'intentionally_excluded'): continue
        row = {'benchmark': rule['benchmark'], 'source_rule': rule['source_rule'],
               'reason': rule['disposition_reason']}
        if rule['status'] == 'blocked':
            row['reasons'] = [item.get('message', '') for item in rule.get('blockers', [])]
            blocked.append(row)
        else: excluded.append(row)
    ledger['blocker_policy'] = {'rules': len(blocked),
        'reason': 'Each blocked Rule retains its primary blocker and full blocker list in ACTIVE-CANDIDATE-RULES.json.gz; no blocked Rule is emitted as a generated Assessment.'}
    ledger['blocked_rule_reasons'] = blocked
    ledger['exclusion_policy'] = {'rules': len(excluded),
        'reason': 'SQLEXT is outside the supported SCAP-NG 0.4 capability contract; intentionally excluded from active modernization and not emitted as Assessments.',
        'capability': '{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}sqlext',
        'source_rules_retained_in_active_candidate_rules': True}
    ledger['excluded_rule_reasons'] = excluded
    expected_blocked = int(ledger['classification']['genuinely_blocked'])
    expected_excluded = int(ledger['classification']['intentionally_excluded'])
    if len(blocked) != expected_blocked or len(excluded) != expected_excluded:
        raise SystemExit(f'unexpected disposition counts: blocked={len(blocked)} excluded={len(excluded)} expected={expected_blocked}/{expected_excluded}')
    args.ledger.write_text(json.dumps(ledger, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    payload = json.dumps(rules, indent=2, sort_keys=True).encode() + b'\n'
    with args.rules.open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as out: out.write(payload)
    print(json.dumps({'candidate_digest': digest, 'blocked': len(blocked), 'excluded': len(excluded)}, sort_keys=True))

if __name__ == '__main__': main()
