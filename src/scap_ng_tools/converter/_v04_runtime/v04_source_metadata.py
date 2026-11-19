"""Lossless source Rule relationship and publisher metadata helpers.

XCCDF relationships are source policy, not Assessment dependencies.  The
converter keeps their original Rule IDs and leaves publisher-only description
metadata in the source discussion until a canonical extension contract is
approved.  This module is deliberately independent of the native evaluator.
"""
from __future__ import annotations

import html
import xml.etree.ElementTree as ET

XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
DISA_DESCRIPTION_FIELDS = (
    'VulnDiscussion', 'FalsePositives', 'FalseNegatives', 'Documentable',
    'Mitigations', 'SeverityOverrideGuidance', 'PotentialImpacts',
    'ThirdPartyTools', 'MitigationControl', 'Responsibility', 'IAControls',
)


def _tokens(value: str | None) -> list[str]:
    return (value or '').split()


def source_relationships(rule: ET.Element) -> dict[str, list]:
    """Return exact XCCDF Rule relationships in authored order.

    XCCDF represents ``requires`` and ``conflicts`` as child elements. Each
    ``requires/@idref`` is a clause: its whitespace-separated IDs are ORed;
    separate ``requires`` children are ANDed. A conflict carries one ID.
    The result is shaped for the canonical 0.4.1 Rule contract.
    """
    requires = []
    for child in rule.findall(f'{{{XCCDF}}}requires'):
        ids = _tokens(child.get('idref'))
        if not ids:
            raise ValueError('XCCDF requires element has no idref')
        requires.append(ids[0] if len(ids) == 1 else {'any_of': ids})
    conflicts = []
    for child in rule.findall(f'{{{XCCDF}}}conflicts'):
        ids = _tokens(child.get('idref'))
        if len(ids) != 1:
            raise ValueError('XCCDF conflicts element requires one idref')
        conflicts.append(ids[0])
    return {'requires': requires, 'conflicts': conflicts}


def parse_disa_description(description: ET.Element | None) -> dict:
    """Inspect literal DISA XML in an XCCDF description without data loss.

    The converter continues to retain the original description text in
    ``rule.discussion``.  This helper provides an auditable structured view
    for a future approved extension mapping; it must not be used to silently
    replace or discard ordinary/malformed source descriptions.
    """
    raw = '' if description is None else (description.text or '')
    if not raw.strip():
        return {'raw': raw, 'fields': {}, 'parsed': False}
    try:
        root = ET.fromstring('<wrapper>' + html.unescape(raw) + '</wrapper>')
    except ET.ParseError:
        return {'raw': raw, 'fields': {}, 'parsed': False}
    fields = {}
    for child in root:
        if child.tag in DISA_DESCRIPTION_FIELDS and child.tag not in fields:
            fields[child.tag] = ''.join(child.itertext())
    return {'raw': raw, 'fields': fields, 'parsed': bool(fields)}
