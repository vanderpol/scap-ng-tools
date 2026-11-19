"""Lossless source selectable-item relationship and publisher metadata helpers.

XCCDF relationships are source policy, not Assessment dependencies.  The
converter keeps their original Rule/Group IDs and leaves publisher-only description
metadata in the source discussion until a canonical extension contract is
approved.  This module is deliberately independent of the native evaluator.
"""
from __future__ import annotations

import hashlib
import html
import json
import xml.etree.ElementTree as ET

XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
DISA_DESCRIPTION_FIELDS = (
    'VulnDiscussion', 'FalsePositives', 'FalseNegatives', 'Documentable',
    'Mitigations', 'SeverityOverrideGuidance', 'PotentialImpacts',
    'ThirdPartyTools', 'MitigationControl', 'Responsibility', 'IAControls',
)


def _tokens(value: str | None) -> list[str]:
    return (value or '').split()


def _clause_ids(value: str | None, *, kind: str) -> list[str]:
    ids = _tokens(value)
    if not ids:
        raise ValueError(f'XCCDF {kind} element has no idref')
    # The canonical Rule any_of contract is uniqueItems.  XCCDF IDREFS is a
    # lexical list and does not provide that native uniqueness guarantee; do
    # not silently deduplicate a source relationship while claiming fidelity.
    if len(ids) != len(set(ids)):
        raise ValueError(f'XCCDF {kind} idref contains duplicate IDs not representable by canonical any_of')
    return ids


def source_relationships(item: ET.Element) -> dict[str, list]:
    """Return exact XCCDF selectable-item relationships in authored order.

    XCCDF represents ``requires`` and ``conflicts`` as child elements on both
    Rules and Groups. Each ``requires/@idref`` is a clause: its
    whitespace-separated IDs are ORed; separate ``requires`` children are
    ANDed. A conflict carries one ID. The result is shaped for the canonical
    0.4.1 Rule contract when ``item`` is a Rule. Group relationships are
    intentionally audited by the same helper but remain a fail-closed hold
    until canonical 0.4.1 defines a non-flattening Group representation.
    """
    requires = []
    for child in item.findall(f'{{{XCCDF}}}requires'):
        ids = _clause_ids(child.get('idref'), kind='requires')
        requires.append(ids[0] if len(ids) == 1 else {'any_of': ids})
    conflicts = []
    for child in item.findall(f'{{{XCCDF}}}conflicts'):
        ids = _tokens(child.get('idref'))
        if len(ids) != 1:
            raise ValueError('XCCDF conflicts element requires one idref')
        conflicts.append(ids[0])
    return {'requires': requires, 'conflicts': conflicts}


def validate_relationship_targets(relationships: dict[str, list], nodes: dict[str, ET.Element]) -> None:
    """Reject dangling/non-selectable XCCDF relationship targets.

    XCCDF relationships are IDREF(S), while the native Rule contract stores
    source IDs without a resolver. Validate the source graph before emission
    so a typo cannot become a seemingly valid prerequisite or conflict.
    Group targets are accepted for source fidelity; Group *relationships*
    themselves remain held by ``native_group`` until canonical mapping exists.
    """
    for kind, clauses in relationships.items():
        targets = []
        if kind == 'requires':
            for clause in clauses:
                targets.extend(clause.get('any_of', []) if isinstance(clause, dict) else [clause])
        else:
            targets.extend(clauses)
        for identifier in targets:
            target = nodes.get(identifier)
            if target is None:
                raise ValueError(f'XCCDF {kind} target is unresolved: {identifier}')
            if target.tag.rsplit('}', 1)[-1] not in ('Rule', 'Group'):
                raise ValueError(f'XCCDF {kind} target is not a Rule or Group: {identifier}')


def _xml_identity(element: ET.Element):
    """Return the stable source-node shape used by converter provenance."""
    return [
        element.tag,
        sorted(element.attrib.items()),
        element.text if not len(element) else None,
        [_xml_identity(child) for child in element],
    ]


def _identity_digest(element: ET.Element) -> str:
    raw = json.dumps(_xml_identity(element), sort_keys=True,
                     ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def source_standard_metadata(item: ET.Element) -> list[dict]:
    """Capture ordered standard XCCDF Rule metadata without native projection.

    ``ident``, ``reference``, ``fix`` and ``fixtext`` are policy/source
    metadata.  The active 0.4.1 Rule contract has no approved generic mapping
    for all of their attributes and semantics, so the converter preserves an
    exact, source-identity-linked ledger in the provenance binding only.
    Child order and duplicate elements are intentional and must not be
    collapsed into a dictionary.
    """
    records = []
    for ordinal, child in enumerate(item, 1):
        kind = child.tag.rsplit("}", 1)[-1]
        if kind not in {"ident", "reference", "fix", "fixtext"}:
            continue
        records.append({
            "ordinal": ordinal,
            "kind": kind,
            "attributes": dict(child.attrib),
            "text": "".join(child.itertext()),
            "source_xml_sha256": _identity_digest(child),
        })
    return records


def source_description_text(item: ET.Element) -> str:
    """Return all authored XCCDF description text, including mixed-content tails.

    ``ElementTree.findtext`` returns only the first text node.  XCCDF
    descriptions may contain escaped publisher payloads or valid inline
    markup, so using it would silently truncate source discussion.  The
    native discussion field is plain text; retain the complete ordered text
    while the source Rule identity digest preserves the original structure.
    """
    description = item.find(f'{{{XCCDF}}}description')
    return '' if description is None else ''.join(description.itertext())


def parse_disa_description(description: ET.Element | None) -> dict:
    """Inspect literal DISA XML in an XCCDF description without data loss.

    The converter continues to retain the original description text in
    ``rule.discussion``.  This helper provides an auditable structured view
    for a future approved extension mapping; it must not be used to silently
    replace or discard ordinary/malformed source descriptions.
    """
    # Preserve mixed-content text before parsing escaped publisher XML.
    raw = '' if description is None else ''.join(description.itertext())
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
