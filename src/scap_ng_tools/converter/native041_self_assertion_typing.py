"""Bounded, source-pinned OVAL Self-Assertion typing compatibility overlay.

The original OVAL XML, its source SHA-256 and native authoring schema remain
unchanged. A known malformed declaration can be normalized only inside a
standalone conversion visitor, never by rewriting source or relaxing runtime
typing. This compatibility contract does NOT claim evaluation equivalence to
an invalid original OVAL declaration.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

SOURCE_COMMIT = "e3538595c5083b9c34d937a81d319234df9bbfaa"

# Keyed by original XML path AND original XML SHA, not generated Assessment ID,
# result, filename alone, or a broad lexical-cast heuristic.
PINNED = {
    (
        "agnostic/oval-def_criterion.xml",
        "943136ebe4c6a9fd014a6dda43d1be126c801130dc1e7867165e56434d232f38",
    ): {
        "oval:org.mitre.oval.test:var:524": ("binary", "boolean"),
        "oval:org.mitre.oval.test:var:712": ("binary", "boolean"),
    },
    (
        "agnostic/oval-def_extend_definition.xml",
        "ed488025fedd372fbfc0bf0930139e6ab50cd0343dc04d016b0a185fba6c42be",
    ): {
        "oval:org.mitre.oval.test:var:945": ("binary", "boolean"),
    },
    (
        "agnostic/oval-def_merge.xml",
        "e9cf10371c2d41a3c92087a93f62f597043828d0914a21c5ab4314f03fd8a6ef",
    ): {
        "oval:navy.navwar.niwcatlantic.scc:var:1": ("int", "string"),
        "oval:navy.navwar.niwcatlantic.scc:var:2": ("int", "string"),
        "oval:navy.navwar.niwcatlantic.scc:var:3": ("int", "string"),
        "oval:navy.navwar.niwcatlantic.scc:var:4": ("int", "string"),
        "oval:navy.navwar.niwcatlantic.scc:var:101": ("int", "string"),
    },
}


def qualification_policy(*, source_commit, source_path, source_sha256):
    """Return exactly the preapproved source edits; no general coercion.

    A new commit or XML revision must receive independent review and a new
    source-hash-pinned entry. The original-only SHA remains in trace receipts.
    """
    if source_commit != SOURCE_COMMIT:
        return {}
    # The standalone CLI uses the repository-relative Git blob path, while
    # the independent Definition ledger uses OVAL_Test_Content-relative paths.
    # Only this exact source root prefix is accepted as an alias.
    prefix = "SCAP_1.4/OVAL_Test_Content/"
    logical_path = source_path[len(prefix):] if source_path.startswith(prefix) else source_path
    return PINNED.get((logical_path, source_sha256), {})


def prepare_nodes(node_index, policy, *, source_path):
    """Validate all original declarations up front and return isolated clones.

    The source index is never mutated. Inconsistent declarations fail closed
    instead of producing a partly corrected native Assessment.
    """
    replacements = {}
    for variable_id, (declared, normalized) in sorted(policy.items()):
        original = node_index.get(variable_id)
        if original is None or original.tag.rsplit("}", 1)[-1] not in ("constant_variable", "local_variable"):
            raise ValueError(f"{source_path}: approved source Variable missing: {variable_id}")
        if original.get("datatype") != declared:
            raise ValueError(
                f"{source_path}: expected original datatype {declared!r} "
                f"on {variable_id}, found {original.get('datatype')!r}"
            )
        clone = deepcopy(original)
        clone.set("datatype", normalized)
        replacements[variable_id] = clone
    return replacements


def source_node_digest(element):
    """Hash the original XML node using the pinned visitor's identity rules."""
    def identity(node):
        return [
            node.tag, sorted(node.attrib.items()),
            node.text if not len(node) else None,
            [identity(child) for child in node],
        ]
    payload = json.dumps(identity(element), sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode()
    return sha256(payload).hexdigest()


def trace_records(node_index, replacements, policy):
    """Deterministic source-vs-native provenance for each adjusted Variable."""
    return [{
        "code": "pinned_source_variable_datatype_normalized",
        "source_variable": variable_id,
        "declared_datatype": policy[variable_id][0],
        "native_result_datatype": policy[variable_id][1],
        "original_node_sha256": source_node_digest(node_index[variable_id]),
        "normalized_visitor_node_sha256": source_node_digest(replacements[variable_id]),
        "qualification": "OWNER_ACCEPTED_SOURCE_COMPATIBILITY_NOT_ORIGINAL_OVAL_EQUIVALENCE",
    } for variable_id in sorted(replacements)]
