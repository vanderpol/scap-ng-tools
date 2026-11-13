"""Canonical standalone OVAL source adapter for the shared 0.4 visitor.

Standalone XML is indexed here. All Test/Object/State/Variable/function
translation is performed by the SAME production AssessmentConverter used by
benchmark Rules; no secondary per-capability interpreter or result invention.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from .direct04 import QualifiedConversionError, conversion_identity, load_runtime, validate_native_documents
from .conversion_budget import ConversionBudget, ConversionBudgetTracker

OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
NS_INDEPENDENT = OVAL + "#independent"
SOURCE_FAMILIES = (OVAL, NS_INDEPENDENT, OVAL + "#unix", OVAL + "#linux")


def local_name(element):
    return element.tag.rsplit("}", 1)[-1]


def identity(element):
    return [element.tag, sorted(element.attrib.items()), element.text if not len(element) else None,
            [identity(child) for child in element]]


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def ensure(condition, message):
    if not condition:
        raise QualifiedConversionError(message)


def native_identifier(element, suffix, title=None):
    from ._v04_runtime.v04_direct_scap_source import native_identifier as make_name
    return make_name(element, suffix, title)


class StandalonePlatformSource:
    """Minimal SourceModel protocol consumed by the production visitor."""

    # Reused from 0.3's explicit conversion resource-budget contract. These
    # limits guard implementation resources, not the OVAL language itself.
    # Exceeded budgets reject the entire conversion, never partial authoring.
    DEFAULT_DEPENDENCY_BUDGET = ConversionBudget(
        dependency_nodes=100_000, dependency_edges=500_000)
    def __init__(self, raw: bytes, component: str):
        ensure(b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw,
               "OVAL XML declarations forbidden")
        self.root = ET.fromstring(raw)
        ensure(self.root.tag == "{" + OVAL + "}oval_definitions",
               "expected original OVAL Definitions XML")
        ensure(set(self.root.attrib) <= {
            "{http://www.w3.org/2001/XMLSchema-instance}schemaLocation"},
               "unsupported OVAL root attributes")
        generator = self.root.find("{" + OVAL + "}generator")
        ensure(generator is not None, "standalone OVAL generator missing")
        self.oval_schema_version = generator.findtext(
            "{http://oval.mitre.org/XMLSchema/oval-common-5}schema_version")
        # Pinned publisher CPE/application content legitimately declares
        # older OVAL 5.x versions. Source-version compatibility is an input
        # contract, not a request to reinterpret all earlier syntax as 5.12.3.
        # Unknown versions fail closed and require a separate source proof.
        ensure(self.oval_schema_version in {
            "5.11", "5.11.1", "5.11.2", "5.12.2", "5.12.3"},
            "unsupported standalone source OVAL version: " +
            repr(self.oval_schema_version))
        self.component_id = component
        self.draft_compatibility = True
        # The standalone adapter is the source-parity lane. It may preserve
        # named constant Variables at comparison sites; benchmark conversion
        # keeps its historical inline-literal policy.
        self.standalone_oval = True
        self.nodes = {component: {}}
        for section in self.root:
            if local_name(section) == "generator":
                continue
            ensure(section.tag == "{" + OVAL + "}" + local_name(section),
                   "unsupported OVAL section namespace")
            ensure(local_name(section) in {"definitions", "tests", "objects", "states", "variables"},
                   "unsupported OVAL document section")
            for node in section:
                ident = node.get("id")
                ensure(ident and ident not in self.nodes[component],
                       "duplicate/missing original OVAL ID")
                ensure(node.tag.startswith("{"), "unsupported OVAL declaration namespace")
                self.nodes[component][ident] = node
        self.node_index = self.nodes[component]

    def node(self, component, identifier, kind):
        ensure(component == self.component_id and identifier in self.node_index,
               f"unresolved {kind}: {identifier}")
        node = self.node_index[identifier]
        ensure(local_name(node) == kind or local_name(node).endswith("_" + kind),
               f"wrong reference kind: {identifier}")
        return node

    def object_uses(self, component, identifier, kind):
        """Account for all reachable Objects with an iterative graph walk.

        Restores the 0.3 worklist/active-node model: no Python call-stack
        dependency for deep valid Set/Filter/Variable graphs; direct/indirect
        cycles and missing references fail closed. Multiple Object references
        are counted at their actual source edges, including shared Objects.
        """
        references = {"definition_ref": "definition", "test_ref": "test",
                      "object_ref": "object", "state_ref": "state",
                      "var_ref": "variable"}
        counts, complete, active = Counter(), set(), set()
        budget = ConversionBudgetTracker(self.DEFAULT_DEPENDENCY_BUDGET)
        # (kind, source_id, exiting) — postorder exit releases the active
        # mark while retaining completed shared dependencies.
        pending = [(kind, identifier, False)]
        if kind == "object":
            counts[identifier] += 1

        while pending:
            node_kind, ident, exiting = pending.pop()
            key = (node_kind, ident)
            if exiting:
                active.remove(key)
                complete.add(key)
                continue
            ensure(key not in active,
                   "cyclic standalone OVAL dependency: " + str(ident))
            if key in complete:
                continue
            budget.note_node()
            active.add(key)
            node = self.node(component, ident, node_kind)
            edges = []
            for child in node.iter():
                edges.extend((value, target_kind)
                             for attr, target_kind in references.items()
                             if (value := child.get(attr)))
                element = local_name(child)
                if element in ("object_reference", "filter", "var_ref"):
                    target = (child.text or "").strip()
                    ensure(target, "missing standalone OVAL " + element + " target")
                    edges.append((target, {
                        "object_reference": "object",
                        "filter": "state",
                        "var_ref": "variable",
                    }[element]))
            budget.note_edge(len(edges))
            pending.append((node_kind, ident, True))
            # Count actual incoming Object edges even when the same target
            # was completed through a different path.
            for target, target_kind in reversed(edges):
                if target_kind == "object":
                    counts[target] += 1
                pending.append((target_kind, target, False))
        return counts


def references(node):
    result = [{"attribute": key, "id": value} for child in node.iter()
              for key, value in child.attrib.items() if key.endswith("_ref")]
    # Set/Filter edges are text nodes in OVAL, not *_ref attributes.
    # Preserve them in provenance alongside var_ref and object/state refs.
    for child in node.iter():
        kind = local_name(child)
        if kind in {"var_ref", "object_reference", "filter"} and child.text:
            result.append({"attribute": kind + "_text", "id": child.text.strip()})
    return result


def convert_definition(*, schema_root, source, sha256_pin, definition_id,
                       source_commit, source_path):
    snapshot = FrozenSchemaSnapshot(schema_root)
    raw = Path(source).read_bytes()
    ensure(sha256(raw).hexdigest() == sha256_pin, "original OVAL SHA-256 mismatch")
    ensure(len(source_commit) == 40 and all(c in "0123456789abcdef" for c in source_commit),
           "exact source commit required")
    engine = load_runtime()
    original = StandalonePlatformSource(raw, source_path)
    definition = original.node(source_path, definition_id, "definition")
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    # This is the same 0.4 recovery setting used by the benchmark converter,
    # scoped to this standalone Assessment. All unqualified operations still
    # fail closed at the production visitor/schema/semantic boundaries.
    original.native_recovery = True
    visitor = engine.AssessmentConverter(original, source_path, mappings,
                                         human_compact=False,
                                         native_recovery=True)
    expression = visitor.reference(definition_id, "definition")
    assessment = {
        "id": native_identifier(definition, "assessment", definition_id),
        "version": int(definition.get("version")),
        "assessment_title": definition.findtext("{" + OVAL + "}metadata/{" + OVAL + "}title"),
        "mode": "automated", "class": definition.get("class"),
        "specification": {"id": "scap-ng.pre-alpha.assessment", "version": "0.4.0"},
        "tests": visitor.tests, "evaluate": expression,
    }
    # Standalone OVAL must assemble the same native graph as benchmark Rules.
    # In particular, Set operands are references into shared_objects; omitting
    # that declaration makes a source-valid Set look like an unresolved native
    # Object during independent semantic validation.
    for section in ("shared_objects", "variables"):
        if getattr(visitor, section):
            assessment[section] = getattr(visitor, section)
    if visitor.inputs:
        assessment["inputs"] = visitor.inputs
    documents = {"assessment.json": {"assessment": assessment}}
    validate_native_documents(snapshot, documents)
    from ._v04_semantic.validation import document_errors
    errors = list(document_errors(snapshot, "assessment", documents["assessment.json"]))
    ensure(not errors, "standalone platform semantic validation failed: " +
           "; ".join(error.message for error in errors[:4]))
    trace = {
        "source_commit": source_commit, "source_path": source_path,
        "source_sha256": sha256_pin, "definition_id": definition_id,
        "source_oval_schema_version": original.oval_schema_version,
        "source_nodes": {ident: {**row, "references": references(original.node_index[ident])}
                         for ident, row in sorted(visitor.used.items())},
        "native_identities": [{"kind": kind, "native_id": name, "source_id": source_id}
                              for (kind, name), source_id in sorted(visitor.native_names.items())],
        "test_bindings": [{
            "source_test": source_id, "native_test": native_id,
            "source_object": next((child.get("object_ref") for child in original.node_index[source_id]
                                    if local_name(child) == "object"), None),
            "source_states": [child.get("state_ref") for child in original.node_index[source_id]
                              if local_name(child) == "state"],
        } for (kind, native_id), source_id in sorted(visitor.native_names.items()) if kind == "test"],
        "qualification": "CONVERTED_UNVERIFIED", "schema_validated": True,
        "semantic_validated": True, "scanner_execution": False,
        **conversion_identity(snapshot),
    }
    root = subprocess.run(["git", "-C", str(Path(source).resolve().parent), "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True)
    trace["source_commit_blob_verified"] = False
    if root.returncode == 0:
        blob = subprocess.run(["git", "-C", root.stdout.strip(), "show", source_commit + ":" + source_path],
                              capture_output=True, env=dict(os.environ, GIT_NO_LAZY_FETCH="1"))
        ensure(blob.returncode == 0 and blob.stdout == raw,
               "source commit/path does not match original XML bytes")
        trace["source_commit_blob_verified"] = True
    return documents, trace
