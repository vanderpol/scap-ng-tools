"""Bounded standalone OVAL platform lane for canonical unix.file.

This adapter reuses the production AssessmentConverter and frozen capability
mapping. It does not rewrite OVAL semantics or claim scanner equivalence. The
initial lane intentionally admits only unix.file; other platform Test kinds
remain exact blocked diagnostics until their native contracts and collectors
are independently qualified.
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

OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
NS_INDEPENDENT = OVAL + "#independent"
SOURCE_FAMILIES = (OVAL, NS_INDEPENDENT, OVAL + "#unix", OVAL + "#linux")
SUPPORTED_TESTS = {"file_test"}


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
        ensure(generator is not None and generator.findtext(
            "{http://oval.mitre.org/XMLSchema/oval-common-5}schema_version") == "5.12.3",
            "standalone source must declare OVAL 5.12.3")
        self.component_id = component
        self.draft_compatibility = True
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
        references = {"definition_ref": "definition", "test_ref": "test",
                      "object_ref": "object", "state_ref": "state", "var_ref": "variable"}
        counts, visited = Counter(), set()

        def visit(ident, node_kind):
            if (node_kind, ident) in visited:
                return
            visited.add((node_kind, ident))
            node = self.node(component, ident, node_kind)
            for child in node.iter():
                edges = [(child.get(attr), target_kind) for attr, target_kind in references.items()
                         if child.get(attr)]
                if local_name(child) == "var_ref" and child.text:
                    edges.append((child.text.strip(), "variable"))
                for target, target_kind in edges:
                    if target_kind == "object":
                        counts[target] += 1
                    visit(target, target_kind)

        if kind == "object":
            counts[identifier] += 1
        visit(identifier, kind)
        return counts


def references(node):
    result = [{"attribute": key, "id": value} for child in node.iter()
              for key, value in child.attrib.items() if key.endswith("_ref")]
    result.extend({"attribute": "var_ref_text", "id": child.text.strip()}
                  for child in node.iter() if local_name(child) == "var_ref" and child.text)
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
    tests = [node for node in original.node_index.values() if local_name(node).endswith("_test")]
    unsupported = sorted({local_name(node) for node in tests} - SUPPORTED_TESTS)
    ensure(not unsupported, "standalone platform Test kind held: " + ", ".join(unsupported))
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    visitor = engine.AssessmentConverter(original, source_path, mappings,
                                         human_compact=False,
                                         preserve_variable_references=True)
    expression = visitor.reference(definition_id, "definition")
    assessment = {
        "id": native_identifier(definition, "assessment", definition_id),
        "version": int(definition.get("version")),
        "assessment_title": definition.findtext("{" + OVAL + "}metadata/{" + OVAL + "}title"),
        "mode": "automated", "class": definition.get("class"),
        "specification": {"id": "scap-ng.pre-alpha.assessment", "version": "0.4.0"},
        "variables": visitor.variables, "tests": visitor.tests, "evaluate": expression,
    }
    documents = {"assessment.json": {"assessment": assessment}}
    validate_native_documents(snapshot, documents)
    from ._v04_semantic.validation import document_errors
    errors = list(document_errors(snapshot, "assessment", documents["assessment.json"]))
    ensure(not errors, "standalone platform semantic validation failed: " +
           "; ".join(error.message for error in errors[:4]))
    trace = {
        "source_commit": source_commit, "source_path": source_path,
        "source_sha256": sha256_pin, "definition_id": definition_id,
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
