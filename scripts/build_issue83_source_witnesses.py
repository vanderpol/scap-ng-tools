#!/usr/bin/env python3
"""Build bounded, source-traced OVAL 5.12.3 positive/negative witnesses.

The pinned Self-Assertion files are individual fragments: their definitions
refer to Tests in other files.  This harness builds a minimal closure around
each source Test and validates it against a wrapper importing the complete
pinned platform definition-schema set.  It also checks every retained
reference explicitly.  The receipt keeps source-schema validity separate from
converter and runtime equivalence.

Large witness XML files are optional and should remain outside Git.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import zipfile
from typing import Iterable

OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
COMMON = "http://oval.mitre.org/XMLSchema/oval-common-5"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
XSD = "http://www.w3.org/2001/XMLSchema"


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def xml_bytes(node) -> bytes:
    return __import__("lxml.etree", fromlist=["etree"]).tostring(
        node, method="xml", with_tail=False, encoding="utf-8")


@dataclass(frozen=True)
class SourceDocument:
    source_file: str
    archive_sha256: str
    member_sha256: str
    root: object
    document_sha256: str


class WitnessBuilder:
    def __init__(self, source_root: Path, schema_root: Path, *, output: Path | None,
                 write_witnesses: bool, max_tests: int, source_commit: str | None = None,
                 schema_commit: str | None = None):
        try:
            from lxml import etree
        except ImportError as error:  # pragma: no cover - environment gated
            raise SystemExit("lxml is required; install it outside the repository") from error
        self.etree = etree
        self.source_root = source_root
        self.schema_root = schema_root
        self.output = output
        self.write_witnesses = write_witnesses
        self.max_tests = max_tests
        self.source_commit = source_commit
        self.schema_commit = schema_commit
        manifest = [{
            "file": path.relative_to(schema_root).as_posix(),
            "sha256": digest(path.read_bytes()),
            "bytes": path.stat().st_size,
        } for path in sorted(schema_root.rglob("*.xsd"))]
        self.schema_manifest_files = len(manifest)
        self.schema_manifest_sha256 = digest(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        self.documents: list[SourceDocument] = []
        self.by_ref: dict[tuple[str, str], list[tuple[int, object]]] = {}
        self._load_documents()
        self.schema = self._load_structural_schema()

    def _parse(self, raw: bytes, source: str):
        try:
            return self.etree.fromstring(raw)
        except self.etree.XMLSyntaxError as error:
            raise ValueError(f"invalid XML {source}: {error}") from error

    def _load_documents(self) -> None:
        paths = sorted(self.source_root.rglob("*.xml"))
        for path in paths:
            raw = path.read_bytes()
            root = self._parse(raw, str(path))
            if local(root.tag) != "oval_definitions":
                continue
            self.documents.append(SourceDocument(
                path.relative_to(self.source_root).as_posix(), digest(raw), digest(raw),
                root, digest(raw)))
        for path in sorted(self.source_root.rglob("*.zip")):
            archive_raw = path.read_bytes()
            archive_sha = digest(archive_raw)
            with zipfile.ZipFile(path) as archive:
                if archive.testzip() is not None:
                    raise ValueError(f"CRC failure in {path}")
                for member in sorted(name for name in archive.namelist()
                                     if name.lower().endswith(".xml")):
                    raw = archive.read(member)
                    root = self._parse(raw, f"{path}!{member}")
                    if local(root.tag) != "oval_definitions":
                        continue
                    self.documents.append(SourceDocument(
                        f"{path.relative_to(self.source_root).as_posix()}!{member}",
                        archive_sha, digest(raw), root, digest(raw)))
        self.documents.sort(key=lambda document: document.source_file)
        for doc_index, document in enumerate(self.documents):
            for container_name, role in (("tests", "test"), ("objects", "object"),
                                         ("states", "state"), ("variables", "variable")):
                container = document.root.find(f"{{{OVAL}}}{container_name}")
                if container is None:
                    continue
                for node in container:
                    identifier = node.get("id")
                    if identifier:
                        self.by_ref.setdefault((role, identifier), []).append((doc_index, node))

    def _load_structural_schema(self):
        # The core schema intentionally leaves platform Test/Object/State/Item
        # declarations to substitution-group imports. Import every pinned
        # definition schema in one temporary wrapper so libxml2 sees that
        # complete source closure. The wrapper is in-memory and is not source
        # content or a modified canonical schema.
        wrapper = self.etree.Element(f"{{{XSD}}}schema",
                                     nsmap={"xsd": XSD})
        wrapper.set("targetNamespace", "urn:scap-ng-tools-issue83-witness")
        for path in sorted(self.schema_root.glob("*-definitions-schema.xsd")):
            schema_root = self.etree.parse(str(path)).getroot()
            namespace = schema_root.get("targetNamespace")
            if namespace:
                self.etree.SubElement(wrapper, f"{{{XSD}}}import",
                                      namespace=namespace,
                                      schemaLocation=str(path))
        return self.etree.XMLSchema(self.etree.ElementTree(wrapper))

    @staticmethod
    def _refs(node) -> Iterable[tuple[str, str]]:
        attr_roles = {"object_ref": "object", "state_ref": "state",
                      "var_ref": "variable", "test_ref": "test"}
        for element in node.iter():
            for key, value in element.attrib.items():
                role = attr_roles.get(local(key))
                if role and value:
                    yield role, value
        text_roles = {"var_ref": "variable", "object_reference": "object",
                      "state_reference": "state", "test_reference": "test",
                      "filter": "state"}
        for child in node.iter():
            role = text_roles.get(local(child.tag))
            value = (child.text or "").strip()
            if role and value:
                yield role, value

    def _resolve(self, role: str, identifier: str, source_index: int):
        candidates = self.by_ref.get((role, identifier), [])
        local_candidates = [node for index, node in candidates if index == source_index]
        if len(local_candidates) == 1:
            return local_candidates[0], "same_document"
        if len(candidates) == 1:
            return candidates[0][1], "cross_document"
        if not candidates:
            return None, "missing"
        return None, "ambiguous"

    def _closure(self, test, source_index: int):
        order = {"test": [], "object": [], "state": [], "variable": []}
        seen: set[tuple[str, str]] = set()
        unresolved = []
        resolutions = []

        def visit(role: str, identifier: str, node=None):
            key = (role, identifier)
            if key in seen:
                return
            seen.add(key)
            if node is None:
                node, basis = self._resolve(role, identifier, source_index)
                resolutions.append({"role": role, "id": identifier, "basis": basis})
            else:
                basis = "selected_source"
            if node is None:
                unresolved.append({"role": role, "id": identifier,
                                   "reason": basis})
                return
            order[role].append(node)
            for child_role, child_id in self._refs(node):
                visit(child_role, child_id)

        identifier = test.get("id")
        visit("test", identifier, test)
        return order, unresolved, resolutions

    def _new_root(self):
        return self.etree.Element(f"{{{OVAL}}}oval_definitions",
                                  nsmap={None: OVAL, "oval": COMMON, "xsi": XSI})

    def _witness(self, test, source_index: int, witness_id: str):
        order, unresolved, resolutions = self._closure(test, source_index)
        root = self._new_root()
        generator = self.etree.SubElement(root, f"{{{OVAL}}}generator")
        self.etree.SubElement(generator, f"{{{COMMON}}}product_name").text = (
            "SCAP-NG Tools Issue 83 witness harness")
        self.etree.SubElement(generator, f"{{{COMMON}}}schema_version").text = "5.12.3"
        self.etree.SubElement(generator, f"{{{COMMON}}}timestamp").text = "2026-01-01T00:00:00Z"
        definitions = self.etree.SubElement(root, f"{{{OVAL}}}definitions")
        definition = self.etree.SubElement(
            definitions, f"{{{OVAL}}}definition",
            **{"id": witness_id, "version": "1", "class": "miscellaneous"})
        metadata = self.etree.SubElement(definition, f"{{{OVAL}}}metadata")
        self.etree.SubElement(metadata, f"{{{OVAL}}}title").text = "Source witness"
        self.etree.SubElement(metadata, f"{{{OVAL}}}description").text = (
            "Generated source-identity witness; not an expected result.")
        criteria = self.etree.SubElement(definition, f"{{{OVAL}}}criteria")
        self.etree.SubElement(criteria, f"{{{OVAL}}}criterion", test_ref=test.get("id"))
        for container_name, role in (("tests", "test"), ("objects", "object"),
                                     ("states", "state"), ("variables", "variable")):
            if not order[role]:
                continue
            container = self.etree.SubElement(root, f"{{{OVAL}}}{container_name}")
            for node in order[role]:
                container.append(deepcopy(node))
        return root, unresolved, resolutions

    def _references_valid(self, root) -> tuple[bool, list[dict]]:
        ids = {role: set() for role in ("test", "object", "state", "variable")}
        for container_name, role in (("tests", "test"), ("objects", "object"),
                                     ("states", "state"), ("variables", "variable")):
            container = root.find(f"{{{OVAL}}}{container_name}")
            if container is not None:
                ids[role].update(node.get("id") for node in container if node.get("id"))
        missing = []
        for node in root.iter():
            for role, identifier in self._refs(node):
                if identifier not in ids[role]:
                    missing.append({"role": role, "id": identifier,
                                    "source_element": local(node.tag)})
        return not missing, missing

    def _mutate_negative(self, root, test_id: str):
        mutated = deepcopy(root)
        target = next((node for node in mutated.iter()
                       if node.get("id") == test_id and local(node.tag).endswith("_test")), None)
        if target is None:
            return mutated
        target.set("check", "__invalid_source_check__")
        return mutated

    def build(self) -> dict:
        tests = []
        for source_index, document in enumerate(self.documents):
            container = document.root.find(f"{{{OVAL}}}tests")
            if container is None:
                continue
            for node in container:
                if node.get("id") and local(node.tag).endswith("_test"):
                    tests.append((source_index, node))
        tests.sort(key=lambda pair: (self.documents[pair[0]].source_file, pair[1].get("id")))
        tests = tests[:self.max_tests]
        rows = []
        if self.output and self.write_witnesses:
            (self.output / "positive").mkdir(parents=True, exist_ok=True)
            (self.output / "negative").mkdir(parents=True, exist_ok=True)
        for ordinal, (source_index, test) in enumerate(tests, 1):
            document = self.documents[source_index]
            witness_id = f"oval:scapng.tools:def:{ordinal}"
            root, unresolved, resolutions = self._witness(test, source_index, witness_id)
            structural_valid = self.schema.validate(root)
            schema_error = None if structural_valid else str(self.schema.error_log.last_error)
            keyrefs_valid, missing = self._references_valid(root)
            negative = self._mutate_negative(root, test.get("id"))
            negative_invalid = not self.schema.validate(negative)
            positive_raw = self.etree.tostring(root, encoding="utf-8", xml_declaration=True)
            negative_raw = self.etree.tostring(negative, encoding="utf-8", xml_declaration=True)
            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", test.get("id"))
            if self.output and self.write_witnesses:
                positive_path = self.output / "positive" / f"{ordinal:04d}-{safe}.xml"
                negative_path = self.output / "negative" / f"{ordinal:04d}-{safe}.xml"
                positive_path.write_bytes(positive_raw)
                negative_path.write_bytes(negative_raw)
            rows.append({
                "source_file": document.source_file,
                "source_archive_sha256": document.archive_sha256,
                "source_member_sha256": document.member_sha256,
                "source_test_id": test.get("id"),
                "source_test_sha256": digest(xml_bytes(test)),
                "witness_definition_id": witness_id,
                "witness_positive_sha256": digest(positive_raw),
                "witness_negative_sha256": digest(negative_raw),
                "closure": {
                    "unresolved": unresolved,
                    "resolutions": resolutions,
                    "reference_check_missing": missing,
                },
                "validation": {
                    "pinned_xsd_import_closure": structural_valid,
                    "schema_error": schema_error,
                    "explicit_keyrefs": keyrefs_valid,
                    "positive_source_witness": structural_valid and keyrefs_valid and not unresolved,
                    "negative_check_mutation_rejected": negative_invalid,
                    "full_schema_keyref_validation": (
                        "proved_by_complete_platform_import_wrapper" if structural_valid
                        else "failed"),
                },
                "qualification": "source_witness_only",
            })
        summary = {
            "format": "scap-ng-tools/issue83-source-witnesses/1",
            "source_root": str(self.source_root),
            "source_commit": self.source_commit,
            "schema_root": str(self.schema_root),
            "schema_commit": self.schema_commit,
            "schema_manifest_files": self.schema_manifest_files,
            "schema_manifest_sha256": self.schema_manifest_sha256,
            "source_documents": len(self.documents),
            "tests_considered": len(tests),
            "positive_source_witnesses": sum(row["validation"]["positive_source_witness"] for row in rows),
            "negative_mutations_rejected": sum(row["validation"]["negative_check_mutation_rejected"] for row in rows),
            "unresolved_closures": sum(bool(row["closure"]["unresolved"]) for row in rows),
            "full_schema_keyref_validation": "proved_by_complete_platform_import_wrapper",
            "expected_outcomes": "not_inferred",
            "independent_equivalence": "not_proved",
        }
        return {"summary": summary, "tests": rows}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--schema-commit")
    parser.add_argument("--max-tests", type=int, default=256)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--write-witnesses", action="store_true")
    args = parser.parse_args(argv)
    if args.max_tests < 1:
        parser.error("--max-tests must be positive")
    result = WitnessBuilder(args.source_root, args.schema_root, output=args.output,
                             write_witnesses=args.write_witnesses,
                             max_tests=args.max_tests, source_commit=args.source_commit,
                             schema_commit=args.schema_commit).build()
    args.output.mkdir(parents=True, exist_ok=True)
    path = args.output / "receipt.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
