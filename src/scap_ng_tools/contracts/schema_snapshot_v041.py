"""Fail-closed, *separately versioned* SCAP-NG 0.4.1 candidate pack.

This validates the exact source/output manifest emitted by the canonical
build_schema_v041.py generator. 0.4.0 FrozenSchemaSnapshot remains unchanged.
Passing this structural pin does NOT prove source OVAL or RI/SCC equivalence.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re

from .schema_snapshot import SnapshotError, load_json, references

VERSION = "0.4.1"
PREFIX = "https://scap-ng.dev/schema/v0.4.1/"
MANIFEST_SHA256 = "d0dd1abd0966a1843f7fea389524ffb5eca2758850e5a41a860a916655329114"
FORMAT = "scap-ng/v0.4.1/source-and-output-sha256/1"
NAME = re.compile(r"^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*$")


class Pinned041SchemaSnapshot:
    def __init__(self, root):
        raw = Path(root)
        if (raw / "schema" / "v0.4.1").is_dir():
            raw = raw / "schema" / "v0.4.1"
        elif (raw / "v0.4.1").is_dir():
            raw = raw / "v0.4.1"
        if raw.is_symlink() or not raw.is_dir():
            raise SnapshotError("expected an explicit, non-symlink SCAP-NG 0.4.1 schema directory")
        self.schema_root = raw.resolve(strict=True)
        self.schema_version = VERSION
        manifest = self.schema_root / "source-and-output-sha256.json"
        if not manifest.is_file() or manifest.is_symlink():
            raise SnapshotError("0.4.1 source/output manifest missing")
        data = manifest.read_bytes()
        if sha256(data).hexdigest() != MANIFEST_SHA256:
            raise SnapshotError("unapproved 0.4.1 source/output manifest digest")
        receipt = load_json(manifest)
        if (receipt.get("format") != FORMAT
                or receipt.get("source_schema_version") != "0.4.0"
                or receipt.get("target_schema_version") != VERSION
                or receipt.get("target_schema_uri") != PREFIX
                or receipt.get("original_0_4_0_untouched") is not True):
            raise SnapshotError("invalid 0.4.1 pack provenance/identity")
        entries = receipt.get("files")
        if not isinstance(entries, list) or len(entries) != 149:
            raise SnapshotError("unexpected 0.4.1 resource count")
        expected = set()
        for entry in entries:
            p = entry.get("path", "")
            if (not isinstance(p, str) or not p or p.startswith("/")
                    or "\\" in p or ".." in Path(p).parts
                    or p in expected):
                raise SnapshotError("unsafe/duplicate 0.4.1 pack path")
            expected.add(p)
            file = self.schema_root / p
            if not file.is_file() or file.is_symlink():
                raise SnapshotError("0.4.1 pack resource missing or symlinked: " + p)
            if sha256(file.read_bytes()).hexdigest() != entry["target_sha256"]:
                raise SnapshotError("0.4.1 pack resource checksum mismatch: " + p)
        actual = {
            p.relative_to(self.schema_root).as_posix()
            for p in self.schema_root.rglob("*") if p.is_file()
        }
        if actual != expected | {"source-and-output-sha256.json"}:
            raise SnapshotError("unexpected/missing 0.4.1 pack resources")
        roots = sorted(self.schema_root.glob("*.schema.json"))
        if len(roots) != 35:
            raise SnapshotError("wrong 0.4.1 root schema count")
        for file in roots:
            doc = load_json(file)
            if (doc.get("$id") != PREFIX + file.name
                    or doc.get("x-scap-ng-version") != VERSION
                    or doc.get("$schema") != "https://json-schema.org/draft/2020-12/schema"):
                raise SnapshotError("invalid versioned logical schema identity: " + file.name)
        self._supported_paths = {}
        scope = load_json(self.schema_root / "capability-scope.json")
        supported = sorted((self.schema_root / "capability-mappings" / "supported").glob("*.json"))
        if len(supported) != 100 or len(supported) != scope["supported"]["expected_count"]:
            raise SnapshotError("wrong supported 0.4.1 capability count")
        for p in supported:
            record = load_json(p)
            if record.get("capability") != p.stem or record.get("specification_version") != VERSION:
                raise SnapshotError("wrong 0.4.1 capability contract: " + p.name)
            self._supported_paths[p.stem] = p

    def supported_mapping(self, capability):
        if not isinstance(capability, str) or not NAME.fullmatch(capability):
            raise SnapshotError("invalid capability identifier")
        try:
            path = self._supported_paths[capability]
        except KeyError as exc:
            raise SnapshotError("unsupported 0.4.1 capability " + capability) from exc
        return load_json(path)

    def supported_mappings(self, capabilities=None):
        names = sorted(self._supported_paths) if capabilities is None else list(capabilities)
        if len(names) != len(set(names)):
            raise SnapshotError("duplicate capabilities")
        return [self.supported_mapping(name) for name in names]

    def manifest(self):
        return {
            "schema_version": VERSION,
            "logical_id_prefix": PREFIX,
            "source_and_output_manifest_sha256": MANIFEST_SHA256,
            "schema_root": self.schema_root.as_posix(),
            "root_schema_count": 35,
            "supported_capability_count": 100,
            "external_snapshot_required": True,
        }
