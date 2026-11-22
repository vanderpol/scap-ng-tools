"""One active SCAP-NG 0.4.1 schema snapshot. No older schema mode.

The canonical repository publishes a flat schema/ tree. A snapshot is usable
only when its exact reviewed 145-resource aggregate SHA-256 matches the
canonical release candidate. This proves bytes/authoring grammar, not runtime
equivalence to source OVAL checks or RI/SCC scanners.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit
import re

import json


class SnapshotError(ValueError):
    """An externally supplied schema tree does not meet the approved pin."""


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SnapshotError(f"{path}: duplicate JSON member {key}")
            result[key] = value
        return result

    def nonfinite(value):
        raise SnapshotError(f"{path}: invalid numeric value {value}")

    return json.loads(path.read_bytes(), object_pairs_hook=unique,
                      parse_constant=nonfinite)

CANONICAL_COMMIT = "f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2"
VERSION = "0.4.1"
PREFIX = "https://scap-ng.dev/schema/v0.4.1/"
FLAT_SCHEMA_SHA256 = "11b5ae735dd0a7a1db496b421e0d12f757c027f734da688c2b1d96940f4c47dc"
# RI's execution identity covers its frozen Assessment validator closure.
# It is distinct from the production flat-family identity above. The current
# canonical closure must match before this execution identity may be emitted.
ASSESSMENT_EXECUTION_FAMILY_SHA256 = "9873247ae54f5d9b7ba77f487f8e33f96b791f30c181c8e15f3931a2afcfdf4b"
ASSESSMENT_CLOSURE_SHA256 = "9873247ae54f5d9b7ba77f487f8e33f96b791f30c181c8e15f3931a2afcfdf4b"
RESOURCE_COUNT = 146
ROOT_SCHEMA_COUNT = 35
SUPPORTED_COUNT = 101
NAME = re.compile(r"^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*$")


def fingerprint(paths, root):
    """Hash sorted relative paths and exact bytes, including path identity."""
    checksum = sha256()
    for path in sorted(paths):
        checksum.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        checksum.update(path.read_bytes())
    return checksum.hexdigest()


class Pinned041SchemaSnapshot:
    """Load ONLY the flat 0.4.1 resource family, not a legacy fallback."""

    canonical_commit = CANONICAL_COMMIT
    flat_schema_sha256 = FLAT_SCHEMA_SHA256
    assessment_execution_family_sha256 = ASSESSMENT_EXECUTION_FAMILY_SHA256
    assessment_closure_sha256 = ASSESSMENT_CLOSURE_SHA256
    resource_count = RESOURCE_COUNT
    root_schema_count = ROOT_SCHEMA_COUNT
    supported_count = SUPPORTED_COUNT
    version = VERSION
    prefix = PREFIX

    def __init__(self, root):
        raw = Path(root)
        if (raw / "schema").is_dir():
            raw = raw / "schema"
        if raw.is_symlink() or not raw.is_dir():
            raise SnapshotError("expected a flat, explicit 0.4.1 schema directory")
        self.schema_root = raw.resolve(strict=True)
        self.schema_version = self.version
        if any(self.schema_root.glob("v0.*")):
            raise SnapshotError("parallel historical schema directories are unsupported")
        paths = sorted((
            *self.schema_root.glob("*.json"),
            *(self.schema_root / "capability-mappings").rglob("*.json"),
        ))
        if len(paths) != self.resource_count:
            raise SnapshotError("unexpected 0.4.1 schema resource count")
        digest = sha256()
        for path in paths:
            if not path.is_file() or path.is_symlink():
                raise SnapshotError("missing or symlinked 0.4.1 schema resource")
            digest.update(path.relative_to(self.schema_root).as_posix().encode() + b"\0")
            digest.update(path.read_bytes())
        if digest.hexdigest() != self.flat_schema_sha256:
            raise SnapshotError("schema family does not match the exact approved 0.4.1 digest")

        roots = sorted(self.schema_root.glob("*.schema.json"))
        if len(roots) != self.root_schema_count:
            raise SnapshotError("unexpected root 0.4.1 JSON Schema count")
        for path in roots:
            doc = load_json(path)
            if (doc.get("$id") != self.prefix + path.name
                    or doc.get("x-scap-ng-version") != self.version
                    or doc.get("$schema") != "https://json-schema.org/draft/2020-12/schema"):
                raise SnapshotError("invalid 0.4.1 schema identity: " + path.name)
        variable = load_json(self.schema_root / "variable-expression.schema.json")
        declaration = variable["$defs"]["declaration"]
        if ("datatype" in declaration.get("properties", {})
                or "datatype" in declaration.get("required", [])
                or set(declaration["required"]) != {"kind", "expression"}):
            raise SnapshotError("Variable declarations must infer types under 0.4.1")

        scope = load_json(self.schema_root / "capability-scope.json")
        supported = sorted((self.schema_root / "capability-mappings" / "supported").glob("*.json"))
        if len(supported) != SUPPORTED_COUNT or len(supported) != scope["supported"]["expected_count"]:
            raise SnapshotError("unsupported 0.4.1 capability-count change")
        self._supported_paths = {}
        for path in supported:
            record = load_json(path)
            if (record.get("capability") != path.stem
                    or record.get("specification_version") != self.version):
                raise SnapshotError("0.4.1 capability mapping is not version-pinned: " + path.name)
            self._supported_paths[path.stem] = path

    def assessment_closure(self):
        """Return the exact current Assessment $ref closure, with no fallback."""
        pending = ['assessment.schema.json']
        files = {}
        while pending:
            name = pending.pop()
            if name in files:
                continue
            if Path(name).name != name or not name.endswith('.schema.json'):
                raise SnapshotError('invalid Assessment schema reference')
            path = self.schema_root / name
            raw = path.read_bytes()
            files[name] = raw

            def references(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key == '$ref':
                            ref = urlsplit(child)
                            if ref.scheme and not child.startswith(self.prefix):
                                raise SnapshotError('foreign Assessment schema reference')
                            if ref.path:
                                pending.append(ref.path.rsplit('/', 1)[-1])
                        references(child)
                elif isinstance(value, list):
                    for child in value:
                        references(child)
            references(load_json(path))
        checksum = sha256()
        for name, raw in sorted(files.items()):
            checksum.update(name.encode() + b'\0')
            checksum.update(raw)
        if len(files) != 8 or checksum.hexdigest() != self.assessment_closure_sha256:
            raise SnapshotError('Assessment closure does not match the RI execution pin')
        return files

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
        self.assessment_closure()
        return {
            "assessment_execution_family_sha256": self.assessment_execution_family_sha256,
            "assessment_closure_sha256": self.assessment_closure_sha256,
            "canonical_commit": self.canonical_commit,
            "schema_version": self.version,
            "logical_id_prefix": self.prefix,
            "flat_json_aggregate_sha256": self.flat_schema_sha256,
            "aggregate_sha256": self.flat_schema_sha256,
            "schema_root": self.schema_root.as_posix(),
            "root_schema_count": self.root_schema_count,
            "supported_capability_count": self.supported_count,
            "single_version": True,
            "external_snapshot_required": True,
        }
