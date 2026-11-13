"""One active SCAP-NG 0.4.1 schema snapshot. No older schema mode.

The canonical repository publishes a flat schema/ tree. A snapshot is usable
only when its exact reviewed 145-resource aggregate SHA-256 matches the
canonical release candidate. This proves bytes/authoring grammar, not runtime
equivalence to source OVAL checks or RI/SCC scanners.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

from .schema_snapshot import SnapshotError, load_json

VERSION = "0.4.1"
PREFIX = "https://scap-ng.dev/schema/v0.4.1/"
FLAT_SCHEMA_SHA256 = "578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829"
RESOURCE_COUNT = 145
ROOT_SCHEMA_COUNT = 35
SUPPORTED_COUNT = 100
NAME = re.compile(r"^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*$")


class Pinned041SchemaSnapshot:
    """Load ONLY the flat 0.4.1 resource family, not a legacy fallback."""

    def __init__(self, root):
        raw = Path(root)
        if (raw / "schema").is_dir():
            raw = raw / "schema"
        if raw.is_symlink() or not raw.is_dir():
            raise SnapshotError("expected a flat, explicit 0.4.1 schema directory")
        self.schema_root = raw.resolve(strict=True)
        self.schema_version = VERSION
        if any(self.schema_root.glob("v0.*")):
            raise SnapshotError("parallel historical schema directories are unsupported")
        paths = sorted((
            *self.schema_root.glob("*.json"),
            *(self.schema_root / "capability-mappings").rglob("*.json"),
        ))
        if len(paths) != RESOURCE_COUNT:
            raise SnapshotError("unexpected 0.4.1 schema resource count")
        digest = sha256()
        for path in paths:
            if not path.is_file() or path.is_symlink():
                raise SnapshotError("missing or symlinked 0.4.1 schema resource")
            digest.update(path.relative_to(self.schema_root).as_posix().encode() + b"\0")
            digest.update(path.read_bytes())
        if digest.hexdigest() != FLAT_SCHEMA_SHA256:
            raise SnapshotError("schema family does not match the exact approved 0.4.1 digest")

        roots = sorted(self.schema_root.glob("*.schema.json"))
        if len(roots) != ROOT_SCHEMA_COUNT:
            raise SnapshotError("unexpected root 0.4.1 JSON Schema count")
        for path in roots:
            doc = load_json(path)
            if (doc.get("$id") != PREFIX + path.name
                    or doc.get("x-scap-ng-version") != VERSION
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
                    or record.get("specification_version") != VERSION):
                raise SnapshotError("0.4.1 capability mapping is not version-pinned: " + path.name)
            self._supported_paths[path.stem] = path

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
            "flat_json_aggregate_sha256": FLAT_SCHEMA_SHA256,
            "schema_root": self.schema_root.as_posix(),
            "root_schema_count": ROOT_SCHEMA_COUNT,
            "supported_capability_count": SUPPORTED_COUNT,
            "single_version": True,
            "external_snapshot_required": True,
        }
