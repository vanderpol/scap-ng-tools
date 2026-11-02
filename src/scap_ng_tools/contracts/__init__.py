"""Offline, pinned SCAP-NG contract readers shared by converter/editor tools."""

from .schema_snapshot import FrozenSchemaSnapshot, SnapshotError

__all__ = ['FrozenSchemaSnapshot', 'SnapshotError']
