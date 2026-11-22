"""Canonical 2d983fc editor-pack schema snapshot.

The editor exporter and converter share the exact current canonical 0.4.1
schema family; this adapter keeps the editor pin explicit and fail-closed.
"""
from .schema_snapshot_v041 import Pinned041SchemaSnapshot


class Pinned041EditorSchemaSnapshot(Pinned041SchemaSnapshot):
    canonical_commit = "2d983fcbd7b2367d567ca8ccc689a378d08905e4"
    flat_schema_sha256 = "dc650646a24e727e68de242027cca3058683accc531f07bf6ace217609755b24"
    assessment_execution_family_sha256 = "56d6e0ace6032a505bdcf61f9140436a1f480d696f7441237c2864ada4ade7d6"
    assessment_closure_sha256 = "56d6e0ace6032a505bdcf61f9140436a1f480d696f7441237c2864ada4ade7d6"
    resource_count = 147
    root_schema_count = 36
    supported_count = 101
    version = "0.4.1"
    prefix = "https://scap-ng.dev/schema/v0.4.1/"
