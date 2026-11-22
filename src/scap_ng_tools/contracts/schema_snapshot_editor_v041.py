"""Canonical d1ab0283 editor-pack schema snapshot.

The converter's historical supported snapshot remains unchanged. This adapter
is intentionally scoped to the offline editor exporter so its exact canonical
0.4.1 pack can advance without silently changing converter qualification.
"""
from .schema_snapshot_v041 import Pinned041SchemaSnapshot


class Pinned041EditorSchemaSnapshot(Pinned041SchemaSnapshot):
    canonical_commit = "d1ab0283e09369c2c734d3b8f93b65007441cf07"
    flat_schema_sha256 = "1755c893712ef30334dc7ecadc88e5abf387c2d60a75211bc2445b7cefa2e7d4"
    assessment_execution_family_sha256 = "56d6e0ace6032a505bdcf61f9140436a1f480d696f7441237c2864ada4ade7d6"
    assessment_closure_sha256 = "56d6e0ace6032a505bdcf61f9140436a1f480d696f7441237c2864ada4ade7d6"
    resource_count = 146
    root_schema_count = 35
    supported_count = 101
    version = "0.4.1"
    prefix = "https://scap-ng.dev/schema/v0.4.1/"
