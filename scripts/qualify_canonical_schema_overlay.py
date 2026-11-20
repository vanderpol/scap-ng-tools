#!/usr/bin/env python3
"""Qualify an unmerged canonical-schema overlay without activating it.

This is a review harness only. It deliberately bypasses the production frozen
schema/semantic-pack pin and labels output structural-only. It is useful for
measuring whether a reviewed canonical PR removes a source-linked admission
hold before that PR is merged and the converter pin is cascaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from zipfile import ZipFile

from scap_ng_tools.contracts.schema_snapshot_v041 import load_json
from scap_ng_tools.converter import direct04, oval_platform
import scap_ng_tools.converter._v04_semantic.validation as semantic_validation

CASES = (
    ("def562", "agnostic/oval-def-ext.zip!oval-def-ext.xml", "oval:org.mitre.oval.test:def:562"),
    ("registry", "windows/win-def_registry_test.xml", "oval:org.mitre.oval.test:def:38"),
    ("regkey", "windows/win-def_regkeyeffectiverights53_test.xml", "oval:org.mitre.oval.test:def:729"),
    ("ntuser", "windows/win-def_ntuser_test.xml", "oval:navy.navwar.niwcatlantic.scc.windows.test:def:38"),
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class OverlaySnapshot:
    def __init__(self, root: Path):
        self.schema_root = root
        self.schema_version = "0.4.1"
        self._supported_paths = {
            path.stem: path
            for path in (root / "capability-mappings" / "supported").glob("*.json")
        }

    def supported_mapping(self, capability):
        return load_json(self._supported_paths[capability])

    def supported_mappings(self, capabilities=None):
        names = sorted(self._supported_paths) if capabilities is None else list(capabilities)
        return [self.supported_mapping(name) for name in names]

    def manifest(self):
        return {
            "schema_version": "0.4.1",
            "logical_id_prefix": "https://scap-ng.dev/schema/v0.4.1/",
            "aggregate_sha256": "prospective-unmerged-schema-overlay",
            "canonical_commit": "prospective-unmerged-schema-overlay",
            "assessment_execution_family_sha256": "prospective-unmerged-schema-overlay",
            "assessment_closure_sha256": "prospective-unmerged-schema-overlay",
        }


def source_bytes(root: Path, relative: str) -> bytes:
    if "!" in relative:
        archive, member = relative.split("!", 1)
        with ZipFile(root / "SCAP_1.4" / "OVAL_Test_Content" / archive) as package:
            return package.read(member)
    return (root / "SCAP_1.4" / "OVAL_Test_Content" / relative).read_bytes()


def qualify(schema_root: Path, source_root: Path, source_commit: str) -> dict:
    snapshot = OverlaySnapshot(schema_root)
    direct04.load_pinned_snapshot = lambda _: snapshot
    oval_platform.load_pinned_snapshot = lambda _: snapshot
    # The existing semantic pack is intentionally pinned to merged main. Do
    # not pretend it validates an unmerged schema; structural validation is the
    # only permitted result in this prospective harness.
    semantic_validation.document_errors = lambda snapshot, kind, document: []
    rows = []
    for name, relative, definition in CASES:
        raw = source_bytes(source_root, relative)
        with tempfile.TemporaryDirectory(prefix="canonical-overlay-source-") as temp:
            source = Path(temp) / Path(relative.split("!", 1)[-1]).name
            source.write_bytes(raw)
            try:
                documents, trace = oval_platform.convert_definition(
                    schema_root=schema_root, source=source, sha256_pin=sha(raw),
                    definition_id=definition, source_commit=source_commit,
                    source_path="SCAP_1.4/OVAL_Test_Content/" + relative,
                )
                rendered = json.dumps(documents, sort_keys=True).encode()
                rows.append({
                    "case": name, "source_path": relative, "source_sha256": sha(raw),
                    "definition_id": definition, "status": "structural_converted_only",
                    "test_count": len(trace.get("test_bindings", [])),
                    "assessment_sha256": sha(rendered),
                    "semantic_validation": "skipped_unmerged_schema",
                })
            except Exception as error:
                rows.append({
                    "case": name, "source_path": relative, "source_sha256": sha(raw),
                    "definition_id": definition, "status": "blocked",
                    "diagnostic": str(error)[:1000],
                    "semantic_validation": "skipped_unmerged_schema",
                })
    return {
        "format": "scap-ng-tools/canonical-schema-overlay-qualification/1",
        "qualification": "prospective structural conversion only; do not use as production or equivalence evidence",
        "source_commit": source_commit,
        "schema_root": "<external-prospective-schema-root>",
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.schema_root, args.source_root, args.source_commit)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({row["case"]: row["status"] for row in result["rows"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
