#!/usr/bin/env python3
"""Audit active 0.4.1 Variable expression operations across consumers.

The canonical JSON Schema is the source of the operation set.  This is a
quality gate, not a claim of runtime equivalence: supplied RI/editor roots are
checked for handlers, while explicit unsupported Input/runtime paths are
reported as holds instead of being relabeled as canonical gaps.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import sys

EXPECTED_RUNTIME_HOLDS = {"input"}  # RI organizational Input binding is separate.
TO_INTEGER_RULE_IDS = {
    "xccdf_mil.disa.stig_rule_SV-221718r991590_rule",
}
GAP_CLASS_FIELDS = ("category", "disposition_class", "native_conversion_disposition", "failure_class", "disposition")
RULE_ID_FIELDS = ("source_rule", "source_rule_id", "rule_id")


def schema_operations(schema_root: Path) -> list[str]:
    schema = json.loads((schema_root / "variable-expression.schema.json").read_text())
    variants = schema["$defs"]["expression"]["oneOf"]
    operations = []
    for variant in variants:
        properties = variant.get("properties", {})
        if len(properties) != 1:
            raise ValueError("expression variant must expose exactly one operation")
        operations.append(next(iter(properties)))
    if len(operations) != len(set(operations)):
        raise ValueError("duplicate canonical expression operation")
    return operations


def source_has_branch(path: Path, operation: str, *, token: str = "") -> bool:
    text = path.read_text()
    # Branch checks intentionally look for executable dispatch syntax rather
    # than a comment or a documentation mention. A deliberate branch removal
    # therefore fails this gate even if the operation remains documented.
    patterns = (
        rf"\bif\s+(?:op|operation)\s*==\s*['\"]{re.escape(operation)}['\"]",
        rf"\bcase\s+[^:\n]*['\"]{re.escape(operation)}['\"]", 
        rf"['\"]{re.escape(operation)}['\"]\s*:\s*",
        rf"\b(?:op|operation)\s+in\s+[^\n)]*['\"]{re.escape(operation)}['\"]",
    )
    return any(re.search(pattern, text) for pattern in patterns) and (not token or token in text)


def _rule_disposition_rows(value):
    """Yield only rows that carry both a source Rule identity and disposition.

    Ledgers contain nested summaries and unrelated Definitions/Tests. Matching
    serialized text is unsafe: an unrelated Rule can mention both the witness
    ID and a legitimate gap. This walk preserves row-local identity.
    """
    if isinstance(value, dict):
        source_ids = {str(value[key]) for key in RULE_ID_FIELDS
                      if isinstance(value.get(key), str)}
        classes = {str(value[key]) for key in GAP_CLASS_FIELDS
                   if isinstance(value.get(key), str)}
        if source_ids and classes:
            yield source_ids, classes, value
        for child in value.values():
            yield from _rule_disposition_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from _rule_disposition_rows(child)


def audit(schema_root: Path, *, ri_root: Path | None = None,
          editor_root: Path | None = None,
          editor_pack: Path | None = None,
          blocker_receipt: Path | None = None,
          tools_root: Path | None = None) -> dict:
    operations = schema_operations(schema_root)
    semantic = schema_root.parent  # only used to make result paths explicit
    tools_root = tools_root or Path(__file__).resolve().parents[1]
    semantic_file = tools_root / "src/scap_ng_tools/converter/_v04_semantic/v04_variable_expressions.py"
    semantic_missing = [op for op in operations if not source_has_branch(semantic_file, op)]
    # Check the generic production lowerer, not the source-specific adapter
    # that happens to mention the operation while preserving Input witnesses.
    converter_file = tools_root / "src/scap_ng_tools/converter/native041_function_lowering.py"
    converter_missing = ["to_integer"] if "to_integer" in operations and not source_has_branch(converter_file, "to_integer") else []
    result = {
        "format": "scap-ng/issue118-operation-coverage/1",
        "schema": {"root": str(schema_root), "operations": operations},
        "converter": {"semantic_missing": semantic_missing, "to_integer_lowering_missing": converter_missing},
        "runtime": {"checked": False, "missing": [], "held": sorted(EXPECTED_RUNTIME_HOLDS)},
        "editor": {"checked": False, "missing": [], "pack_checked": False, "pack_missing": [], "pack_extra": []},
        "classification": {
            "to_integer_canonical_gap": False,
            "gap_dispositions": {"checked": False, "status": "not_checked", "matches": []},
        },
        "errors": [],
    }
    if ri_root:
        result["runtime"]["checked"] = True
        runtime_file = ri_root / "evaluate/variable_functions.go"
        infer_file = ri_root / "evaluate/infer041.go"
        count_file = ri_root / "evaluate/variable_count.go"
        for op in operations:
            if op in EXPECTED_RUNTIME_HOLDS:
                continue
            files = [runtime_file, infer_file]
            if op != "input":
                files.append(count_file)
            if not all(path.is_file() and source_has_branch(path, op) for path in files):
                result["runtime"]["missing"].append(op)
    if editor_root:
        result["editor"]["checked"] = True
        # Every schema-admitted operation must have a concrete template
        # dispatch in the host authoring path. The graphical planner and
        # schema-driven operation list are checked separately by editor CI;
        # this avoids mistaking a displayed menu item for a serializable edit.
        template_file = editor_root / "src/extension.ts"
        for op in operations:
            if not template_file.is_file() or not source_has_branch(template_file, op):
                result["editor"]["missing"].append(op)
    if editor_pack:
        result["editor"]["pack_checked"] = True
        manifest_path = editor_pack / "manifest.json"
        schema_path = editor_pack / "schemas/variable-expression.schema.json"
        try:
            manifest = json.loads(manifest_path.read_text())
            packed = schema_operations(editor_pack / "schemas")
            result["editor"]["pack_source_commit"] = manifest.get("source_commit")
            result["editor"]["pack_operations"] = packed
            result["editor"]["pack_missing"] = sorted(set(operations) - set(packed))
            result["editor"]["pack_extra"] = sorted(set(packed) - set(operations))
        except (OSError, KeyError, TypeError, ValueError) as error:
            result["editor"]["pack_missing"] = ["editor-pack-invalid: " + str(error)]
            result["editor"]["pack_extra"] = []
        if result["editor"]["pack_missing"]:
            result["errors"].append("editor metadata pack omits active schema operations")
        if result["editor"]["pack_extra"]:
            result["errors"].append("editor metadata pack contains operations absent from the active schema")
    if blocker_receipt and blocker_receipt.is_file():
        payload = json.loads(blocker_receipt.read_text())
        matches = []
        for source_ids, classes, row in _rule_disposition_rows(payload):
            matched_ids = sorted(source_ids & TO_INTEGER_RULE_IDS)
            if matched_ids and "canonical_language_gap" in classes:
                matches.append({"source_rule": matched_ids[0], "classification": "canonical_language_gap"})
        result["classification"]["gap_dispositions"] = {
            "checked": True,
            "status": "fail" if matches else "pass",
            "matches": matches,
            "receipt": str(blocker_receipt),
        }
        # This exact Rule is the original defect witness. It may not remain a
        # canonical-language-gap row after the canonical to_integer admission.
        result["classification"]["to_integer_canonical_gap"] = bool(matches)
    if semantic_missing:
        result["errors"].append("semantic validator lacks an active schema operation branch")
    if converter_missing:
        result["errors"].append("converter lacks the canonical to_integer lowering branch")
    if result["runtime"]["missing"]:
        result["errors"].append("RI lacks one or more non-held active operation handlers")
    if result["editor"]["missing"]:
        result["errors"].append("editor lacks to_integer authoring/inference handling")
    if result["classification"]["to_integer_canonical_gap"]:
        result["errors"].append("to_integer is incorrectly classified as a canonical language gap")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--tools-root", type=Path)
    parser.add_argument("--ri-root", type=Path)
    parser.add_argument("--editor-root", type=Path)
    parser.add_argument("--editor-pack", type=Path)
    parser.add_argument("--blocker-receipt", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = audit(args.schema_root, ri_root=args.ri_root, editor_root=args.editor_root,
                   editor_pack=args.editor_pack, blocker_receipt=args.blocker_receipt,
                   tools_root=args.tools_root)
    raw = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(raw)
    print(raw, end="")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
