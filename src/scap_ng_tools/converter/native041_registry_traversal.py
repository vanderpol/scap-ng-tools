"""Native 0.4.1 Registry zero-depth equivalence boundary.

Keep the provenance-pinned OVAL visitor and helper files byte-identical.
The source helper performs all OVAL attribute, direction, depth and selector
validation first. The adapter changes only the emitted *native* operation:
OVAL max_depth=0 permits the starting key but no recursive descent, so a
collector traversal instruction is unnecessary and potentially misleading.
"""
from __future__ import annotations

from functools import wraps
from importlib import import_module


def install() -> None:
    helper = import_module("v04_direct_file_behaviors")
    original = helper.hierarchy_behaviors
    if getattr(original, "_native041_zero_depth_adapter", False):
        return

    @wraps(original)
    def hierarchy_behaviors(element, acquisition, *, native_recovery=False):
        result = original(element, acquisition, native_recovery=native_recovery)
        # Never bypass source validation: deprecated up, non-equality recursive
        # selectors and invalid attributes/depth have already raised here.
        if result.get("traversal") == {"max_depth": 0}:
            return {}
        return result

    hierarchy_behaviors._native041_zero_depth_adapter = True
    helper.hierarchy_behaviors = hierarchy_behaviors
