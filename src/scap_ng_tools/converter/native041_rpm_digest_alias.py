"""One-to-one deprecated rpmverifyfile digest behavior migration.

OVAL Linux 5.11.1:1.1 formally deprecated nomd5 and md5_differs, replacing
them with nofiledigest and filedigest_differs respectively. Canonical mapping
already handles the State field; this adapter extends the Object behavior
route with an explicit, source-XSD-checked alias. Vendored code stays pinned.
"""
from __future__ import annotations

from functools import wraps
from importlib import import_module
from xml.etree import ElementTree as ET


def install(engine):
    helper = import_module("v04_direct_scalar_behaviors")
    if getattr(helper, "_native041_rpm_digest_alias", False):
        return
    from v04_direct_scap_source import ensure, digest, xml_identity, local_name
    original = helper.scalar_behaviors

    @wraps(original)
    def scalar_behaviors(element, mapping):
        if (mapping.get("capability") != "linux.rpmverifyfile" or element is None
                or "nomd5" not in element.attrib):
            return original(element, mapping)
        migration = mapping.get("migration_crosswalk", {})
        deprecated = migration.get("deprecated", {})
        routes = helper.behavior_routes(mapping)
        ensure(
            deprecated.get("nomd5") == "migration_error_replaced_by_nofiledigest"
            and routes.get("nofiledigest") == "skip_file_digest",
            "deprecated OVAL nomd5 requires approved nofiledigest crosswalk",
        )
        declarations = helper.original_attributes(
            mapping["source"]["definitions_schema"], mapping["source"]["object"])
        ensure("nomd5" in declarations and "nofiledigest" in declarations,
               "original OVAL RPM digest behaviors absent from schema")
        # The XSD permits both spellings; the source specifies the behavior
        # twice only ambiguously. Reject dual specification instead of
        # choosing order-dependent precedence.
        ensure("nofiledigest" not in element.attrib,
               "both deprecated nomd5 and nofiledigest were supplied")
        # No original XML mutation: preserve signed-source digest/provenance.
        substitute = ET.Element(element.tag, dict(element.attrib))
        raw = substitute.attrib.pop("nomd5")
        substitute.set("nofiledigest", raw)
        return original(substitute, mapping)

    helper.scalar_behaviors = scalar_behaviors
    helper._native041_rpm_digest_alias = True

    cls = engine.AssessmentConverter
    if getattr(cls, "_native041_rpm_digest_warning", False):
        return
    old_convert = cls.convert_object

    @wraps(old_convert)
    def convert_object(visitor, element):
        result = old_convert(visitor, element)
        if not getattr(visitor, "native_recovery", False):
            return result
        mapping = visitor.capability(element, "object")
        if mapping.get("capability") != "linux.rpmverifyfile":
            return result
        for child in element:
            if local_name(child) == "behaviors" and "nomd5" in child.attrib:
                visitor.conversion_warnings.append({
                    "code": "oval_deprecated_rpmverifyfile_nomd5",
                    "source_object": element.get("id"),
                    "source_object_sha256": digest(xml_identity(element)),
                    "source_legacy_behavior": "nomd5",
                    "original_value": child.get("nomd5"),
                    "replacement": "nofiledigest",
                    "semantic_basis": "OVAL Linux extension 5.11.1:1.1 deprecation with exact canonical crosswalk",
                    "independent_static_proof": "XSD_MIGRATION_CROSSWALK",
                    "scanner_evaluated": False,
                })
        return result

    cls.convert_object = convert_object
    cls._native041_rpm_digest_warning = True
