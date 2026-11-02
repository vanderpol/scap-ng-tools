"""Standalone, schema-pinned focused SCAP 1.4 → SCAP-NG 0.4 conversion."""

__all__ = ['convert_focused', 'QualifiedConversionError']


def __getattr__(name):
    if name in __all__:
        from . import direct04
        return getattr(direct04, name)
    raise AttributeError(name)
