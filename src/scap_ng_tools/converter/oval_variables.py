"""Legacy import compatibility for standalone OVAL conversion.

The former variable-only adapter duplicated part of the OVAL importer, used
stricter datatype/function checks than the benchmark converter, and became
incompatible with changes to the production AssessmentConverter. All original
OVAL Definitions now use the single adapter in oval_platform and the same
production visitor as XCCDF benchmark Rules.

Do not add conversion logic here. This module exists solely for older callers;
new code imports convert_oval_definition from direct04.
"""

from .oval_platform import StandalonePlatformSource as OvalSource
from .oval_platform import convert_definition

__all__ = ["OvalSource", "convert_definition"]
