# SQLEXT benchmark exclusions

The four SQL Server benchmarks are intentionally excluded from the in-scope
conversion because faithful SQLEXT semantics are not present in native 0.4.
Their 209 source Rules and source hashes remain in the inventory/ledger; no
SQL selector or result is fabricated. The source inventory observed 66
SQLEXT-dependent capability occurrences. This exclusion is reported separately
from genuine conversion blockers.
