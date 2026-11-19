# Issue #83 source crosswalk receipt

- Source commit: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Archive-set SHA-256: `6e04353f3b1ef32b31a6ef022f75cd7c68486dadb017bd18aa9108c3864ed1ca`
- Archives/Rules: **65 / 8892**
- Rules containing `requires`/`conflicts`: **0**
- OVAL schema commit: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`; declarations inventoried: **1033**

## Findings

The 65 pinned signed archives contain no non-empty XCCDF `Rule/requires` or `Rule/conflicts` children. This is a measured zero, not permission to drop relationships. The converter now preserves source child elements as canonical `requires` clauses and `conflicts` IDs; the focused fixture covers one-token, multi-token, empty and malformed boundaries.

DISA literal description fields are inventoried with per-Rule hashes. The current converter retains the complete source description in `rule.discussion`; structured publisher extensions remain a canonical/owner coordination hold.

The full detailed report is reproducible outside the repository with the script and source root; this committed receipt intentionally contains compact archive identities and counts only.
