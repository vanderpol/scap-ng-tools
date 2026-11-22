# Normative SCAP 1.4 completion matrix

This matrix is generated from the pinned OVAL 5.12.3 source crosswalk.
It normalizes top-level source declarations and deliberately does not promote schema or mapping presence into converter or runtime proof.

- Source commit: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- OVAL schema commit: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`
- Canonical mapping commit: `f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2`
- Input crosswalk SHA-256: `30abf7729a07bd1153e2ca0c77ddee72f1ba0f397d4d37c4e589971010eb38a8`
- Distinct top-level features: **1017**
- Structural grammar rows dispositioned: **42567**

## Classification

| Classification | Count | Meaning |
|---|---:|---|
| deprecated | 227 | Official source deprecation evidence; not active support |
| mapped_unproven | 381 | Canonical mapping candidate exists; converter/semantic/runtime proof remains separate |
| unmapped_source_feature | 409 | Exact mapping absent; review hold, not automatically a canonical gap |

## By platform/schema family

| Platform | Deprecated | Mapped, unproven | Unmapped hold |
|---|---:|---:|---:|
| `aix` | 3 | 8 | 29 |
| `android` | 13 | 0 | 39 |
| `apache` | 4 | 0 | 0 |
| `asa` | 9 | 8 | 27 |
| `aws` | 0 | 0 | 20 |
| `catos` | 6 | 0 | 9 |
| `esx` | 6 | 0 | 9 |
| `freebsd` | 1 | 0 | 3 |
| `hpux` | 8 | 0 | 15 |
| `independent` | 22 | 34 | 8 |
| `ios` | 7 | 44 | 16 |
| `iosxe` | 3 | 44 | 9 |
| `junos` | 2 | 4 | 10 |
| `linux` | 6 | 49 | 9 |
| `macos` | 24 | 68 | 15 |
| `netconf` | 1 | 0 | 3 |
| `oval` | 1 | 0 | 13 |
| `panos` | 0 | 8 | 0 |
| `pixos` | 2 | 0 | 6 |
| `sharepoint` | 19 | 0 | 45 |
| `solaris` | 15 | 14 | 33 |
| `unix` | 17 | 32 | 23 |
| `windows` | 58 | 68 | 68 |

## Structural grammar evidence

The source crosswalk contains inherited members, particles, attributes, Schematron expressions and documentation in addition to top-level declarations. Their disposition counts are retained in the machine matrix under `grammar_inventory`; a row with no mapping is a review hold, not an automatic canonical gap.

Supporting grammar rows are not distinct source features; Schematron rows remain semantic constraints requiring separate proof. The compact JSON retains these dimensions so they cannot be mistaken for 413 top-level converter blockers.

## Proof boundaries

Every feature row carries source QName, schema family, source shape, exact mapping candidates and independent proof fields. Current structural evidence does not prove converter source parity, RI execution, or independent OVAL equivalence.

The full feature rows are intentionally generated externally when large; this compact report is reproducible from the recorded crosswalk hash.
