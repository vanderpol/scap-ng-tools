# Count candidate generation performance

These are wall-clock command measurements in the Codex Linux environment, not model reasoning time. AI analysis/planning time is excluded. Timings include process startup and filesystem I/O; concurrent commands are identified.

| Phase | Command / evidence | Wall clock | Result |
|---|---|---:|---|
| Schema/metadata generation | `generate_approved_annotation_pilot.py --materialize` followed by `generate_docs.py` | 4.015 s | PASS |
| Converter execution / fast normal audit | `build_issue28_ledger.py` over the pinned source set (observed process elapsed) | ~4m50s | PASS; 65-source audit/ledger, not release qualification |
| 63-benchmark corpus generation | `publish_issue28_assessments.py` | ~17m20s | PASS; 22,483 JSON and YAML documents, archive SHA verified |
| JSON/YAML exact validation | independent schema-only validation command (see JSON receipt) | pending measurement | PASS when receipt is complete |
| Independent archive audit | `audit_candidate_archive.py` | ~8m35s | PASS for conformance; one known editor filename-selector defect reported |
| Reproducibility rebuild | same publisher command at generator commit `0822dd7e4a3b8a7e5656f98322805d28447f1d7c` | ~20m54s | PASS; byte-identical archive |

The routine command is the converter/ledger audit when iterating on source conversion. The release command is the publisher followed by the independent auditor and reproducibility rebuild; it must not be replaced by the routine command and does not weaken validation.

The release bottleneck is repeated Draft 2020-12 validation plus dependency-graph walking across approximately 45,096 archive files/documents. No validation was disabled to improve the routine path. A sub-five-minute *qualified release* target was not met in this environment; normal conversion iteration was approximately five minutes.
