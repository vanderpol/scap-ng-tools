# SCAP-NG 0.4 Variable-function support and Issue #47 regression audit

Read-only comparison of the immutable `applicability.8` and `count.1` candidate ledgers; no corpus was regenerated.

## Result

- **55 exact Rule regressions:** `converted → blocked`.
- Classification: **50** inactive-envelope outputs and **5** unrelated datatype/schema blockers.
- Count-bearing regressions: **0** (none expected). The count.1 inventory has 32 converted and 5 blocked count-bearing Rules.
- Runtime/scanner equivalence is **not** claimed.

## Pins and immutable inputs

- applicability.8 SHA-256: `e164ba54ac99ed1ebc6d205205deedea311ad92abd3d83739073eb0751ae4125`
- count.1 SHA-256: `5e34519ee38189d8a104770fc9f1e944b7f3681edf8a76636d931026a8b02571`
- Source: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Schema: `8f8e219e4fb2db8b37a6d0e1ca418e8a392c38e3` (SHA-256 `910beeebfb90a63c773615907289a0e4b93095ee41cd1ad41b33652363900c74`)
- count.1 generator: `0822dd7e4a3b8a7e5656f98322805d28447f1d7c`

## Function-support matrix

| Function | Active native 0.4 | Source uses | Source Rule IDs | count.1 Rule instances (overlapping) | Converter contract |
|---|---:|---:|---:|---|---|
| `arithmetic` | no | 9 | 4 | blocked=4 | fail_closed; inactive function envelope is forbidden |
| `concat` | yes | 750 | 299 | blocked=60, converted=251, intentionally_excluded=16, manual_only=1 | active_native_shape |
| `count` | yes | 47 | 37 | blocked=5, converted=32 | active_native_structural; 32 count-bearing Rules converted |
| `end` | no | 3 | 2 | blocked=2 | fail_closed; inactive function envelope is forbidden |
| `merge` | yes | 106 | 61 | blocked=14, converted=53 | active_native_shape; multi-component source form is unsupported |
| `regex_capture` | yes | 320 | 128 | blocked=16, converted=105, intentionally_excluded=6 | active_native_shape |
| `split` | no | 29 | 23 | blocked=23 | fail_closed; inactive function envelope is forbidden |
| `substring` | no | 21 | 8 | blocked=8 | fail_closed; inactive function envelope is forbidden |
| `unique` | yes | 63 | 87 | blocked=31, converted=86 | active_native_shape; multi-component source form is unsupported |

Active grammar is `concat`, `regex_capture`, `unique`, recursive `count`, and `merge`; the historical generic `function` envelope is not active 0.4 syntax.

## Exact Rule-level regressions

The machine-readable JSON retains every original blocker object and message. Paths below are the emitted assessment paths when present.

### `xccdf_mil.disa.stig_rule_SV-219147r958472_rule` — Ubuntu operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes.
- Benchmark: `U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip`
- Functions in source closure: `concat, split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/ubuntu-operating-systems-maintenance-modes-sv-219147-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': {'capability': 'independent.textfilecontent', 'full_path': {'equals': '/boot/grub/grub.cfg'}, 'pattern': {'matches_regex': '^\\s*set\\s+superusers="(root)"\\s*$'}, 'instance': {'greater_than_or_equal': 1}, 'ignore_case': False, 'multiline': True, 'singleline': False, 'item_creation': 'all_object_elements_fullfilled', 'filesystem': 'all'}, 'field': 'subexpression'}}], 'options': {'delimiter': ' '}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/ubuntu-operating-systems-maintenance-modes-sv-219147-assessment.json: Native Variable expression: Variable grub-superusers-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': {'capability': 'independent.textfilecontent', 'full_path': {'equals': '/boot/grub/grub.cfg'}, 'pattern': {'matches_regex': '^\\s*set\\s+superusers="(root)"\\s*$'}, 'instance': {'greater_than_or_equal': 1}, 'ignore_case': False, 'multiline': True, 'singleline': False, 'item_creation': 'all_object_elements_fullfilled', 'filesystem': 'all'}, 'field': 'subexpression'}}], 'options': {'delimiter': ' '}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-219148r958472_rule` — Ubuntu operating systems booted with United Extensible Firmware Interface (UEFI) implemented must require authentication upon booting into single-user mode and maintenance.
- Benchmark: `U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip`
- Functions in source closure: `concat, split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/ubuntu-operating-systems-and-maintenance-sv-219148-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': {'capability': 'independent.textfilecontent', 'full_path': {'equals': '/boot/efi/EFI/ubuntu/grub.cfg'}, 'pattern': {'matches_regex': '^\\s*set\\s+superusers="(root)"\\s*$'}, 'instance': {'greater_than_or_equal': 1}, 'ignore_case': False, 'multiline': True, 'singleline': False, 'item_creation': 'all_object_elements_fullfilled', 'filesystem': 'all'}, 'field': 'subexpression'}}], 'options': {'delimiter': ' '}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/ubuntu-operating-systems-and-maintenance-sv-219148-assessment.json: Native Variable expression: Variable grub-superusers-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': {'capability': 'independent.textfilecontent', 'full_path': {'equals': '/boot/efi/EFI/ubuntu/grub.cfg'}, 'pattern': {'matches_regex': '^\\s*set\\s+superusers="(root)"\\s*$'}, 'instance': {'greater_than_or_equal': 1}, 'ignore_case': False, 'multiline': True, 'singleline': False, 'item_creation': 'all_object_elements_fullfilled', 'filesystem': 'all'}, 'field': 'subexpression'}}], 'options': {'delimiter': ' '}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251546r1201983_rule` — Firefox must be configured to allow only TLS 1.2 or above.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-allow-only-tls-1-2-or-above-sv-251546-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-allow-only-tls-1-2-or-above-sv-251546-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251547r1067550_rule` — Firefox must be configured to ask which certificate to present to a website when a certificate is required.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, merge, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-ask-which-certificate-is-required-sv-251547-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-ask-which-certificate-is-required-sv-251547-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251548r1067552_rule` — Firefox must be configured to not automatically check for updated versions of installed search plugins.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, merge, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-automatically-search-plugins-sv-251548-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-automatically-search-plugins-sv-251548-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251549r960963_rule` — Firefox must be configured to not automatically update installed add-ons and plugins.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-automatically-ons-and-plugins-sv-251549-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-automatically-ons-and-plugins-sv-251549-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251551r960963_rule` — Firefox must be configured to disable form fill assistance.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-disable-form-fill-assistance-sv-251551-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-disable-form-fill-assistance-sv-251551-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251552r960963_rule` — Firefox must be configured to not use a password store with or without a master password.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-use-password-master-password-sv-251552-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-use-password-master-password-sv-251552-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251553r960963_rule` — Firefox must be configured to block pop-up windows.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-block-pop-up-windows-sv-251553-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-block-pop-up-windows-sv-251553-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251554r1067554_rule` — Firefox must be configured to prevent JavaScript from moving or resizing windows.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, merge, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-prevent-moving-or-resizing-windows-sv-251554-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-prevent-moving-or-resizing-windows-sv-251554-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251555r1067556_rule` — Firefox must be configured to prevent JavaScript from raising or lowering windows.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, merge, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-prevent-or-lowering-windows-sv-251555-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-prevent-or-lowering-windows-sv-251555-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251557r960963_rule` — Firefox must be configured to disable the installation of extensions.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-disable-installation-of-extensions-sv-251557-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-disable-installation-of-extensions-sv-251557-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251558r960963_rule` — Background submission of information to Mozilla must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/background-submission-of-mozilla-disabled-sv-251558-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/background-submission-of-mozilla-disabled-sv-251558-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251559r961167_rule` — Firefox development tools must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-development-tools-must-be-disabled-sv-251559-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-development-tools-must-be-disabled-sv-251559-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251562r1156569_rule` — Firefox must prevent the user from quickly deleting data.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-prevent-user-from-deleting-data-sv-251562-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-prevent-user-from-deleting-data-sv-251562-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251563r960963_rule` — Firefox private browsing must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-private-browsing-must-be-disabled-sv-251563-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-private-browsing-must-be-disabled-sv-251563-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251564r960963_rule` — Firefox search suggestions must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-search-suggestions-must-be-disabled-sv-251564-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-search-suggestions-must-be-disabled-sv-251564-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251565r960963_rule` — Firefox autoplay must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-autoplay-must-be-disabled-sv-251565-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-autoplay-must-be-disabled-sv-251565-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251566r960963_rule` — Firefox network prediction must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-network-prediction-must-be-disabled-sv-251566-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-network-prediction-must-be-disabled-sv-251566-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251567r960963_rule` — Firefox fingerprinting protection must be enabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-fingerprinting-protection-enabled-sv-251567-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-fingerprinting-protection-enabled-sv-251567-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251568r960963_rule` — Firefox cryptomining protection must be enabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-cryptomining-protection-enabled-sv-251568-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-cryptomining-protection-enabled-sv-251568-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251569r1067561_rule` — Firefox Enhanced Tracking Protection must be enabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, merge, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-enhanced-tracking-enabled-sv-251569-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-enhanced-tracking-enabled-sv-251569-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251570r1067563_rule` — Firefox extension recommendations must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, merge, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-extension-recommendations-disabled-sv-251570-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-extension-recommendations-disabled-sv-251570-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251571r960963_rule` — Firefox deprecated ciphers must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-deprecated-ciphers-must-be-disabled-sv-251571-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-deprecated-ciphers-must-be-disabled-sv-251571-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251572r960963_rule` — Firefox must not recommend extensions as the user is using the browser.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-recommend-is-using-browser-sv-251572-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-recommend-is-using-browser-sv-251572-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251573r960963_rule` — The Firefox New Tab page must not show Top Sites, Sponsored Top Sites, Pocket Recommendations, Sponsored Pocket Stories, Searches, Highlights, or Snippets.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-new-tab-page-not-or-snippets-sv-251573-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-new-tab-page-not-or-snippets-sv-251573-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251577r960963_rule` — Firefox must be configured so that DNS over HTTPS is disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-so-that-dns-over-https-is-disabled-sv-251577-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-so-that-dns-over-https-is-disabled-sv-251577-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251578r960963_rule` — Firefox accounts must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-accounts-must-be-disabled-sv-251578-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-accounts-must-be-disabled-sv-251578-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251580r960963_rule` — Firefox feedback reporting must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-feedback-reporting-must-be-disabled-sv-251580-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-feedback-reporting-must-be-disabled-sv-251580-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-251581r960963_rule` — Firefox encrypted media extensions must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-encrypted-media-extensions-disabled-sv-251581-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-encrypted-media-extensions-disabled-sv-251581-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-252881r960963_rule` — Firefox must be configured to not delete data upon shutdown.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-delete-data-upon-shutdown-sv-252881-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-not-delete-data-upon-shutdown-sv-252881-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-252909r960963_rule` — Firefox Studies must be disabled.
- Benchmark: `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
- Functions in source closure: `concat, unique`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `unique`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-studies-must-be-disabled-sv-252909-assessment.json: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/firefox-studies-must-be-disabled-sv-252909-assessment.json: Native Variable expression: Variable policies-json-path-for-firefox-variable/expression: {'function': {'name': 'unique', 'arguments': [{'literal': {'datatype': 'string', 'value': '/etc/firefox/policies'}}, {'concat': [{'values': {'object': {'capability': 'unix.file', 'path': {'equals': '/usr'}, 'filename': {'matches_regex': '^firefox.sh$|^firefox-bin$|^firefox$'}, 'filesystem': 'all', 'traversal': {'max_depth': 'unlimited', 'recurse': 'symlinks_and_directories'}}, 'field': 'directory'}}, {'literal': {'datatype': 'string', 'value': '/distribution'}}]}], 'options': {}}} is not valid under any of the given schemas`

### `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259592r961095_rule` — Exchange queue database must reside on a dedicated partition.
- Benchmark: `U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip`
- Functions in source closure: `concat, substring`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `substring`
- `schema-semantic`: `authoring/direct-slice/assessments/exchange-queue-database-partition-sv-259592-assessment.json: {'function': {'name': 'substring', 'arguments': [{'values': {'object': 'shellcommand-object-true-msiinstallpath-msiinstallpath-w-object', 'field': 'stdout_line'}}], 'options': {'substring_start': 1, 'substring_length': 1}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/exchange-queue-database-partition-sv-259592-assessment.json: Native Variable expression: Variable exchange-installation-drive-letter-variable/expression: {'function': {'name': 'substring', 'arguments': [{'values': {'object': 'shellcommand-object-true-msiinstallpath-msiinstallpath-w-object', 'field': 'stdout_line'}}], 'options': {'substring_start': 1, 'substring_length': 1}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-224867r958388_rule` — Windows Server 2016 must have the number of allowed bad logon attempts configured to three or less.
- Benchmark: `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip`
- Functions in source closure: `none`
- Status: `converted` → `blocked`
- Classification: **unrelated_datatype_or_schema_blocker**; emitted operation(s): `none`
- `schema-semantic`: `authoring/direct-slice/assessments/windows-server-2016-have-three-or-less-sv-224867-assessment.json: Additional properties are not allowed ('relation' was unexpected)`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`

### `xccdf_mil.disa.stig_rule_SV-224868r958388_rule` — Windows Server 2016 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.
- Benchmark: `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip`
- Functions in source closure: `none`
- Status: `converted` → `blocked`
- Classification: **unrelated_datatype_or_schema_blocker**; emitted operation(s): `none`
- `schema-semantic`: `authoring/direct-slice/assessments/windows-server-2016-have-or-greater-sv-224868-assessment.json: Additional properties are not allowed ('relation' was unexpected)`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`

### `xccdf_mil.disa.stig_rule_SV-224869r982201_rule` — Windows Server 2016 password history must be configured to 24 passwords remembered.
- Benchmark: `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip`
- Functions in source closure: `none`
- Status: `converted` → `blocked`
- Classification: **unrelated_datatype_or_schema_blocker**; emitted operation(s): `none`
- `schema-semantic`: `authoring/direct-slice/assessments/windows-server-2016-passwords-remembered-sv-224869-assessment.json: Additional properties are not allowed ('relation' was unexpected)`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`

### `xccdf_mil.disa.stig_rule_SV-224870r982200_rule` — Windows Server 2016 maximum password age must be configured to 60 days or less.
- Benchmark: `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip`
- Functions in source closure: `none`
- Status: `converted` → `blocked`
- Classification: **unrelated_datatype_or_schema_blocker**; emitted operation(s): `none`
- `schema-semantic`: `authoring/direct-slice/assessments/windows-server-2016-age-60-days-or-less-sv-224870-assessment.json: Additional properties are not allowed ('relation' was unexpected)`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`

### `xccdf_mil.disa.stig_rule_SV-224871r982188_rule` — Windows Server 2016 minimum password age must be configured to at least one day.
- Benchmark: `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip`
- Functions in source closure: `none`
- Status: `converted` → `blocked`
- Classification: **unrelated_datatype_or_schema_blocker**; emitted operation(s): `none`
- `schema-semantic`: `authoring/direct-slice/assessments/windows-server-2016-age-at-least-one-day-sv-224871-assessment.json: Additional properties are not allowed ('relation' was unexpected)`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`
- `unsupported-construct`: `unbound external Variable or unsupported possible_restriction`

### `xccdf_mil.disa.stig_rule_SV-271653r1091671_rule` — OL 9 must mount /tmp with the nodev option.
- Benchmark: `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-must-mount-tmp-with-the-nodev-option-sv-271653-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-must-mount-tmp-with-the-nodev-option-sv-271653-assessment.json: Native Variable expression: Variable mount-options-for-tmp-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-271657r1091683_rule` — OL 9 must mount /var/log with the nodev option.
- Benchmark: `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-with-nodev-option-sv-271657-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-with-nodev-option-sv-271657-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-271658r1091686_rule` — OL 9 must mount /var/log with the noexec option.
- Benchmark: `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-with-noexec-option-sv-271658-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-with-noexec-option-sv-271658-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-271659r1091689_rule` — OL 9 must mount /var/log with the nosuid option.
- Benchmark: `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-with-nosuid-option-sv-271659-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-with-nosuid-option-sv-271659-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-271660r1091692_rule` — OL 9 must mount /var/log/audit with the nodev option.
- Benchmark: `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-audit-with-nodev-option-sv-271660-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/ol-9-mount-var-log-audit-with-nodev-option-sv-271660-assessment.json: Native Variable expression: Variable mount-options-for-var-log-audit-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-230511r958804_rule` — RHEL 8 must mount /tmp with the nodev option.
- Benchmark: `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-must-mount-tmp-with-the-nodev-option-sv-230511-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-must-mount-tmp-with-the-nodev-option-sv-230511-assessment.json: Native Variable expression: Variable mount-options-for-tmp-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-230514r958804_rule` — RHEL 8 must mount /var/log with the nodev option.
- Benchmark: `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nodev-option-sv-230514-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nodev-option-sv-230514-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-230515r958804_rule` — RHEL 8 must mount /var/log with the nosuid option.
- Benchmark: `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nosuid-option-sv-230515-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nosuid-option-sv-230515-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-230516r958804_rule` — RHEL 8 must mount /var/log with the noexec option.
- Benchmark: `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-noexec-option-sv-230516-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-noexec-option-sv-230516-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-230517r958804_rule` — RHEL 8 must mount /var/log/audit with the nodev option.
- Benchmark: `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nodev-option-sv-230517-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nodev-option-sv-230517-assessment.json: Native Variable expression: Variable mount-options-for-var-log-audit-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-257866r958804_rule` — RHEL 9 must mount /tmp with the nodev option.
- Benchmark: `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-must-mount-tmp-with-the-nodev-option-sv-257866-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-must-mount-tmp-with-the-nodev-option-sv-257866-assessment.json: Native Variable expression: Variable mount-options-for-tmp-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-257870r958804_rule` — RHEL 9 must mount /var/log with the nodev option.
- Benchmark: `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nodev-option-sv-257870-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nodev-option-sv-257870-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-257871r958804_rule` — RHEL 9 must mount /var/log with the noexec option.
- Benchmark: `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-noexec-option-sv-257871-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-noexec-option-sv-257871-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-257872r958804_rule` — RHEL 9 must mount /var/log with the nosuid option.
- Benchmark: `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nosuid-option-sv-257872-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nosuid-option-sv-257872-assessment.json: Native Variable expression: Variable mount-options-for-var-log-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-257873r958804_rule` — RHEL 9 must mount /var/log/audit with the nodev option.
- Benchmark: `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip`
- Functions in source closure: `split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nodev-option-sv-257873-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nodev-option-sv-257873-assessment.json: Native Variable expression: Variable mount-options-for-var-log-audit-in-etc-fstab-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-216301r959010_rule` — Run control scripts executable search paths must contain only authorized paths.
- Benchmark: `U_SOL_11_SPARC_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip`
- Functions in source closure: `concat, split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216301-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-than-or-equal-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216301-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'path-variables-in-etc-init-d-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216301-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'path-variables-in-lib-svc-method-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216301-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-or-equal-rc-012356s-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216301-assessment.json: Native Variable expression: Variable split-paths-for-etc-rc-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-than-or-equal-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`

### `xccdf_mil.disa.stig_rule_SV-216066r959010_rule` — Run control scripts executable search paths must contain only authorized paths.
- Benchmark: `U_SOL_11_X86_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip`
- Functions in source closure: `concat, split`
- Status: `converted` → `blocked`
- Classification: **inactive_function_envelope**; emitted operation(s): `split`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216066-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-than-or-equal-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216066-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'path-variables-in-etc-init-d-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216066-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'path-variables-in-lib-svc-method-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216066-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-or-equal-rc-012356s-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`
- `schema-semantic`: `authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216066-assessment.json: Native Variable expression: Variable split-paths-for-etc-rc-variable/expression: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-than-or-equal-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas`

## Interpretation and next gate

The 50 inactive-envelope regressions demonstrate a converter admission defect: native recovery attempted to emit schema-invalid generic function objects for operations/shapes not present in the active 0.4 grammar. The safe correction is fail-closed conversion with an explicit unsupported-function blocker. The five unrelated regressions remain separate datatype/possible-restriction work and are not count defects. A new full-corpus candidate is intentionally not produced by Issue #47.
