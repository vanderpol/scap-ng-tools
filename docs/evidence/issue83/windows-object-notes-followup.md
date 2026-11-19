# Windows Object notes follow-up

- Source correction: [Self-Assertion PR #9](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/9)
- Converter admission: [Tools PR #84](https://github.com/vanderpol/scap-ng-tools/pull/84)
- Machine receipt: `windows-object-notes-followup.json`

The pinned source uses deprecated `oval-def:notes` on Objects `obj:3` and `obj:4` in Definition `oval:org.mitre.oval.test:def:360`. The candidate changes only the namespace to canonical `oval:notes` and increments Object versions. The production converter admits both metadata forms, emits an explicit warning for the deprecated baseline form, and produces identical native Assessment bytes. This is authoring/schema validation and representability evidence; runtime execution and independent OVAL equivalence remain unproved.
