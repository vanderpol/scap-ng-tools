# OVAL 5.12.3 → SCAP-NG 0.4 feature coverage

Schema admission is not runtime equivalence or independent proof.

| Feature | Source occurrences | Benchmarks | Schema | Converter/runtime status | Proof |
| --- | ---: | ---: | --- | --- | --- |
| `arithmetic` | 5 | 4 | inactive broader function schema | missing/unsupported | source-backed proof not established by conversion |
| `capability:independent.family` | 1 | 1 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:independent.shellcommand` | 1581 | 45 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:independent.textfilecontent` | 4420 | 24 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:independent.unknown` | 34 | 7 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:independent.xmlfilecontent` | 13 | 3 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:iosxe.global` | 106 | 5 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:iosxe.line` | 258 | 5 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:linux.dpkginfo` | 99 | 4 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:linux.partition` | 138 | 10 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:linux.rpminfo` | 323 | 10 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:linux.rpmverifyfile` | 2 | 2 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:linux.selinuxsecuritycontext` | 4 | 4 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:linux.systemdunitproperty` | 115 | 9 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:solaris.smf` | 50 | 2 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.file` | 692 | 19 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.interface` | 9 | 9 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.password` | 39 | 11 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.process` | 117 | 10 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.shadow` | 25 | 13 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.symlink` | 37 | 8 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.sysctl` | 221 | 14 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:unix.uname` | 105 | 4 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:variable.value` | 80 | 27 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.appcmd` | 36 | 3 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.appcmdlistconfig` | 91 | 8 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.auditeventpolicysubcategories` | 541 | 10 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.cmdlet` | 90 | 12 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.file` | 46 | 18 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.fileeffectiverights` | 111 | 10 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.lockoutpolicy` | 57 | 8 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.ntuser` | 158 | 12 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.passwordpolicy` | 64 | 12 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.registry` | 2308 | 29 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.regkeyeffectiverights` | 32 | 2 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.service` | 19 | 8 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.sid` | 2 | 1 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.sid_sid` | 4 | 2 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.user_sid` | 2 | 2 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.userright` | 202 | 7 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:windows.wmi.query` | 228 | 15 | supported | supported-but-proof-gated | source-backed proof not established by conversion |
| `capability:{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}sqlext` | 214 | 4 | not admitted by snapshot | missing/unsupported | source-backed proof not established by conversion |
| `capability:{http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken` | 168 | 4 | not admitted by snapshot | missing/unsupported | source-backed proof not established by conversion |
| `capability:{http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user` | 10 | 8 | not admitted by snapshot | missing/unsupported | source-backed proof not established by conversion |
| `capability:{http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi` | 36 | 3 | not admitted by snapshot | missing/unsupported | source-backed proof not established by conversion |
| `concat` | 768 | 48 | active native grammar | supported-but-proof-gated | source-backed proof not established by conversion |
| `constant_variable` | 759 | 34 | active bounded Variable grammar | supported-but-proof-gated | source-backed proof not established by conversion |
| `count` | 47 | 14 | inactive broader function schema | missing/unsupported | source-backed proof not established by conversion |
| `end` | 6 | 1 | inactive broader function schema | missing/unsupported | source-backed proof not established by conversion |
| `external_variable` | 443 | 11 | active bounded Variable grammar | supported-but-proof-gated | source-backed proof not established by conversion |
| `filter:operation` | 738 | 37 | active 0.4 contract where capability-specific | supported-but-proof-gated | source-backed proof not established by conversion |
| `local_variable` | 1450 | 49 | active bounded Variable grammar | supported-but-proof-gated | source-backed proof not established by conversion |
| `merge` | 98 | 15 | active native grammar | supported-but-proof-gated | source-backed proof not established by conversion |
| `regex_capture` | 308 | 26 | active native grammar | supported-but-proof-gated | source-backed proof not established by conversion |
| `set:operation` | 979 | 33 | active 0.4 contract where capability-specific | supported-but-proof-gated | source-backed proof not established by conversion |
| `split` | 29 | 10 | inactive broader function schema | missing/unsupported | source-backed proof not established by conversion |
| `substring` | 21 | 7 | inactive broader function schema | missing/unsupported | source-backed proof not established by conversion |
| `unique` | 87 | 15 | active native grammar | supported-but-proof-gated | source-backed proof not established by conversion |
