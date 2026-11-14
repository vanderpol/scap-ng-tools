# Issue #59 datatype recovery ledger

This ledger is generated from the original 118 converted→blocked transitions in the signed 65-ZIP rebuild. It records source XML identities and does not claim scanner or RI equivalence.

## Pins and proof boundary

- Canonical schema commit: `aece827964c785be77b088c3c61255a2d07fd9a9`
- Schema aggregate SHA-256: `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`
- Source commit: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Original regression receipt SHA-256: `d6f8f21ca649d9aae688a5785b656ff96c8ea620de945d1a0ff7760e370070a1`
- Latest rebuild receipt SHA-256: `8655eb5bc701f294869936d2436546c322915185ca35c010952481403e3d0761`
- OVAL semantic source: 5.12.3 as pinned by the 0.4.1 semantic pack (`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`).
- Proof status: authoring-only/unverified; scanner-equivalent is explicitly false.

## Outcome

| source family | original | recovered | still blocked |
|---|---:|---:|---:|
| `collected_field` | 115 | 7 | 108 |
| `unique` | 3 | 3 | 0 |

Recovered transformations are only: (1) collected Item fields whose reviewed `field_datatypes` is exactly `string` (`independent.shellcommand.stdout_line`, 7 Rules), and (2) source OVAL `unique`, whose pinned function contract explicitly produces lexical strings (3 Rules). The latter is represented by an explicit empty-prefix `concat` at each collected-field operand.

The 108 remaining cases retain native Variable datatype inference and remain blocked; the source `string`/`int` declaration is provenance, not a cast. OVAL State comparison domains are recorded separately from collected Item domains.

## Recovered Rule IDs

- `xccdf_mil.disa.stig_rule_SV-238367r958902_rule` — `unique`, independent.shellcommand.subexpression; OVAL 5.12.3 unique has an explicit lexical-string result. Source Rule SHA-256 `156f313306b5f53d24b5fd36851feafe0b06588267651358a8731213acb2330c`.
- `xccdf_mil.disa.stig_rule_SV-260517r958902_rule` — `unique`, independent.shellcommand.subexpression; OVAL 5.12.3 unique has an explicit lexical-string result. Source Rule SHA-256 `1006970e4c80c5ff57e80ece5395ae5014f5ce0cf2733e263de1dbbeabbec860`.
- `xccdf_mil.disa.stig_rule_SV-270754r1066751_rule` — `unique`, independent.shellcommand.subexpression; OVAL 5.12.3 unique has an explicit lexical-string result. Source Rule SHA-256 `4d78a4f569d3dcdb162532639956140458e68f27b89125ec42e462344b2dbff1`.
- `xccdf_navy.navwar.niwcatlantic.scc.ms.dns_rule_SV-259338r1028386_rule` — `object_component`, independent.shellcommand.stdout_line; collected Item field contract is a singleton datatype. Source Rule SHA-256 `055363a557decea13b74bf0f01cf6a937860f97d763cc742d25771cd1314a53a`.
- `xccdf_navy.navwar.niwcatlantic.scc.ms.dns_rule_SV-259368r1212359_rule` — `object_component`, independent.shellcommand.stdout_line; collected Item field contract is a singleton datatype. Source Rule SHA-256 `8cd9b24878892eb34f1080e5d58894c189df81fe3a8d5bf06a4ebd4d4119be7b`.
- `xccdf_mil.disa.stig_rule_SV-221734r991589_rule` — `object_component`, independent.shellcommand.stdout_line; collected Item field contract is a singleton datatype. Source Rule SHA-256 `1096c2ba8162d9f6cae391b1d26934818bc15665f06cb2e409533c1c4a85a811`.
- `xccdf_mil.disa.stig_rule_SV-248640r991589_rule` — `object_component`, independent.shellcommand.stdout_line; collected Item field contract is a singleton datatype. Source Rule SHA-256 `bfbd1448a3e5ba29fcfd358b7474dbe630c044450e24e40db8cb1b98f4a66a09`.
- `xccdf_mil.disa.stig_rule_SV-204473r991589_rule` — `object_component`, independent.shellcommand.stdout_line; collected Item field contract is a singleton datatype. Source Rule SHA-256 `7baa6d7c7f9c452f9aa9f4a9a049ec63e27aebe9024b1a43f18013ce105702ea`.
- `xccdf_mil.disa.stig_rule_SV-230384r1017193_rule` — `object_component`, independent.shellcommand.stdout_line; collected Item field contract is a singleton datatype. Source Rule SHA-256 `b9f51e5d9d15f81705a5b0288b90582e27d5a7d55676b067ef8b697c16fc5194`.
- `xccdf_mil.disa.stig_rule_SV-244531r1017338_rule` — `object_component`, independent.shellcommand.stdout_line; collected Item field contract is a singleton datatype. Source Rule SHA-256 `95c39286d4b592487a9de48e5a06c53a73eb023fb13a5d056e10e14155b0f0c9`.

## Still-blocked Rule IDs

Grouped by actual collected Item contract:

### `independent.environmentvariable.value` — 4 Rules

Collected Item datatypes: `string, boolean, integer, float, binary, version, ipv4, ipv6, rpm_evr, debian_evr, fileset_revision, ios_version`; source declarations remain unchanged.

- `xccdf_mil.disa.stig_rule_SV-224861r991589_rule` (source datatype `string`, source Rule SHA-256 `bed6403938beacf8379061f97ee5585a95e813f0e044e113248ed60d018fa54c`)
- `xccdf_mil.disa.stig_rule_SV-205854r991589_rule` (source datatype `string`, source Rule SHA-256 `e93ff85d681e735464944034347b7a763f5d82bf63c55475d8681539f379ab5a`)
- `xccdf_mil.disa.stig_rule_SV-254280r991589_rule` (source datatype `string`, source Rule SHA-256 `f2b023b58112862ca76512fd5a0fbf91df509a459e67e57facb95eb42b787889`)
- `xccdf_mil.disa.stig_rule_SV-278028r1182265_rule` (source datatype `string`, source Rule SHA-256 `601cab34520b8eab72417a72261d932112869c66e98c503eafb1fb1bedbc43d8`)

### `independent.shellcommand.subexpression` — 13 Rules

Collected Item datatypes: `string, boolean, integer, float, binary, version, ipv4, ipv6, rpm_evr, debian_evr, fileset_revision, ios_version`; source declarations remain unchanged.

- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278382r1171898_rule` (source datatype `string`, source Rule SHA-256 `e90d477068bb1188958fc9e5fdc60d31d70c4e50a6f8283b29abc50433de92c2`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278383r1171901_rule` (source datatype `string`, source Rule SHA-256 `9a3737a0690be8108124f20c44e2118c38dfc960f84ae4ae6b16d766cdb21d77`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278385r1171907_rule` (source datatype `string`, source Rule SHA-256 `c2c8a3a555c949fa826e55d59d66f0c2c91399ff7e790ed951d08c9880434d00`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278386r1171910_rule` (source datatype `string`, source Rule SHA-256 `233a0bf2b2492989753680d103bf6c864f44a48b65dba4423daa35e3082e729f`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278387r1172701_rule` (source datatype `string`, source Rule SHA-256 `61a0f6823a7b86796b1403f39a769659db3255ddd6372f31e9c4d39f2f490ed2`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278388r1171916_rule` (source datatype `string`, source Rule SHA-256 `9dc19f9b84067d36a3e1fbce0baf13d1662a81e1e1d374f3eec5e40a814d8abf`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278392r1171928_rule` (source datatype `string`, source Rule SHA-256 `559f7f19cd49537bc4c5a3d36975ba35b9971f95454c4ccc8ca7098ac600791d`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278397r1171943_rule` (source datatype `string`, source Rule SHA-256 `152e0259f467a78e0ed6c50ffb5cc09bdb82016d413ef1447daf06a58aeddfd9`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278399r1172775_rule` (source datatype `string`, source Rule SHA-256 `a0e1ee7af2deebd4288c333916d38bff0afd8eb39cec2f0c2adcabb84511932e`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278408r1171976_rule` (source datatype `string`, source Rule SHA-256 `5f042ff6d1642d9cc5d65fa6bacef3412081a86d20a28d9ec77bbbfbaf7f1ff3`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259592r961095_rule` (source datatype `string`, source Rule SHA-256 `2439499bbbd173fbfcadc996fc17b8e1262a76e1ce69ccf8e7e52cee735fb50c`)
- `xccdf_mil.disa.stig_rule_SV-248526r958390_rule` (source datatype `string`, source Rule SHA-256 `5341ee494e77c4cf9eb676e63aa8511d2203d36e73cea1cc2cc5e80f2b8fe4da`)
- `xccdf_mil.disa.stig_rule_SV-230225r1184236_rule` (source datatype `string`, source Rule SHA-256 `165d29d2b485e3e1423c94fab8dd8a75c03a7e4094b6357ff153896244f1bc8c`)

### `independent.textfilecontent.subexpression` — 85 Rules

Collected Item datatypes: `string, boolean, integer, float, binary, version, ipv4, ipv6, rpm_evr, debian_evr, fileset_revision, ios_version`; source declarations remain unchanged.

- `xccdf_mil.disa.stig_rule_SV-274068r1120192_rule` (source datatype `string`, source Rule SHA-256 `476c67685e84a37381ebcf0c320f760299155041db81c32c484d5346d0a317a2`)
- `xccdf_mil.disa.stig_rule_SV-274108r1120312_rule` (source datatype `string`, source Rule SHA-256 `e41a60ec38623e52d9245abe6b2bea0ee2946b477f921acd8803d748fd4df558`)
- `xccdf_mil.disa.stig_rule_SV-274109r1120315_rule` (source datatype `string`, source Rule SHA-256 `d423747c1d4baf7e867d5eeebf625b436b77878fefa0c64fc18adf5d45366587`)
- `xccdf_mil.disa.stig_rule_SV-274110r1120318_rule` (source datatype `string`, source Rule SHA-256 `1d545cbadbd674313121587d1c9433a975bbcd9851c5c83f118a3a6ec2ef3dfe`)
- `xccdf_mil.disa.stig_rule_SV-274116r1120336_rule` (source datatype `string`, source Rule SHA-256 `581812af4c1eea421f6d591b012d8a176db2d22371df2051c04e29a60c50da26`)
- `xccdf_mil.disa.stig_rule_SV-274117r1120339_rule` (source datatype `string`, source Rule SHA-256 `cc9e4e5ce5e23c998286e901c68875e9e9bef3486cad59da63bb914f9c357735`)
- `xccdf_mil.disa.stig_rule_SV-274159r1120465_rule` (source datatype `int`, source Rule SHA-256 `80c662fd928461d681191124dce91ed9ebb4c30c7160a5359aae85ce25b7967b`)
- `xccdf_mil.disa.stig_rule_SV-219189r958566_rule` (source datatype `int`, source Rule SHA-256 `fbb1d7644179c035f89f6287a68bdf20df912022dfe0c35e830f4615834b8d7d`)
- `xccdf_mil.disa.stig_rule_SV-219192r958566_rule` (source datatype `int`, source Rule SHA-256 `8bc13610c9d5bc614bc1ba81d32e2ec4a4008976e233726f4fdf09f8945f7583`)
- `xccdf_mil.disa.stig_rule_SV-219193r958566_rule` (source datatype `int`, source Rule SHA-256 `047f25e41e81b0ce0feaf5d05d2ef30c4f5926f22a2577bac2770b7d83ce5d66`)
- `xccdf_mil.disa.stig_rule_SV-238338r958566_rule` (source datatype `int`, source Rule SHA-256 `2f97019163033c9fa39934b1a0d1939bb3e43245ff8c7f200e9f7169b03d9dd9`)
- `xccdf_mil.disa.stig_rule_SV-238341r958566_rule` (source datatype `int`, source Rule SHA-256 `f580b4b33ce80956df0b5cc5a8f992af65cdb8bf4e7259ee04796923a2f67286`)
- `xccdf_mil.disa.stig_rule_SV-238342r958566_rule` (source datatype `int`, source Rule SHA-256 `97eb3d330e26ceb38aacab39076bfa40e0fd7ce5848c45aca7993a3ec70c56a6`)
- `xccdf_mil.disa.stig_rule_SV-260502r1184054_rule` (source datatype `int`, source Rule SHA-256 `4c6f43b50b8e150ea11f19ae2650ccf5fe75244c12f9241e26a930da1a720e7c`)
- `xccdf_mil.disa.stig_rule_SV-260504r1184058_rule` (source datatype `int`, source Rule SHA-256 `fc5a73727dfcb94a29e521530c59a4887b7296f459ca86a91f0b8951de3a4aa1`)
- `xccdf_mil.disa.stig_rule_SV-260509r958566_rule` (source datatype `int`, source Rule SHA-256 `00a26972317d34d7155529f3b28ba4eac463062678dedee88a3806cc5b5339ed`)
- `xccdf_mil.disa.stig_rule_SV-260510r958566_rule` (source datatype `int`, source Rule SHA-256 `71f577227b49065794b01c5fc3d4d7115c09d028c7b9144eced4a5bd1ff83630`)
- `xccdf_mil.disa.stig_rule_SV-260511r958566_rule` (source datatype `int`, source Rule SHA-256 `10871ba09c64456c75c9314ebbf46c34519c146efe885b7bf63f4fc148b367bd`)
- `xccdf_mil.disa.stig_rule_SV-260597r958434_rule` (source datatype `string`, source Rule SHA-256 `91abc0ef5faf91792422c2d3da2698c5589892e80027111026913d0a6fec0cc8`)
- `xccdf_mil.disa.stig_rule_SV-260598r958434_rule` (source datatype `string`, source Rule SHA-256 `33baa22ae5f727f91d8686f4b832d9af1b1d0a27d6b033222c946174118c77f4`)
- `xccdf_mil.disa.stig_rule_SV-260600r958438_rule` (source datatype `string`, source Rule SHA-256 `bbad065683fe2ba4a4cfd36fe580263e6f9daec64a9d511f80c51dca2333ac7a`)
- `xccdf_mil.disa.stig_rule_SV-270761r1184074_rule` (source datatype `int`, source Rule SHA-256 `e56cdbdc154b5609ca3b980fcef8577c6fcdff86a3672c6a900f5d7c5f32131d`)
- `xccdf_mil.disa.stig_rule_SV-270762r1184076_rule` (source datatype `int`, source Rule SHA-256 `da5e3f043d2c6339e5bac9e8f18c3f882684825c6f17b21ed2f9049db2e9ae3d`)
- `xccdf_mil.disa.stig_rule_SV-270765r1066784_rule` (source datatype `int`, source Rule SHA-256 `82a2c002b53874ab538e5f981d6268964e5b8e5891f18cefbaf903b7deadfe1b`)
- `xccdf_mil.disa.stig_rule_SV-270768r1066793_rule` (source datatype `int`, source Rule SHA-256 `f97abf7b3994883b573a32dd6c5d10d2b2691c912812a5d6feb1cae7835f983d`)
- `xccdf_mil.disa.stig_rule_SV-270769r1066796_rule` (source datatype `int`, source Rule SHA-256 `86300a44e16e5f37192bd7edbef5caa04f35a082efbe6da8d73a3c0008da672d`)
- `xccdf_mil.disa.stig_rule_SV-270827r1066970_rule` (source datatype `string`, source Rule SHA-256 `c5af8a7b0ba3e5eeb2c01751b9836c6e9f18363e1e3cf6f0d4763aa104acfaea`)
- `xccdf_mil.disa.stig_rule_SV-270828r1066973_rule` (source datatype `string`, source Rule SHA-256 `d93d04625055899f2803b360552df0e62fb11d7a6fa118674c778151b352daf8`)
- `xccdf_mil.disa.stig_rule_SV-270829r1066976_rule` (source datatype `string`, source Rule SHA-256 `033fc027341ce72a340739bb9e5e0dee177975db5aa50bd463ca29babfb45759`)
- `xccdf_mil.disa.stig_rule_SV-270830r1068397_rule` (source datatype `string`, source Rule SHA-256 `06ea2caa0a2cb20f08967797cd7d5a69f8f8c3dec67cec42ceff879fa1e345a5`)
- `xccdf_mil.disa.stig_rule_SV-242403r986135_rule` (source datatype `string`, source Rule SHA-256 `51cce9cc8e675db746ef7ffd154246e82c19df417ab5c4154f6c03427045690b`)
- `xccdf_mil.disa.stig_rule_SV-242420r1043178_rule` (source datatype `string`, source Rule SHA-256 `e426e1480f7f9f053aad9d0ec97085cc67137874289613b5d4540027d28fb3d1`)
- `xccdf_mil.disa.stig_rule_SV-242445r961863_rule` (source datatype `int`, source Rule SHA-256 `7767b4439cb2da888a485481186ef7b714021afa634f67c9fed77ca4fab04b5f`)
- `xccdf_mil.disa.stig_rule_SV-242449r961863_rule` (source datatype `string`, source Rule SHA-256 `ac961d43aa9282a5f7452a7d6b675c516a609c511c2927d209791ce08d118c44`)
- `xccdf_mil.disa.stig_rule_SV-242450r961863_rule` (source datatype `string`, source Rule SHA-256 `7f933e97a03567b09496e852870ecbcda374ccec1d6ec58d934a6c3b42a325bb`)
- `xccdf_mil.disa.stig_rule_SV-242465r961863_rule` (source datatype `string`, source Rule SHA-256 `912104467d5b5fb2e5d7a67944deddf2d676c6decfbeb38bbaa4748c1ab0a3a7`)
- `xccdf_mil.disa.stig_rule_SV-221722r958482_rule` (source datatype `string`, source Rule SHA-256 `09b68f94c87cab7f1476130136c33cdb6432265a05dc9bd4d7e22d72ce912df2`)
- `xccdf_mil.disa.stig_rule_SV-221729r991589_rule` (source datatype `string`, source Rule SHA-256 `a5f6ae7b1ce1f951faa41ca828a465fb27b711d03155e1a33a1c54d475febe40`)
- `xccdf_mil.disa.stig_rule_SV-248610r991589_rule` (source datatype `string`, source Rule SHA-256 `b61fb32e58985aff05bf679f320a8171cfda152928d9c82c3d29fb029725b17a`)
- `xccdf_mil.disa.stig_rule_SV-248669r958388_rule` (source datatype `string`, source Rule SHA-256 `cc906439e12b8707b2cafc7349a7340b6da359962b0d5714685e687150c96f4c`)
- `xccdf_mil.disa.stig_rule_SV-248694r1015054_rule` (source datatype `string`, source Rule SHA-256 `3aeda8101ccbe2379cbdab2be00c02ecaeef2a92436894ac3e393a360a448a0c`)
- `xccdf_mil.disa.stig_rule_SV-248732r958434_rule` (source datatype `string`, source Rule SHA-256 `16daec66010eef40a36cffa1b84ce413371e7c4e3fa3bd23033f73ec1171d283`)
- `xccdf_mil.disa.stig_rule_SV-248733r958434_rule` (source datatype `string`, source Rule SHA-256 `094170ed1639c29cf434492669970d2ff8a76b71eaf7816b69b1e38ea70ee09f`)
- `xccdf_mil.disa.stig_rule_SV-248734r958434_rule` (source datatype `string`, source Rule SHA-256 `a9e0b5f4fa864baf16ce866118927395c2387a9fcdfe8211ee4ae15d757595d2`)
- `xccdf_mil.disa.stig_rule_SV-248735r958434_rule` (source datatype `string`, source Rule SHA-256 `1b5f184bcdd20d13adfa524e1c5023f68aab9d03a370054cef5f03685ebed1f5`)
- `xccdf_mil.disa.stig_rule_SV-248736r958434_rule` (source datatype `string`, source Rule SHA-256 `f0fda657ba528a5f53d61d023e95ed3ebb019a4b9af4cd808fdc1b49962504c6`)
- `xccdf_mil.disa.stig_rule_SV-248737r958434_rule` (source datatype `string`, source Rule SHA-256 `c32065ddb3890f646e05c4c9b16cbc51096636b9eb9a9a0795e6927d0aec01f2`)
- `xccdf_mil.disa.stig_rule_SV-271432r1091008_rule` (source datatype `string`, source Rule SHA-256 `b7a81cd81e7d6a5fe2e15439f4430d6fa11709e12e5d7ad91eb602c912b486ad`)
- `xccdf_mil.disa.stig_rule_SV-271583r1091461_rule` (source datatype `string`, source Rule SHA-256 `117bcbde7e244cac4b633e313d2c0d2e8333c9e6a304f7fd4f2d25bd2f268547`)
- `xccdf_mil.disa.stig_rule_SV-271584r1091464_rule` (source datatype `string`, source Rule SHA-256 `c30405ff6b5b9e5dfcecf66b7f599667455fef8cd4d60bf89bc34809b956ade4`)
- `xccdf_mil.disa.stig_rule_SV-271585r1091467_rule` (source datatype `string`, source Rule SHA-256 `9e7fc970180695b840849b5012eb5751c1abe054b6c0df0084aa5c0e1ab720cf`)
- `xccdf_mil.disa.stig_rule_SV-271630r1091602_rule` (source datatype `string`, source Rule SHA-256 `cc8de0fae7d3ea59c64eff57196c3f240002f757b7bef552ed42af4489eabc3f`)
- `xccdf_mil.disa.stig_rule_SV-271836r1092637_rule` (source datatype `string`, source Rule SHA-256 `b0bdd42e1cc514a7fbc09a9f4849be921c5c21a9d352dc5a3cd6fd567826ef9c`)
- `xccdf_mil.disa.stig_rule_SV-204461r958482_rule` (source datatype `string`, source Rule SHA-256 `8282138d42023f9d1a1dc3f9b108e8c9cc28e93d7c76b74f4ed70e05771153df`)
- `xccdf_mil.disa.stig_rule_SV-204468r991589_rule` (source datatype `string`, source Rule SHA-256 `c2733bbababe92b02c3bbd631d81476f9f0b4a47a050ebc5c05209fa49ac2946`)
- `xccdf_mil.disa.stig_rule_SV-204580r958390_rule` (source datatype `string`, source Rule SHA-256 `5597aed8bc0b876617d8cc1dc4ec21b54472e6b4c5e22e832defd77edd33c0e9`)
- `xccdf_mil.disa.stig_rule_SV-230294r1017105_rule` (source datatype `string`, source Rule SHA-256 `c4cc1412d160718f5616aa9ce3d078f8c8872f7440268e1d16bafdc64c695dfa`)
- `xccdf_mil.disa.stig_rule_SV-230364r1017176_rule` (source datatype `string`, source Rule SHA-256 `7ce2a36258aebd0dbd6c2941be1f509f4dcefe02d2e420dc663bd4f75e28c48e`)
- `xccdf_mil.disa.stig_rule_SV-230396r1017202_rule` (source datatype `string`, source Rule SHA-256 `f6565501c6fbd20ecfdac7ccee8f00d470349c5d2839cd4097c178a900fb2c4a`)
- `xccdf_mil.disa.stig_rule_SV-230397r1017203_rule` (source datatype `string`, source Rule SHA-256 `c9e6001cca13dc9e49a61c100b492f8cf62633ef57b7618e41527f3b3ed629e3`)
- `xccdf_mil.disa.stig_rule_SV-230398r1017204_rule` (source datatype `string`, source Rule SHA-256 `9f23c4453103f17ea796da1cfaf29ae78a4f71855548096ce28e8275c4241b55`)
- `xccdf_mil.disa.stig_rule_SV-230399r1017205_rule` (source datatype `string`, source Rule SHA-256 `0eff6183b2dbfc293b444674e192a71c455dc80f7fd35acfdfd52c29b6de4e30`)
- `xccdf_mil.disa.stig_rule_SV-230400r1017206_rule` (source datatype `string`, source Rule SHA-256 `b6fb65dfcd7a0c111225e424b24d3a1c9ab084c7299f1b903b67369b77a51b5a`)
- `xccdf_mil.disa.stig_rule_SV-230401r1017207_rule` (source datatype `string`, source Rule SHA-256 `406c86fddecbecc50ed2bd1bf57ccb53954766e0ece271d47484ae11f4005feb`)
- `xccdf_mil.disa.stig_rule_SV-250315r1017356_rule` (source datatype `string`, source Rule SHA-256 `4e18c313c0af0a4b203d3c8b7fadb83462ee673c0dd69d5f9536f6871385b2df`)
- `xccdf_mil.disa.stig_rule_SV-257847r1044924_rule` (source datatype `string`, source Rule SHA-256 `08f563d67db7e72d3dde2ec62577c37462b6a20f1f5029a4bcfc80870638513c`)
- `xccdf_mil.disa.stig_rule_SV-258080r1045162_rule` (source datatype `string`, source Rule SHA-256 `07fd1685f7b63456f89d75a25bcda2b0ecffd81667cdd3f5d2989e296d9db9fd`)
- `xccdf_mil.disa.stig_rule_SV-258105r1045212_rule` (source datatype `string`, source Rule SHA-256 `ea8668856c6af74a315484f29f87f9e56726dc6881849d0ee4276b673d89c637`)
- `xccdf_mil.disa.stig_rule_SV-258165r958434_rule` (source datatype `string`, source Rule SHA-256 `300dd3347386f7cbe28d6e63064b808a3371e49e17bfe27aaec8c9a654b0e101`)
- `xccdf_mil.disa.stig_rule_SV-258166r1045303_rule` (source datatype `string`, source Rule SHA-256 `d7f7c318bf5e260425458e45faec3ed1e3a47749e9810ba2d4de0bd15d68527a`)
- `xccdf_mil.disa.stig_rule_SV-258167r1155630_rule` (source datatype `string`, source Rule SHA-256 `3642e62a95f5daa236ef67545ae0290d5065ef1475e4594a36ab59e85f24e995`)
- `xccdf_mil.disa.stig_rule_SV-217173r1184441_rule` (source datatype `string`, source Rule SHA-256 `a6fea4316f84aa62569292ea4b1dc0a76a56eb7740524daff0cd9cd2dfb602b9`)
- `xccdf_mil.disa.stig_rule_SV-234993r1184474_rule` (source datatype `string`, source Rule SHA-256 `f90835cf65ce197d491625033af3b1ccbecbf15a3ac2f7986a69e2f30c248726`)
- `xccdf_mil.disa.stig_rule_SV-216358r959010_rule` (source datatype `string`, source Rule SHA-256 `457ae02e69a5ed090bb8fa097e7493c41c5787a237ffd37bc4a34cd00aefd9a0`)
- `xccdf_mil.disa.stig_rule_SV-216422r959010_rule` (source datatype `int`, source Rule SHA-256 `cc84b0eed69476c99afd216fbccd0c20eae3c165b11b354effd7c8a95fcbc2d7`)
- `xccdf_mil.disa.stig_rule_SV-216475r959010_rule` (source datatype `string`, source Rule SHA-256 `1613b9f26ad946ac9b3cf420d006026c0efeb9d2ed4388f2672d0f04c17a1c9d`)
- `xccdf_mil.disa.stig_rule_SV-216121r959010_rule` (source datatype `string`, source Rule SHA-256 `ed146d598be12e1e2052f19b1c266519daba416267da048df3552b5f919efc2b`)
- `xccdf_mil.disa.stig_rule_SV-216185r959010_rule` (source datatype `int`, source Rule SHA-256 `d0e139f018b4666418ab8d816efec4a6b7df0f216e94081a7a7112c06506df20`)
- `xccdf_mil.disa.stig_rule_SV-216239r959010_rule` (source datatype `string`, source Rule SHA-256 `ff8530c045133447fc60e0c319a1ebb6b87a2d0be5045cfe0b8e8ee78d4a5da8`)
- `xccdf_mil.disa.stig_rule_SV-252977r958434_rule` (source datatype `string`, source Rule SHA-256 `bec17ad4f7529775b31707f66fda840a889adba4fc806dea491e8180794bdb43`)
- `xccdf_mil.disa.stig_rule_SV-252978r958434_rule` (source datatype `string`, source Rule SHA-256 `c811c74cc273fe33e93f4d4cffe5701565948a24d54df6e5589365f31251a1d5`)
- `xccdf_mil.disa.stig_rule_SV-252979r958434_rule` (source datatype `string`, source Rule SHA-256 `f29681c430448712d2d991a95937db09ee65aee233c482a05695ac094c335137`)
- `xccdf_mil.disa.stig_rule_SV-252980r958434_rule` (source datatype `string`, source Rule SHA-256 `e9d506f92423863a3b5c165e4d517dd960b9cba0dd7510cd8944062e5234b526`)
- `xccdf_mil.disa.stig_rule_SV-252981r958434_rule` (source datatype `string`, source Rule SHA-256 `31ce403fc2a3266004d4ee7d04a3b4cf788b8fd907de4d2d7d5710ac046f65d5`)
- `xccdf_mil.disa.stig_rule_SV-252982r958434_rule` (source datatype `string`, source Rule SHA-256 `1cc46c95637f67fdc3250ac13bfec857f8f8dd9de22dc6d32f4e2239fa41db8a`)

### `windows.registry.value` — 6 Rules

Collected Item datatypes: `string, integer, binary, version`; source declarations remain unchanged.

- `xccdf_mil.disa.fso_rule_SV-284958r1208187_rule` (source datatype `string`, source Rule SHA-256 `190e1df45c6cc13d62911da471dd166c0a040adb5463b7d97b9dcf899a4101a6`)
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214429r879717_rule` (source datatype `string`, source Rule SHA-256 `8a8e3cb73eb4090006b3387446876dcc177b559d1a70525d0b9236508a16cc18`)
- `xccdf_mil.disa.stig_rule_SV-224970r958726_rule` (source datatype `string`, source Rule SHA-256 `b85526fae2ef9434c6c9c54e31fffe318def1a944657d776e3ec369ae8ab9395`)
- `xccdf_mil.disa.stig_rule_SV-205739r958726_rule` (source datatype `string`, source Rule SHA-256 `0a5447a9c45ef8a9f4dff6b3b7b2880e90eab883fa168e7db00ebe1ba9e295c0`)
- `xccdf_mil.disa.stig_rule_SV-254391r958726_rule` (source datatype `string`, source Rule SHA-256 `130f8c19673fd4100ff0081db6324524e2b1cabb0cdafb3152b3a46e2a92e907`)
- `xccdf_mil.disa.stig_rule_SV-278138r1182081_rule` (source datatype `string`, source Rule SHA-256 `5f194b14219d8fec22dd8731ce34dba2fd7491b1ceb1d3f96a04c6e0e79222e9`)

## Classification columns

The JSON companion retains source benchmark/name, source Rule hash, source local-Variable ID and XML hash, source datatype, expression, consumer operation/datatype, source Object/field, collected Item datatypes, State comparator datatypes, disposition, and proof boundary.
