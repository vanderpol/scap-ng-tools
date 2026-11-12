# Legacy OVAL WMI recovery

The pinned OVAL 5.12.3 corpus has 15 active legacy-WMI Rules: 14 using
`windows:wmi_object` and one using `windows:wmi_test`. A further 12 legacy-WMI
Rules occur only in the owner-excluded Windows Server 2012/2012 R2 benchmarks.
`windows:wmi57_*` remains the supported native WMI family and is tracked
separately.

## Original source XML

The directly recoverable shape is a single named WQL projection and a scalar
legacy State:

```xml
<windows:wmi_object
    id="oval:mil.disa.stig.windows:obj:8200"
    version="1">
  <windows:namespace>root\cimv2</windows:namespace>
  <windows:wql>SELECT DomainRole FROM Win32_ComputerSystem</windows:wql>
</windows:wmi_object>

<windows:wmi_state id="oval:mil.disa.stig.windows:ste:8200" version="1">
  <windows:result datatype="int">0</windows:result>
</windows:wmi_state>

<windows:wmi_test id="oval:mil.disa.stig.windows:tst:8200" version="1"
                  check="all" check_existence="at_least_one_exists">
  <windows:object object_ref="oval:mil.disa.stig.windows:obj:8200"/>
  <windows:state state_ref="oval:mil.disa.stig.windows:ste:8200"/>
</windows:wmi_test>
```

The source query, namespace, selected field, State datatype/comparator, source
IDs, and object/test hashes are preserved in the migration warning.

## Native candidate

For `SV-224921` the generated native Test is:

```yaml
tests:
  domainrole-is-0-test:
    capability: windows.wmi.query
    object:
      namespace: 'root\\cimv2'
      query: 'SELECT DomainRole FROM Win32_ComputerSystem'
    require:
      item_requirement:
        items_found: one_or_more
      fields:
        result:
          record:
            records_found: one_or_more
            records_matching: every
            fields:
              DomainRole: {equals: 0}
```

The migration is opt-in (`native_recovery`) and accepts only one simple named
`SELECT field FROM ...` projection. `SELECT *`, multiple projections,
expressions, malformed WQL, nested scalar results, and unsupported State
cardinality are rejected. The native WMI result remains a record; no scalar
`result` flattening is fabricated.

## Results

- 15 active legacy-WMI capabilities are migrated to the existing
  `windows.wmi.query` record contract.
- One Rule (`SV-224921`) becomes automated converted/unproved.
- Fourteen Rules remain blocked because their WMI record is consumed through
  scalar Variable/function or Set/Filter shapes not represented by the 0.4
  grammar. Representative Rules are `SV-225230`, `SV-225232`, `SV-225234`,
  `SV-225235`, `SV-259637`, and `SV-218752`.
- These 14 are not declared WMI capability failures after migration; they are
  downstream record projection/function or Set-shape gaps. The active ledger
  records them as blocked and preserves the raw diagnostics.

The direct WMI shape has conversion and schema-validation coverage, plus
fail-closed parser tests. No provider execution or independent OVAL/scanner
semantic proof is claimed.
