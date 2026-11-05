# Actual source XML samples for remaining blocker categories

The snippets below are copied from the pinned Q3 2026 source ZIPs listed in the
ledger. Namespace prefixes may differ from the original serialization; element
names, attributes, values, and IDs are unchanged. They are examples of source
shapes, not generated native syntax.

## Deprecated OVAL Tests: access-token and legacy WMI

Access-token source (`SV-220956`, Windows 10):

```xml
<windows:accesstoken_test id="oval:mil.disa.stig.win:tst:25347900"
    version="2" check="all" comment="Access Credential Manager as a trusted caller - None">
  <windows:object object_ref="oval:mil.disa.stig.win:obj:20000008"/>
  <windows:state state_ref="oval:mil.disa.stig.win:ste:25347900"/>
</windows:accesstoken_test>
```

Legacy `wmi_*` source (`SV-226065`, Windows Server 2012 DC):

```xml
<windows:wmi_object id="oval:mil.disa.fso.windows:obj:469600"
    version="1" comment="Kerberos Policy - Enforce user logon restrictions">
  <windows:namespace datatype="string">root\rsop\computer</windows:namespace>
  <windows:wql datatype="string">SELECT setting FROM RSOP_SecuritySettingBoolean WHERE KeyName='TicketValidateClient'</windows:wql>
</windows:wmi_object>
<windows:wmi_state id="oval:mil.disa.fso.windows:ste:469600" version="1">
  <windows:result datatype="int">-1</windows:result>
</windows:wmi_state>
```

By contrast, WMI57 is a supported source form:

```xml
<windows:wmi57_test id="oval:mil.disa.fso.dotnet:tst:1601"
    version="1" check_existence="at_least_one_exists" check="all">
  <windows:object object_ref="oval:mil.disa.fso.dotnet:obj:1601"/>
  <windows:state state_ref="oval:mil.disa.fso.dotnet:ste:1601"/>
</windows:wmi57_test>
```

## `count` function — mapping missing, not a language gap

Amazon Linux 2023 `SV-274160`:

```xml
<oval:local_variable id="oval:mil.disa.stig.defs:var:25804500"
    version="1" datatype="int">
  <oval:count>
    <oval:object_component object_ref="oval:mil.disa.stig.unix:obj:25804500"
        item_field="user_id"/>
  </oval:count>
</oval:local_variable>
```

## XCCDF Value operator / check-export adapter

Windows Server 2012 DC `SV-226057`:

```xml
<xccdf:Value id="xccdf_mil.disa.stig_value_account_lockout_threshold_var"
    type="number" operator="less than or equal">
  <xccdf:value>3</xccdf:value>
  <xccdf:value selector="3_attempts">3</xccdf:value>
</xccdf:Value>

<xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <xccdf:check-export value-id="xccdf_mil.disa.stig_value_account_lockout_threshold_var"
      export-name="oval:mil.disa.fso.windows:var:442300"/>
  <xccdf:check-content-ref name="oval:mil.disa.fso.windows:def:4423"
      href="U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-oval.xml"/>
</xccdf:check>
```

## Multi-component aggregation

Firefox Linux `SV-251546`:

```xml
<oval:local_variable id="oval:mil.disa.stig.firefox.linux:var:1"
    version="1" datatype="string">
  <oval:unique>
    <oval:literal_component>/etc/firefox/policies</oval:literal_component>
    <oval:concat>
      <oval:object_component object_ref="oval:mil.disa.stig.firefox.linux:obj:1"
          item_field="path"/>
      <oval:literal_component>/distribution</oval:literal_component>
    </oval:concat>
  </oval:unique>
</oval:local_variable>
```

## Native identity collision

Office 365 `SV-223296` contains two distinct source Tests with identical
human comments:

```xml
<windows:registry_test id="oval:mil.disa.stig.sharepointdesigner2013:tst:1"
    version="1" check_existence="at_least_one_exists" check="all"
    comment="Check if the SharePoint Designer 2013 key is present">
  <windows:object object_ref="oval:mil.disa.stig.sharepointdesigner2013:obj:1"/>
</windows:registry_test>
<windows:registry_test id="oval:mil.disa.stig.sharepointdesigner2013:tst:2"
    version="1" check_existence="at_least_one_exists" check="all"
    comment="Check if the SharePoint Designer 2013 key is present">
  <windows:object object_ref="oval:mil.disa.stig.sharepointdesigner2013:obj:2"/>
</windows:registry_test>
```

## Invalid nil selector datatype

The source shape is a nil selector; the datatype is part of the semantic
contract and cannot be inferred:

```xml
<unix:filename xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:nil="true" datatype="string"/>
```

## Ordered comparison requiring an incompatible source datatype

A source ordered comparison carries an explicit non-integer datatype:

```xml
<windows:version datatype="version" operation="greater than or equal">25</windows:version>
```

## Invalid pattern-path recursion attributes

.NET Framework source file object behavior:

```xml
<windows:behaviors max_depth="-1" recurse_direction="down"/>
```

The native traversal contract must determine whether this source combination
is representable; it must not silently normalize it.

## Comparator-bearing absence

SLES 12 source state entity:

```xml
<independent:stderr_line check_existence="none_exist"
    operation="pattern match">.*</independent:stderr_line>
```

This combines an existence absence operator with a comparator, which requires an
explicit native semantic contract rather than a Boolean shortcut.
