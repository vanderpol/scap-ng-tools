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

## Native traversal contract admission

DotNet Framework `SV-225223` uses a Registry Object whose key is an exact
lookup, whose value name is a pattern, and whose behaviors request downward
recursion. The source shape is preserved here; the source Rule ID is retained in the
ledger (`xccdf_mil.disa.fso_rule_SV-225223r961038_rule`):

```xml
<windows:registry_object>
  <windows:hive datatype="string">HKEY_LOCAL_MACHINE</windows:hive>
  <windows:key datatype="string" operation="equals">Software\Microsoft\StrongName\Verification</windows:key>
  <windows:name datatype="string" operation="pattern match">.*</windows:name>
  <windows:behaviors max_depth="-1" recurse_direction="down"/>
</windows:registry_object>
```

The converter preserves the exact key/name/traversal intent, but the pinned
native Registry Object schema admits no traversal member. Removing traversal
would change the population, so this Rule remains blocked pending coordinated
schema/compiler/runtime support.

## Deprecated RPM `md5_differs` State

Oracle Linux 7 `SV-221653` reaches this deprecated State shape (the source
Rule/Test closure is retained in the inventory):

```xml
<linux:rpmverifyfile_state
    id="oval:mil.disa.stig.ol7:ste:3860" operator="AND">
  <linux:md5_differs>fail</linux:md5_differs>
</linux:rpmverifyfile_state>
```

The approved mapping uses `filedigest_differs`; inventing a replacement for
this deprecated RPM field would change the source contract, so the two Rules
remain intentionally unsupported.

## Unsupported Windows `user_*` capability

Windows 10 `SV-220952` contains a genuine OVAL User Test, not a WMI57 Test:

```xml
<windows:user_test
    id="oval:navy.navwar.niwcatlantic.scc.windows:tst:22095201"
    check_existence="any_exist" check="all">
  <windows:object object_ref="oval:navy.navwar.niwcatlantic.scc.windows:obj:22095201"/>
  <windows:state state_ref="oval:navy.navwar.niwcatlantic.scc.windows:ste:22095201"/>
</windows:user_test>
```

The current 0.4 contract has `windows.user_sid` and related capabilities, but
no approved `windows.user` mapping preserving this User Object/State
population and semantics. No SID-only equivalent is fabricated.

## XCCDF string Value to OVAL binary Variable mismatch

Windows Server 2012 `SV-226276` exports a string XCCDF Value to a binary OVAL
external Variable:

```xml
<xccdf:Value id="xccdf_mil.disa.stig_value_audit_use_backup_restore_privilege_var"
    type="string" operator="equals">
  <xccdf:value>00</xccdf:value>
  <xccdf:value selector="disabled">00</xccdf:value>
  <xccdf:value selector="enabled">01</xccdf:value>
</xccdf:Value>
<oval:external_variable id="oval:mil.disa.fso.windows:var:454400"
    datatype="binary">
  <oval:possible_value hint="disabled">00</oval:possible_value>
  <oval:possible_value hint="enabled">01</oval:possible_value>
</oval:external_variable>
```

The converter preserves both source datatypes and blocks the binding; it does
not silently reinterpret lexical text as binary.

## Declared/derived Variable datatype mismatch

IIS 10.0 Site `SV-218762` declares an integer Variable whose concatenated
regex captures derive strings:

```xml
<oval:local_variable id="oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:var:21876201"
    datatype="int">
  <oval:concat>
    <oval:regex_capture pattern="(\d\d):\d\d:\d\d">
      <oval:object_component object_ref="oval:...:obj:21876202"
          item_field="result"/>
    </oval:regex_capture>
    <oval:regex_capture pattern="\d\d:(\d\d):\d\d">
      <oval:object_component object_ref="oval:...:obj:21876202"
          item_field="result"/>
    </oval:regex_capture>
  </oval:concat>
</oval:local_variable>
```

No numeric cast is inferred. A faithful native contract needs explicit cast
and lexical-error propagation semantics.

## Variable cast at an acquisition boundary

IIS 10.0 Server `SV-218814` passes a derived integer-declared Variable to a
string shell-command acquisition:

```xml
<independent:shellcommand_object
    id="oval:navy.navwar.niwcatlantic.scc.ms.iis.10.0.server:obj:21881401">
  <independent:shell>powershell</independent:shell>
  <independent:command
      var_ref="oval:navy.navwar.niwcatlantic.scc.ms.iis.10.0.server:var:21881401"/>
  <independent:pattern/>
</independent:shellcommand_object>
```

The source Variable expression is string-producing while declared `int`; the
converter rejects the acquisition cast rather than inserting a coercion.

## Assessment Input function composition

Oracle Linux 7 `SV-221718` exports an organizational Value and then uses it
inside OVAL `substring` Variables:

```xml
<xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <xccdf:check-export value-id="xccdf_mil.disa.stig_value_var_accounts_user_umask"
      export-name="oval:mil.disa.stig.ol7:var:4211"/>
  <xccdf:check-content-ref name="oval:mil.disa.stig.ol7:def:518"/>
</xccdf:check>
<oval:local_variable id="oval:mil.disa.stig.ol7:var:4212" datatype="int">
  <oval:substring substring_start="1" substring_length="1">
    <oval:variable_component var_ref="oval:mil.disa.stig.ol7:var:4211"/>
  </oval:substring>
</oval:local_variable>
```

The current native Input contract cannot be an operand of a composed Variable
expression. Direct typed Input binding is preserved; composed Input remains a
genuine language-contract gap.

## IIS/NGINX capability mismatch

F5 NGINX `SV-278400` contains a Unix `file_test` whose referenced Object and
State are independent `shellcommand` nodes:

```xml
<unix:file_test id="oval:navy.navwar.niwcatlantic.scc.nginx:tst:27840004"
    check_existence="at_least_one_exists" check="all">
  <unix:object object_ref="oval:...:obj:27840004"/>
  <unix:state state_ref="oval:...:ste:27840004"/>
</unix:file_test>
<independent:shellcommand_object id="oval:...:obj:27840004">
  <independent:shell>bash</independent:shell>
  <independent:command var_ref="oval:...:var:27840001"/>
</independent:shellcommand_object>
<independent:shellcommand_state id="oval:...:ste:27840004">
  <independent:subexpression operation="pattern match">\S+</independent:subexpression>
</independent:shellcommand_state>
```

The family/capability mismatch is source-specific; mapping it to an unrelated
native collector would change the evidence population.
