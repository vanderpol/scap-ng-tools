# Native identity collision recovery

This is a converter identity bug, not a semantic capability gap. The current
readable native name is derived primarily from an OVAL comment. Two distinct
source nodes can therefore produce the same native identifier.

Office 365 `SV-223296` contains:

```xml
<windows:registry_test
    id="oval:mil.disa.stig.sharepointdesigner2013:tst:1"
    version="1" check_existence="at_least_one_exists" check="all"
    comment="Check if the SharePoint Designer 2013 key is present">
  <windows:object object_ref="oval:mil.disa.stig.sharepointdesigner2013:obj:1"/>
</windows:registry_test>
<windows:registry_test
    id="oval:mil.disa.stig.sharepointdesigner2013:tst:2"
    version="1" check_existence="at_least_one_exists" check="all"
    comment="Check if the SharePoint Designer 2013 key is present">
  <windows:object object_ref="oval:mil.disa.stig.sharepointdesigner2013:obj:2"/>
</windows:registry_test>
```

Both comments currently suggest the same name, such as
`check-if-the-sharepoint-designer-2013-key-is-present-test`, although their
source IDs and Objects differ. The fix must add a deterministic source-identity
discriminator (or a stable source-ID digest) while retaining the original ID in
provenance and respecting the 64-character native-name limit. It must not merge,
renumber, or silently select one source node.
