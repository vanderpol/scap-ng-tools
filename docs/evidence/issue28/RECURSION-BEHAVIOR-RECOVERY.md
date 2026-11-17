# Recursion behavior recovery

This is primarily a converter boundary issue, not a missing traversal language.
The native file traversal contract already supports bounded downward recursion.
The converter currently tests for the literal native key `equals`; some source
selectors use typed equality (`case insensitive equals`) and are consequently
misclassified as pattern paths.

Representative .NET Framework `SV-225229` source:

```xml
<windows:file_object
    id="oval:navy.navwar.niwcatlantic.scc.dotnet:obj:22522901"
    version="15">
  <windows:behaviors max_depth="2" recurse_direction="down"/>
  <windows:path datatype="string"
      operation="case insensitive equals"
      var_ref="oval:navy.navwar.niwcatlantic.scc.dotnet:var:22522901"
      var_check="at least one"/>
  <windows:filename datatype="string"
      operation="case insensitive equals">Mscorlib.dll</windows:filename>
</windows:file_object>
```

The fix should recognize only equality forms proven equivalent for the
capability's path lookup. Pattern selectors must continue to reject recursion
attributes, and upward/deprecated recursion must remain blocked.
