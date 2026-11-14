# `xsi:nil` selector recovery

This is a converter limitation. The existing `windows.cmdlet` capability mapping
already declares `module_id`, `module_version`, `parameters`, and `select` as
nullable and defines the native meaning of null. No new language construct is
needed.

The recovery should lower source `xsi:nil="true"` to the existing native null
contract, while keeping it distinct from an empty string, omitted selector, and
literal null result. Required regression cases are null, empty, non-null, wrong
datatype, and nested record selectors. The current failure affects 11 primary
Rules, including Windows 10 `SV-220698`.
