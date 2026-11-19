# Current macOS/iOS OVAL witness conversion (diagnostic)

These are source-witness authoring results only. No macOS/iOS runtime or
independent equivalence is claimed.

Pins: Self-Assertion `e3538595c5083b9c34d937a81d319234df9bbfaa`, converter
`bcae834`, canonical schema `5ee55288b369da26f308f40813e545b78dff2753`, flat
schema family `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`.

## macOS

- 43 Tests considered; 12 converted; 31 blocked
- 30 unsupported macOS capabilities
- 1 bounded Variable-cast failure
- Receipt: `/tmp/tools-issue83-current-conversion-macos-final-1795108664/receipt.json`
- SHA-256: `36bfbaef556b4174bada3e9c3368473ba2362629912e5bbc04a98f194105b40d`

## iOS

- 16 Tests considered; 0 converted; 16 explicitly unsupported iOS capabilities
- Receipt: `/tmp/tools-issue83-current-conversion-ios-final-1795108664/receipt.json`
- SHA-256: `239863d97ace5084cea3b163b71e915bb6f46d4ec1976feaa15ea4f62fea2340`

These platforms remain diagnostic scope and were not relabeled as converter
successes or runtime support.
