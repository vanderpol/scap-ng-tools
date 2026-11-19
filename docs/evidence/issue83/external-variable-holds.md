# External Variable canonical-input holds

This receipt joins the 18 agnostic converter holds to exact source OVAL
Variable definitions and the Object/Test reference closure. It does not alter
source content or treat an input-contract hold as a converter success.

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Converter receipt: `/tmp/tools-issue83-current-conversion-agnostic-final-1795107293/receipt.json`
- Converter receipt SHA-256: `5973ca6e8db5aabbf97b2479321b744792846365c849f779fa6b0c3a5ceddc6b`
- Hold audit: `/tmp/tools-issue83-external-holds-1795108835.json`
- Hold audit SHA-256: `6148ddd722af60e8ce37be732e61b16ef4ba33e405ace762fbaf958090ae427e`

Measured disposition:

- 18 blocked source Tests
- 18 unique external Variables referenced through source Object/Test closure
- 3 authored `possible_restriction` rows across the source Variables
- Failure class: `canonical_input_constraint_hold`

The 18 holds are not all authored pattern restrictions: the current converter
also requires a bound external input for unrestricted external Variables. The
canonical 0.4.1 input contract and owner-approved binding semantics therefore
remain the required next decision; no implicit defaults or consumer-side
coercions were introduced.
