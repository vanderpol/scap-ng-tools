# Standalone OVAL operation-directed rebuild

- Canonical schema: `aece827964c785be77b088c3c61255a2d07fd9a9`; digest `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`.
- OVAL source: `e3538595c5083b9c34d937a81d319234df9bbfaa`; 144 files / 168 Definitions / 803 Tests.
- Current production candidate: **97 converted Definitions / 69 blocked / 2 excluded; 506 converted Tests / 295 blocked / 2 excluded**.
- Manifest SHA-256: `1d1725351dffbb057b82c7825979253ca58f336bf887e5c7d5e0687d25e87618`.
- Parity receipt SHA-256: `30e85e46457a65ceb5c4ed3758c846a0a1e8cd510c03cc348bf2ea67e7dfc608`.

The source accounting gate passes and all 803 Tests are dispositioned. Independent parity remains **FAIL/HOLD** with 55 `converted_parity_failure` findings. Execution and scanner/RI equivalence were not performed or claimed. The previous receipt remains unchanged at `oval-accounting-datatype-recovery.json`.

Exact file hashes are in `oval-accounting-operation-directed.json`.
