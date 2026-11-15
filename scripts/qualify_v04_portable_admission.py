#!/usr/bin/env python3
"""Run the complete read-only Issue #5 portable-admission qualification.

This command deliberately keeps generated documents in memory.  It verifies the
four signed acceptance fixtures, the flat schema snapshot, the inventory trace,
and the CONVERTED_UNVERIFIED automatic-admission result without writing a
corpus or making a proof/runtime-equivalence claim.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from time import monotonic

# Keep these pins local to the qualification command so it is usable without
# importing the test suite.  They are also recorded in TEST-FIXTURE-PINS.md.
FIXTURES = (
    {
        "name": "Windows Server 2025",
        "filenames": (
            "U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip",
            "server2025-signed.zip",
        ),
        "sha256": "2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0",
        "source_rules": 291,
        "converted": 247,
        "blocked": 44,
        "native_documents": 496,
        "documents_sha256": "5687a4919b66e4e38e9d9dc2f59131393cf9683b0af768caf0ca4c3fa72deca8",
        "trace_sha256": "28ccb0600d666f99b76b36164776a7b442276ef8282f614d87b28c470dcf95d4",
        "coverage_sha256": "233fa961e84f101107cb62c5b810aa4719309c8bb5c31bbe2e212a09676c5bf4",
        "inventory_trace_sha256": "0558217d6c90a39bf7f0e9b9bf8f8235f391df4152be639968ac1d3e132f41ff",
        "inventory_sha256": "b8e006eceeaca1d1e669e88d2f9336ea3ad165323409a2ff49f80e0641e9b238",
    },
    {
        "name": "Active Directory Domain",
        "filenames": ("U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip",),
        "sha256": "94740b7929dd868043ab1b476c3b568712fc26d045a4d450359cea90effbfa1c",
        "source_rules": 36,
        "converted": 15,
        "blocked": 21,
        "native_documents": 32,
        "documents_sha256": "69d6606cf3b8c1e5ae943b5282ecf35a258556e5ce305b5ac1f4f9e1aa3bb10b",
        "trace_sha256": "450aadbc110a26934a5688aefbed0c86e0e967ead6e1041cbc376e858f7dee64",
        "coverage_sha256": "f90aacf66975f5d3cadf4d1d941142ad2a40f8c6a4c682eab491e15b2e604a53",
        "inventory_trace_sha256": "a904fa7e88ff40bdea90825aac5d8b102a28fbd89d24b7c43b78aebe3b790824",
        "inventory_sha256": "9335f772f3cc5a1952c46d66b1087f17dbd2105ce975b4f9156f29fc96d8d719",
    },
    {
        "name": "Amazon Linux 2023",
        "filenames": ("U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip",),
        "sha256": "88cc35f98c9ff96c567110c284c06e6adfc556fd59967019bdec6fd1cc5a204f",
        "source_rules": 187,
        "converted": 118,
        "blocked": 69,
        "native_documents": 238,
        "documents_sha256": "7a9a7b578bf6f7f3498e58369f64340c719f7b50e5a376058974aefa20f6db4d",
        "trace_sha256": "09d77b842843d3cab5b3dd4e9e28af253799ac3878608cd65239dc47a8d880e2",
        "coverage_sha256": "da41d34d4c1b307097cb55c93e700e4bfa3f85950485c189d6f2f22a9f67a375",
        "inventory_trace_sha256": "af1acfc9a2a7454153f629e2e1a88823f794bfa99e5cc4b4aef2cba980c7f4e1",
        "inventory_sha256": "6b3cdccfda5097f549f7372ae95c661f88b03d2097e9ebce366c4d99e31d0823",
    },
    {
        "name": "Windows Defender Firewall",
        "filenames": ("U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip",),
        "sha256": "d16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca",
        "source_rules": 21,
        "converted": 0,
        "blocked": 21,
        "native_documents": 0,
        "documents_sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        "trace_sha256": "fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc",
        "coverage_sha256": "5e70d08b2503940e2f486529164f65108c9a3a101a358ba2d0e37f16287d8d0d",
        "inventory_trace_sha256": "fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc",
        "inventory_sha256": "f0ba480d3e3d2c61600e68cc1e34daecfc8fe90804912bde5b4484f4440921b4",
    },
)


def stable_digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


def git_value(path: Path, *args: str) -> str | None:
    try:
        return subprocess.check_output(("git", "-C", str(path), *args), text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def git_commit_for_snapshot(path: Path) -> str | None:
    # Accept either a canonical checkout or its flat schema/ child.
    for candidate in (path, path.parent):
        value = git_value(candidate, "rev-parse", "HEAD")
        if value:
            return value
    return None


def find_fixture(root: Path, pin: dict) -> Path:
    matches = [root / name for name in pin["filenames"] if (root / name).is_file()]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one pinned fixture for {pin['name']}; "
            f"found {[str(p) for p in matches]}"
        )
    return matches[0]


def qualify(schema_root: Path, fixture_root: Path) -> dict:
    # Import only after argument parsing, so --help and missing-input failures
    # do not require the converter's optional validation dependencies.
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    from scap_ng_tools.converter import convert_benchmark, inventory_benchmark

    snapshot = FrozenSchemaSnapshot(schema_root)
    report = {
        "format": "scap-ng-tools/issue5-portable-admission-qualification/1",
        "schema": snapshot.manifest(),
        "schema_commit": git_commit_for_snapshot(schema_root),
        "tools_commit": git_value(Path(__file__).resolve().parents[1], "rev-parse", "HEAD"),
        "fixtures": [],
        "totals": {"source_rules": 0, "converted": 0, "blocked": 0, "native_documents": 0},
        "claims": {
            "conversion_status": "CONVERTED_UNVERIFIED",
            "independent_semantic_proof": False,
            "scanner_execution": False,
            "runtime_equivalence": False,
        },
    }
    started = monotonic()
    for pin in FIXTURES:
        source = find_fixture(fixture_root, pin)
        actual_sha = sha256(source.read_bytes()).hexdigest()
        if actual_sha != pin["sha256"]:
            raise SystemExit(f"{source}: SHA-256 {actual_sha} != pinned {pin['sha256']}")
        fixture_started = monotonic()
        inventory_trace, inventory = inventory_benchmark(
            schema_root=schema_root, source=source, sha256_pin=pin["sha256"]
        )
        documents, trace, coverage = convert_benchmark(
            schema_root=schema_root, source=source, sha256_pin=pin["sha256"]
        )
        if stable_digest(inventory_trace) != pin["inventory_trace_sha256"]:
            raise SystemExit(f"{source}: inventory trace digest mismatch")
        if stable_digest(inventory) != pin["inventory_sha256"]:
            raise SystemExit(f"{source}: inventory digest mismatch")
        if stable_digest(documents) != pin["documents_sha256"]:
            raise SystemExit(f"{source}: native document digest mismatch")
        if stable_digest(trace) != pin["trace_sha256"]:
            raise SystemExit(f"{source}: source trace digest mismatch")
        if stable_digest(coverage) != pin["coverage_sha256"]:
            raise SystemExit(f"{source}: coverage digest mismatch")
        summary = coverage["summary"]
        observed = {
            "source_rules": summary["source_rules"],
            "converted": summary["statuses"].get("converted", 0),
            "blocked": summary["statuses"].get("blocked", 0),
            "native_documents": len(documents),
        }
        expected = {key: pin[key] for key in observed}
        if observed != expected:
            raise SystemExit(f"{source}: counts {observed} != {expected}")
        if coverage["scanner_evaluated"] or any(
            row["proof_level"] == "source_proved" for row in coverage["rules"]
        ):
            raise SystemExit(f"{source}: automatic admission exceeded unverified scope")
        report["fixtures"].append({
            "name": pin["name"],
            "path": str(source),
            "sha256": actual_sha,
            **observed,
            "inventory_trace_sha256": stable_digest(inventory_trace),
            "inventory_sha256": stable_digest(inventory),
            "documents_sha256": stable_digest(documents),
            "trace_sha256": stable_digest(trace),
            "coverage_sha256": stable_digest(coverage),
            "elapsed_seconds": round(monotonic() - fixture_started, 6),
        })
        for key, value in observed.items():
            report["totals"][key] += value
    report["elapsed_seconds"] = round(monotonic() - started, 6)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise SystemExit(f"refusing to overwrite report: {args.report}")
    result = qualify(args.schema_root, args.fixture_root)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(args.report), "totals": result["totals"], "elapsed_seconds": result["elapsed_seconds"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
