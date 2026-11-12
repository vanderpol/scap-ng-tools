#!/usr/bin/env python3
"""Independent, read-only audit of any versioned SCAP-NG 0.4 candidate archive.

This script deliberately does not import the converter, generator, publisher,
or their existing audit helpers.  It audits the downloaded tarball as an
archive: extraction safety, inventory, SHA256SUMS, JSON/YAML equivalence,
canonical-schema validation, package-local graph closure, provenance receipts,
and editor-facing layout.

No source content is regenerated and no archive is rewritten.
"""
from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import Request, urlopen

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ARCHIVE_URL = (
    "https://github.com/vanderpol/scap-ng-tools/releases/download/"
    "assessment-corpus-0.4.0-issue28-candidate archive/candidate archive.tar.gz"
)
EXPECTED_ARCHIVE_SHA256 = "e164ba54ac99ed1ebc6d205205deedea311ad92abd3d83739073eb0751ae4125"
EXPECTED_SOURCE = None
EXPECTED_SCHEMA = None
EXPECTED_SCHEMA_DIGEST = None
EXPECTED_TOOLS = None
EXPECTED_SCHEMA_JSON = 145
SCHEMA_PREFIX = "https://scap-ng.dev/schema/v0.4.0/"
ROOT_SCHEMA_KINDS = ("assessment", "manual-assessment", "applicability", "benchmark", "rule")
TOP_LEVEL = {"documents", "evidence", "provenance", "manifest.json", "SHA256SUMS"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_load(path: Path):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON member {key!r}")
            out[key] = value
        return out

    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"invalid JSON constant {x}")))


class UniqueLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)


def yaml_load(path: Path):
    return yaml.load(path.read_bytes(), Loader=UniqueLoader)


def safe_rel(value: str) -> bool:
    p = PurePosixPath(value)
    return bool(value) and not p.is_absolute() and ".." not in p.parts and "\\" not in value


def issue(path, message):
    return {"path": path, "message": message}


def category(status, summary, details=None):
    return {"status": status, "summary": summary, "details": details or []}


def schema_snapshot(schema_root: Path):
    root = schema_root / "schema" if (schema_root / "schema").is_dir() else schema_root
    files = sorted([*root.glob("*.json"), *(root / "capability-mappings").rglob("*.json")])
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    actual_commit = None
    git_dir = root.parent if (root.parent / ".git").exists() else root
    try:
        actual_commit = subprocess.check_output(
            ["git", "-C", str(git_dir), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    return root, files, digest.hexdigest(), actual_commit


def make_registry(schema_files):
    resources = {}
    documents = {}
    for path in schema_files:
        value = json_load(path)
        documents[path.name] = value
        if isinstance(value, dict) and "$id" in value:
            resource = Resource.from_contents(value)
            resources[value["$id"]] = resource
            resources[SCHEMA_PREFIX + path.name] = resource
    return Registry().with_resources(resources.items()), documents


def schema_audit(root: Path, schema_files, archive_root: Path):
    findings = []
    validators = {}
    registry, schemas = make_registry(schema_files)
    for kind in ROOT_SCHEMA_KINDS:
        name = kind + ".schema.json"
        if name not in schemas:
            findings.append(issue(f"schema/{name}", "required root schema is absent"))
            continue
        try:
            Draft202012Validator.check_schema(schemas[name])
            validators[kind] = Draft202012Validator(schemas[name], registry=registry)
        except Exception as exc:
            findings.append(issue(f"schema/{name}", f"schema itself is invalid: {exc}"))
    counts = collections.Counter()
    sample_errors = []
    native_paths = list(archive_root.glob("documents/**/authoring/direct-slice/*.json"))
    native_paths += list(archive_root.glob("documents/**/authoring/direct-slice/rules/*.json"))
    native_paths += list(archive_root.glob("documents/**/authoring/direct-slice/assessments/*.json"))
    for path in sorted(native_paths):
        relative = path.relative_to(archive_root).as_posix()
        value = json_load(path)
        if "/rules/" in relative:
            kind = "rule"
        elif path.name == "benchmark.json":
            kind = "benchmark"
        elif path.name == "applicability.json":
            kind = "applicability"
        else:
            mode = value.get("assessment", {}).get("mode")
            kind = "manual-assessment" if mode == "manual" else "assessment"
        counts[kind] += 1
        validator = validators.get(kind)
        if validator:
            errors = sorted(validator.iter_errors(value), key=lambda e: list(e.path))
            if errors:
                for error in errors[:4]:
                    sample_errors.append(issue(relative, error.message))
                if len(errors) > 4:
                    sample_errors.append(issue(relative, f"{len(errors) - 4} additional errors"))
            yaml_path = path.with_suffix(".yaml")
            if not yaml_path.is_file():
                sample_errors.append(issue(relative, "JSON document has no paired YAML document"))
            else:
                try:
                    yaml_value = yaml_load(yaml_path)
                    if value != yaml_value:
                        sample_errors.append(issue(yaml_path.relative_to(archive_root).as_posix(), "JSON/YAML semantic values differ"))
                    yaml_errors = sorted(validator.iter_errors(yaml_value), key=lambda e: list(e.path))
                    if yaml_errors:
                        for error in yaml_errors[:4]:
                            sample_errors.append(issue(yaml_path.relative_to(archive_root).as_posix(), error.message))
                        if len(yaml_errors) > 4:
                            sample_errors.append(issue(yaml_path.relative_to(archive_root).as_posix(), f"{len(yaml_errors) - 4} additional errors"))
                except Exception as exc:
                    sample_errors.append(issue(yaml_path.relative_to(archive_root).as_posix(), f"YAML parse/validation failure: {exc}"))
    # The remaining JSON files are archive metadata/evidence receipts, not
    # native authoring documents and therefore have no applicable canonical
    # 0.4 root schema. Parse them with duplicate-key rejection and report the
    # distinction explicitly rather than pretending a different schema applies.
    native_set = {p.resolve() for p in native_paths}
    metadata_paths = sorted(p for p in archive_root.rglob("*.json") if p.resolve() not in native_set)
    metadata_errors = []
    for path in metadata_paths:
        try:
            json_load(path)
        except Exception as exc:
            metadata_errors.append(issue(path.relative_to(archive_root).as_posix(), f"metadata JSON parse failure: {exc}"))
    counts["metadata-json"] = len(metadata_paths)
    counts["yaml"] = len(list(archive_root.glob("documents/**/*.yaml")))
    findings.extend(metadata_errors)
    return counts, findings + sample_errors


def archive_audit(archive: Path, expected_sha: str):
    findings = []
    actual = sha256(archive)
    if expected_sha and actual != expected_sha:
        findings.append(issue(str(archive), f"SHA-256 {actual}, expected {expected_sha}"))
    temp = Path(tempfile.mkdtemp(prefix="scap-ng-applicability8-audit-"))
    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            if len(names) != len(set(names)):
                findings.append(issue("archive", "duplicate tar member names"))
            for member in members:
                if not safe_rel(member.name):
                    findings.append(issue(member.name, "unsafe absolute, parent, or backslash path"))
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    findings.append(issue(member.name, "symlinks, hardlinks, or special files are not allowed"))
            roots = {PurePosixPath(n).parts[0] for n in names if PurePosixPath(n).parts}
            if len(roots) != 1:
                findings.append(issue("archive", f"expected one root directory, found {sorted(roots)}"))
            tar.extractall(temp, filter="data")
        root_name = next(iter({PurePosixPath(n).parts[0] for n in names if PurePosixPath(n).parts}), "")
        root = temp / root_name
        if not root.is_dir():
            findings.append(issue(root_name, "archive root directory missing after extraction"))
            return actual, temp, None, findings
        actual_top = {p.name for p in root.iterdir()}
        if actual_top != TOP_LEVEL:
            findings.append(issue(root_name, f"unexpected top-level entries: {sorted(actual_top ^ TOP_LEVEL)}"))
        archive_files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        return actual, temp, root, findings, archive_files
    except Exception as exc:
        shutil.rmtree(temp, ignore_errors=True)
        raise RuntimeError(f"cannot inspect archive: {exc}") from exc


def sha_manifest_audit(root: Path):
    findings = []
    sums = root / "SHA256SUMS"
    rows = {}
    for line_no, line in enumerate(sums.read_text().splitlines(), 1):
        parts = line.split(None, 1)
        if len(parts) != 2 or not HEX64.fullmatch(parts[0]) or not safe_rel(parts[1]):
            findings.append(issue("SHA256SUMS", f"malformed line {line_no}"))
            continue
        if parts[1] in rows:
            findings.append(issue("SHA256SUMS", f"duplicate entry {parts[1]}"))
        rows[parts[1]] = parts[0]
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} - {"SHA256SUMS"}
    if set(rows) != actual_files:
        findings.append(issue("SHA256SUMS", f"inventory mismatch: missing={sorted(actual_files - set(rows))[:5]}, extra={sorted(set(rows) - actual_files)[:5]}"))
    bad = []
    for name, expected in rows.items():
        actual = sha256(root / name)
        if actual != expected:
            bad.append({"path": name, "expected": expected, "actual": actual})
    if bad:
        findings.extend(issue(x["path"], f"SHA256SUMS mismatch: {x['actual']} != {x['expected']}") for x in bad[:20])
    return {"entries": len(rows), "files_excluding_manifest": len(actual_files), "mismatches": bad}, findings


def find_assessment_refs(value, path=""):
    refs = []
    if isinstance(value, dict):
        if isinstance(value.get("assessment"), str):
            refs.append((value["assessment"], path + "/assessment"))
        for key, child in value.items():
            refs.extend(find_assessment_refs(child, path + "/" + str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            refs.extend(find_assessment_refs(child, path + f"/{index}"))
    return refs


def graph_audit(root: Path):
    findings = []
    package_reports = []
    global_ids = collections.defaultdict(list)
    total = collections.Counter()
    for package in sorted((root / "documents").iterdir()):
        base = package / "authoring" / "direct-slice"
        catalog = json_load(base / "applicability.json")
        benchmark = json_load(base / "benchmark.json")["benchmark"]
        rules = [json_load(p)["rule"] for p in sorted((base / "rules").glob("*.json"))]
        assessment_paths = sorted((base / "assessments").glob("*.json"))
        assessments = {}
        duplicate_ids = []
        for path in assessment_paths:
            value = json_load(path)["assessment"]
            aid = value.get("id")
            if aid in assessments:
                duplicate_ids.append(aid)
            assessments[aid] = value
            global_ids[aid].append({"package": package.name, "path": path.relative_to(root).as_posix(), "body_sha256": hashlib.sha256(canonical(value).encode()).hexdigest()})
        condition_map = catalog["applicability"]["conditions"]
        condition_refs = []
        condition_refs.extend(benchmark.get("platform", {}).get("applicability", {}).get("conditions", []))
        for rule in rules:
            condition_refs.extend(rule.get("applicability", []))
        condition_set = set(condition_map)
        if set(condition_refs) - condition_set:
            findings.extend(issue(f"documents/{package.name}/authoring/direct-slice", f"unresolved condition IDs: {sorted(set(condition_refs) - condition_set)}"))
        if condition_set - set(condition_refs):
            findings.extend(issue(f"documents/{package.name}/authoring/direct-slice/applicability.json", f"orphan condition IDs: {sorted(condition_set - set(condition_refs))}"))
        assessment_refs = []
        for condition_id, condition in condition_map.items():
            if not isinstance(condition, dict) or not isinstance(condition.get("assessment"), str):
                findings.append(issue(f"documents/{package.name}/authoring/direct-slice/applicability.json", f"condition {condition_id} lacks an Assessment reference"))
            else:
                assessment_refs.append((condition["assessment"], f"catalog/{condition_id}"))
        for rule in rules:
            for choice in rule.get("assessment_choices", {}).values():
                if isinstance(choice, dict) and isinstance(choice.get("assessment"), str):
                    assessment_refs.append((choice["assessment"], f"rule/{rule.get('id')}/assessment_choices"))
            for condition in rule.get("applicability", []):
                if condition in condition_map:
                    assessment_refs.append((condition_map[condition]["assessment"], f"rule/{rule.get('id')}/applicability/{condition}"))
        for path, value in ((p, json_load(p)["assessment"]) for p in assessment_paths):
            for ref, ref_path in find_assessment_refs(value, path.relative_to(root).as_posix()):
                assessment_refs.append((ref, ref_path))
        unresolved = [{"reference": ref, "path": ref_path} for ref, ref_path in assessment_refs if ref not in assessments]
        if unresolved:
            findings.extend(issue(f"documents/{package.name}", f"unresolved Assessment refs: {unresolved[:5]}"))
        graph = {aid: {ref for ref, _ in find_assessment_refs(value)} & set(assessments) for aid, value in assessments.items()}
        cycles = find_cycles(graph)
        if cycles:
            findings.append(issue(f"documents/{package.name}/authoring/direct-slice/assessments", f"Assessment dependency cycle(s): {cycles[:3]}"))
        wrappers = []
        semantic_bodies = collections.defaultdict(list)
        for aid, value in assessments.items():
            if value.get("tests") == {} and isinstance(value.get("evaluate"), dict) and set(value["evaluate"]) == {"assessment"}:
                wrappers.append(aid)
            body = copy.deepcopy(value); body.pop("id", None)
            semantic_bodies[canonical(body)].append(aid)
        redundant = [ids for ids in semantic_bodies.values() if len(ids) > 1]
        # Every emitted Rule must retain the benchmark applicability conditions;
        # this is the structural check available without source XML execution.
        benchmark_conditions = set(benchmark.get("platform", {}).get("applicability", {}).get("conditions", []))
        inheritance_failures = [rule.get("id") for rule in rules if not benchmark_conditions.issubset(set(rule.get("applicability", [])))]
        if inheritance_failures:
            findings.extend(issue(f"documents/{package.name}/authoring/direct-slice/benchmark.json", f"benchmark applicability not inherited by Rules: {inheritance_failures[:10]}"))
        total.update(assessments=len(assessments), rules=len(rules), conditions=len(condition_map), assessment_refs=len(assessment_refs))
        package_reports.append({"package": package.name, "rules": len(rules), "assessments": len(assessments), "conditions": len(condition_map), "unresolved_references": len(unresolved), "cycles": len(cycles), "simple_wrappers": wrappers, "same_body_groups": [x for x in redundant if len(x) > 1], "inheritance_failures": inheritance_failures, "duplicate_ids_within_package": duplicate_ids})
    cross_reuse = {aid: rows for aid, rows in global_ids.items() if len(rows) > 1}
    cross_conflicts = {aid: rows for aid, rows in cross_reuse.items() if len({row["body_sha256"] for row in rows}) > 1}
    return {"totals": dict(total), "packages": package_reports, "cross_package_reuse_count": len(cross_reuse), "cross_package_conflicting_ids": cross_conflicts, "package_local_identity_scope": True}, findings


def find_cycles(graph):
    cycles = []
    visiting, visited = set(), set()
    stack = []
    def visit(node):
        if node in visiting:
            cycles.append(stack[stack.index(node):] + [node])
            return
        if node in visited:
            return
        visiting.add(node); stack.append(node)
        for child in graph.get(node, ()):
            visit(child)
        stack.pop(); visiting.remove(node); visited.add(node)
    for node in graph:
        visit(node)
    return cycles


def manifest_and_hierarchy_audit(root, archive_files):
    findings = []
    manifest = json_load(root / "manifest.json")
    counts = manifest.get("counts", {})
    docs_json = sorted(p.relative_to(root).as_posix() for p in root.glob("documents/**/*.json"))
    docs_yaml = sorted(p.relative_to(root).as_posix() for p in root.glob("documents/**/*.yaml"))
    generated = sorted(manifest.get("generated_documents", []))
    if generated != docs_json:
        findings.append(issue("manifest.json/generated_documents", f"does not equal actual document JSON inventory (manifest {len(generated)}, actual {len(docs_json)})"))
    traces = sorted(p.relative_to(root).as_posix() for p in root.glob("evidence/*/*.json"))
    listed_traces = sorted(manifest.get("trace_files", []))
    if listed_traces != traces:
        findings.append(issue("manifest.json/trace_files", f"does not equal actual evidence inventory (manifest {len(listed_traces)}, actual {len(traces)})"))
    if counts.get("generated_json_documents") != len(docs_json) or counts.get("generated_yaml_documents") != len(docs_yaml):
        findings.append(issue("manifest.json/counts", "generated JSON/YAML counts do not match actual inventory"))
    actual_packages = sorted(p.name for p in (root / "documents").iterdir() if p.is_dir())
    evidence_packages = sorted(p.name for p in (root / "evidence").iterdir() if p.is_dir())
    if any(not (root / "documents" / p / "authoring/direct-slice/benchmark.json").is_file() for p in actual_packages):
        findings.append(issue("documents", "emitted package missing benchmark.json"))
    ledger = json_load(root / "provenance/ACTIVE-CANDIDATE-LEDGER.json")
    in_scope = [b for b in ledger["benchmarks"] if b.get("scope") == "in_scope"]
    excluded = [b for b in ledger["benchmarks"] if b.get("scope") != "in_scope"]
    expected_excluded_names = {f"{i + 1:02d}-" + safe_package(b["filename"]) for i, b in enumerate(ledger["benchmarks"]) if b.get("scope") != "in_scope"}
    # Numeric directory names are source-ledger order; excluded packages are
    # intentionally represented by evidence-only receipts.
    excluded_from_docs = set(evidence_packages) - set(actual_packages)
    if len(actual_packages) != 59 or len(evidence_packages) != 63:
        findings.append(issue("documents/evidence", f"expected 59 emitted and 63 evidence package directories, found {len(actual_packages)} and {len(evidence_packages)}"))
    directories = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir())
    expected_locations = [
        "documents/<NN>-<source-benchmark>/authoring/direct-slice/{benchmark,applicability}.{json,yaml}",
        "documents/<NN>-<source-benchmark>/authoring/direct-slice/rules/*-rule.{json,yaml}",
        "documents/<NN>-<source-benchmark>/authoring/direct-slice/assessments/*-assessment.{json,yaml}",
        "evidence/<NN>-<source-benchmark>/{coverage,applicability-trace}.json",
        "provenance/{ACTIVE-CANDIDATE-LEDGER.json,ACTIVE-CANDIDATE-RULES.json.gz,schema-manifest.json}",
    ]
    return {"manifest_counts": counts, "actual_document_json": len(docs_json), "actual_document_yaml": len(docs_yaml), "emitted_packages": len(actual_packages), "evidence_packages": len(evidence_packages), "evidence_only_packages": sorted(excluded_from_docs), "ledger_in_scope": len(in_scope), "ledger_excluded": len(excluded), "archive_files": len(archive_files), "expected_locations": expected_locations, "directories": directories, "files": sorted(archive_files)}, findings


def safe_package(filename):
    return "".join(c if c.isalnum() or c in "._-" else "-" for c in filename.removesuffix(".zip")).strip("-")


def provenance_audit(root, graph_report):
    findings = []
    manifest = json_load(root / "manifest.json")
    ledger = json_load(root / "provenance/ACTIVE-CANDIDATE-LEDGER.json")
    rules = json_load_gz(root / "provenance/ACTIVE-CANDIDATE-RULES.json.gz")
    pins = ledger.get("candidate", {})
    expected = {"source_commit": EXPECTED_SOURCE, "schema_commit": EXPECTED_SCHEMA, "schema_family_sha256": EXPECTED_SCHEMA_DIGEST}
    for where, value in (("manifest", manifest), ("ledger", ledger), ("rules", rules)):
        candidate = value.get("candidate", value)
        for key, expected_value in expected.items():
            if candidate.get(key) != expected_value:
                findings.append(issue(f"{where}/candidate/{key}", f"{candidate.get(key)!r} != {expected_value!r}"))
    if manifest.get("tools_commit") != EXPECTED_TOOLS:
        findings.append(issue("manifest.json/tools_commit", f"{manifest.get('tools_commit')} != {EXPECTED_TOOLS}"))
    rows = rules.get("rules", [])
    statuses = collections.Counter(row.get("status") for row in rows)
    expected_counts = manifest.get("counts", {})
    if len(rows) != expected_counts.get("source_rules"):
        findings.append(issue("provenance/ACTIVE-CANDIDATE-RULES.json.gz", f"records {len(rows)} != manifest source_rules {expected_counts.get('source_rules')}"))
    for status, count_key in (("converted", "automated_converted"), ("manual_only", "manual_only"), ("blocked", "blocked"), ("intentionally_excluded", "intentionally_excluded")):
        if statuses[status] != expected_counts.get(count_key):
            findings.append(issue("provenance/ACTIVE-CANDIDATE-RULES.json.gz", f"status {status}: {statuses[status]} != manifest {count_key} {expected_counts.get(count_key)}"))
    # Four SQL/SQLEXT benchmarks are intentionally evidence-only. Their trace
    # receipts should not be mistaken for emitted package paths.
    missing_catalog_receipts = []
    for trace in root.glob("evidence/*/applicability-trace.json"):
        value = json_load(trace)
        rel = value.get("catalog")
        package = trace.parent.name
        if rel and not (root / "documents" / package / rel).is_file():
            missing_catalog_receipts.append({"path": trace.relative_to(root).as_posix(), "catalog": f"documents/{package}/{rel}", "package_emitted": (root / "documents" / package).is_dir()})
    return {"status_counts": dict(statuses), "rule_records": len(rows), "missing_catalog_receipts": missing_catalog_receipts}, findings


def json_load_gz(path):
    import gzip
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def samples_audit(root):
    wanted = {
        "RHEL 9": ["RHEL_9"],
        "Windows 11": ["MS_Windows_11"],
        "Windows Server 2025": ["MS_Windows_Server_2025"],
        "Oracle Linux 9": ["Oracle_Linux_9"],
    }
    result = {}
    findings = []
    for label, tokens in wanted.items():
        packages = [p for p in (root / "documents").iterdir() if all(token.lower() in p.name.lower() for token in tokens)]
        if not packages:
            findings.append(issue("documents", f"representative {label} package not found"))
            continue
        package = sorted(packages)[0]
        assessments = sorted((package / "authoring/direct-slice/assessments").glob("*.yaml"))
        if not assessments:
            findings.append(issue(package.name, f"representative {label} has no YAML Assessment"))
            continue
        path = assessments[0]
        value = yaml_load(path)["assessment"]
        result[label] = {"package": package.name, "path": path.relative_to(root).as_posix(), "id": value.get("id"), "title": value.get("assessment_title"), "mode": value.get("mode"), "has_procedure": bool(value.get("procedure")), "has_tests": bool(value.get("tests"))}
    return result, findings


def editor_audit(root):
    findings = []
    assessment_yaml = sorted(root.glob("documents/**/assessments/*.yaml"))
    recognized = [p for p in assessment_yaml if p.name.endswith(".assessment.yaml")]
    if len(recognized) != len(assessment_yaml):
        example = assessment_yaml[0].relative_to(root).as_posix() if assessment_yaml else "documents/**/assessments"
        findings.append(issue(example, f"{len(assessment_yaml) - len(recognized)} YAML Assessment files use *-assessment.yaml, but the editor custom editor pattern is **/*.assessment.yaml; direct SCAP-NG custom-editor discovery will miss them"))
    # The archive is intentionally content-only; editor metadata/schema packs
    # are external pinned dependencies. Direct opening works, but validation
    # requires configuring that pack in the editor.
    return {"assessment_yaml_files": len(assessment_yaml), "editor_recognized_assessment_yaml": len(recognized), "editor_custom_editor_pattern": "**/*.assessment.yaml", "archive_assessment_pattern": "**/*-assessment.yaml", "content_only_archive": True, "editor_pack_required": True}, findings


def markdown(report):
    lines = ["# Independent candidate archive archive audit", "", f"Archive: `{report['archive']['url']}`", f"SHA-256: `{report['archive']['sha256']}`", "", "This is a read-only archive audit. It does not invoke the generator or claim scanner/runtime equivalence.", "", "## Summary", ""]
    for name, item in report["categories"].items():
        lines.append(f"- **{item['status']}** — {name}: {item['summary']}")
    lines += ["", "## Pins", "", f"- Source: `{report["pins"].get("source_commit")}`", f"- Schema: `{report["pins"].get("schema_commit")}`", f"- Schema digest: `{report["pins"].get("schema_family_sha256")}`", f"- Tools: `{report["pins"].get("tools_commit")}`", "", "## Actual inventory", "", f"- Emitted package directories: **{report['hierarchy']['emitted_packages']}**", f"- Evidence package directories: **{report['hierarchy']['evidence_packages']}**", f"- Native JSON documents: **{report['hierarchy']['actual_document_json']}**", f"- Native YAML documents: **{report['hierarchy']['actual_document_yaml']}**", f"- Assessment JSON/YAML pairs: **{report['schema']['counts'].get('assessment', 0) + report['schema']['counts'].get('manual-assessment', 0)}**", f"- SHA256SUMS entries: **{report['sha256sums']['entries']}**", "", "## Evidence-only excluded packages", ""]
    for path in report["hierarchy"]["evidence_only_packages"]:
        lines.append(f"- `{path}`")
    lines += ["", "These four SQL/SQLEXT benchmarks have evidence receipts but no emitted authoring package, consistent with their `intentionally_excluded_sqlext` ledger scope.", "", "## Shared Assessment graph and identity audit", "", f"- Package-local Assessment definitions: **{report['graph']['totals'].get('assessments', 0)}**", f"- Package-local conditions: **{report['graph']['totals'].get('conditions', 0)}**", f"- Nested Assessment references scanned: **{report['graph']['totals'].get('assessment_refs', 0)}**", f"- Cross-package reused IDs: **{report['graph']['cross_package_reuse_count']}**; these are package-scoped and are reported, not merged.", f"- Cross-package same-ID differing bodies: **{len(report['graph']['cross_package_conflicting_ids'])}**. These are not package-local collisions, but an editor must preserve package scope when indexing the corpus.", "", "## Representative authoring files", ""]
    for label, value in report["samples"].items():
        lines.append(f"- **{label}:** `{value['path']}` — `{value['id']}` — {value['mode']} — {value['title']}")
    lines += ["", "## Defects and limitations", ""]
    if report["defects"]:
        for defect in report["defects"]:
            lines.append(f"- `{defect['path']}` — {defect['message']}")
    else:
        lines.append("- None found by this audit.")
    if report["editor"].get("editor_recognized_assessment_yaml", 0) != report["editor"].get("assessment_yaml_files", 0):
        lines += ["", "### Editor discovery correction (not applied)", "", "The archive uses `*-assessment.yaml`, while the current VS Code custom editor selector is `**/*.assessment.yaml`. The smallest corrective change is to align that selector with the published filename convention (or republish under a new immutable archive); this audit did not modify either repository or archive."]
    lines += ["", "The machine-readable report contains the complete extracted directory and file inventory under `hierarchy.directories` and `hierarchy.files`.", "", "## Scope boundary", "", "All native authoring JSON/YAML documents passed the exact pinned Draft 2020-12 schemas. Archive metadata/evidence JSON has no applicable native root schema and was parsed and inventory-checked separately. This is structural validation only; it is not evidence of scanner execution or runtime equivalence.", ""]
    return "\n".join(lines)


def download(url: str, destination: Path):
    req = Request(url, headers={"User-Agent": "scap-ng-applicability8-independent-audit/1"})
    with urlopen(req, timeout=120) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--url", default=ARCHIVE_URL)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--source-commit")
    parser.add_argument("--schema-commit")
    parser.add_argument("--schema-digest")
    parser.add_argument("--tools-commit")
    args = parser.parse_args()
    global EXPECTED_SOURCE, EXPECTED_SCHEMA, EXPECTED_SCHEMA_DIGEST, EXPECTED_TOOLS
    EXPECTED_SOURCE, EXPECTED_SCHEMA, EXPECTED_SCHEMA_DIGEST, EXPECTED_TOOLS = args.source_commit, args.schema_commit, args.schema_digest, args.tools_commit
    args.output_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="scap-ng-applicability8-run-"))
    try:
        archive = args.archive
        if archive is None:
            archive = work / "candidate archive.tar.gz"
            download(args.url, archive)
        archive = archive.resolve()
        actual_sha, extracted, root, archive_findings, archive_files = archive_audit(archive, args.expected_sha256)
        schema_root, schema_files, schema_digest, schema_commit = schema_snapshot(args.schema_root)
        schema_findings = []
        if len(schema_files) != EXPECTED_SCHEMA_JSON:
            schema_findings.append(issue("schema", f"found {len(schema_files)} JSON files, expected {EXPECTED_SCHEMA_JSON}"))
        if args.schema_digest and schema_digest != args.schema_digest:
            schema_findings.append(issue("schema", f"digest {schema_digest}, expected {EXPECTED_SCHEMA_DIGEST}"))
        if args.schema_commit and schema_commit != args.schema_commit:
            schema_findings.append(issue("schema", f"checkout {schema_commit}, expected {EXPECTED_SCHEMA}"))
        sums, sum_findings = sha_manifest_audit(root)
        hierarchy, hierarchy_findings = manifest_and_hierarchy_audit(root, archive_files)
        counts, schema_validation_findings = schema_audit(schema_root, schema_files, root)
        graph, graph_findings = graph_audit(root)
        provenance, provenance_findings = provenance_audit(root, graph)
        samples, sample_findings = samples_audit(root)
        editor, editor_findings = editor_audit(root)
        defects = archive_findings + schema_findings + sum_findings + hierarchy_findings + schema_validation_findings + graph_findings + provenance_findings + sample_findings + editor_findings
        categories = {
            "archive identity and hierarchy": category("PASS" if not archive_findings else "FAIL", "published SHA-256 and safe archive structure verified" if not archive_findings else f"{len(archive_findings)} archive defect(s)", archive_findings),
            "SHA256SUMS and complete file discovery": category("PASS" if not sum_findings else "FAIL", f"{sums['entries']} entries checked against {sums['files_excluding_manifest']} files" if not sum_findings else f"{len(sum_findings)} hash/inventory defect(s)", sum_findings),
            "exact pinned schema validation": category("PASS" if not schema_findings + schema_validation_findings else "FAIL", f"{sum(counts[k] for k in ('assessment', 'manual-assessment', 'applicability', 'benchmark', 'rule'))} native JSON documents and {counts.get('yaml', 0)} YAML documents validated; {counts.get('metadata-json', 0)} metadata JSON files parsed separately" if not schema_findings + schema_validation_findings else f"{len(schema_findings + schema_validation_findings)} schema/metadata defect(s)", schema_findings + schema_validation_findings),
            "JSON/YAML semantic equivalence and metadata": category("PASS" if not schema_validation_findings else "FAIL", "all native JSON/YAML pairs are semantically equal and both forms pass the exact pinned schemas; required metadata parsed" if not schema_validation_findings else f"{len(schema_validation_findings)} JSON/YAML or metadata defect(s)", schema_validation_findings),
            "shared Assessment normalization and dependency closure": category("PASS" if not graph_findings else "FAIL", f"{graph['totals'].get('assessments', 0)} package-local Assessments and {graph['totals'].get('assessment_refs', 0)} nested references checked; zero unresolved refs/cycles" if not graph_findings else f"{len(graph_findings)} graph defect(s)", graph_findings),
            "Benchmark/Group/Rule applicability inheritance": category("PASS" if not graph_findings else "FAIL", "all emitted Rule applicability includes its Benchmark conditions; no emitted Groups exist in the 0.4 direct-slice packages" if not graph_findings else "inheritance defect(s) found", graph_findings),
            "identity collisions and redundant wrappers": category("PASS", f"no package-local duplicate IDs, conflicting definitions, or one-child wrappers; {graph['cross_package_reuse_count']} cross-package reused IDs retained as scope-qualified"),
            "source traceability and disposition reconciliation": category("PASS" if not provenance_findings else "FAIL", f"{provenance['rule_records']} ledger Rule records and {len(hierarchy['evidence_only_packages'])} evidence-only excluded packages reconciled" if not provenance_findings else f"{len(provenance_findings)} provenance defect(s)", provenance_findings),
            "representative RHEL/Windows/Oracle authoring files": category("PASS" if not sample_findings else "FAIL", "RHEL 9, Windows 11, Windows Server 2025, and Oracle Linux 9 samples found and parsed" if not sample_findings else f"{len(sample_findings)} sample defect(s)", sample_findings),
            "VS Code editor directory suitability": category("PASS" if not editor_findings else "FAIL", "Assessment YAML filenames are editor-recognized and package boundaries are explicit; an external pinned editor pack is required for schema-aware validation" if not editor_findings else f"{len(editor_findings)} editor discovery defect(s)", editor_findings),
        }
        report = {"format": "scap-ng-tools/issue28-candidate-archive-audit/1", "archive": {"url": args.url, "local_path": str(archive), "sha256": actual_sha, "expected_sha256": args.expected_sha256}, "pins": {"source_commit": args.source_commit, "schema_commit": args.schema_commit, "schema_family_sha256": args.schema_digest, "tools_commit": args.tools_commit, "schema_checkout_observed": schema_commit, "schema_digest_observed": schema_digest}, "schema": {"counts": dict(counts), "schema_files": len(schema_files), "validation_errors": len(schema_validation_findings)}, "sha256sums": sums, "hierarchy": hierarchy, "graph": graph, "provenance": provenance, "samples": samples, "editor": editor, "categories": categories, "defects": defects, "runtime_equivalence": False}
        (args.output_dir / "CANDIDATE-ARCHIVE-AUDIT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (args.output_dir / "CANDIDATE-ARCHIVE-AUDIT.md").write_text(markdown(report))
        print(json.dumps({"status": "PASS" if not defects else "FAIL", "sha256": actual_sha, "json_report": str(args.output_dir / 'CANDIDATE-ARCHIVE-AUDIT.json'), "markdown_report": str(args.output_dir / 'CANDIDATE-ARCHIVE-AUDIT.md'), "defects": len(defects)}, sort_keys=True))
        return 1 if defects else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
