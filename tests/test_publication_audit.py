"""Structured egress discovery plus executable fail-closed sink prelude tests."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publication_audit', ROOT / 'scripts/audit_publication_paths.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PublicationAudit(unittest.TestCase):
    def test_discovers_shell_inline_python_and_referenced_writer(self):
        self.assertTrue(audit.run_transport('gh release create tag archive.zip'))
        self.assertTrue(audit.run_transport("python - <<'PY'\nimport subprocess\nsubprocess.run(['gh','api','--method','PUT',url])\nPY\n"))
        self.assertTrue(audit.python_transport("import subprocess\nsubprocess.run(['gh','api','--method','PUT',url])"))
        self.assertFalse(audit.run_transport('gh api repos/owner/repo/actions/workflows'))

    def test_real_shared_denial_runs_before_a_publisher_or_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'must-not-publish'
            program = audit.DENY_PRELUDE + '\nprintf bypass > "$PUBLICATION_MARKER"\n'
            proc = subprocess.run(['bash', '-c', program], capture_output=True, text=True,
                                  env=dict(os.environ, SCAPNG_PUBLICATION_GATE_SRC=str(ROOT / 'src'),
                                           PUBLICATION_MARKER=str(marker)))
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertIn('legacy direct publication is blocked', proc.stderr)

    def test_unpinned_and_raw_upload_sinks_are_not_admitted_by_inventory(self):
        import yaml
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Audit fixture',
                            '-c', 'user.email=audit-fixture@example.invalid', 'commit', '--quiet',
                            '--allow-empty', '-m', 'Test-only audit root'], check=True)
            folder = root / '.github/workflows'
            folder.mkdir(parents=True)
            file = folder / 'publisher.yml'
            workflow = {'on': {'workflow_dispatch': {}}, 'jobs': {'publish': {'steps': [
                {'uses': 'actions/upload-artifact@v4', 'with': {'path': 'unapproved'}},
                {'uses': 'vanderpol/scap-ng-tools/.github/actions/current-publication@main'},
                {'run': 'gh release create current-native unapproved.zip'}]}}}
            file.write_text(yaml.safe_dump(workflow))
            self.assertEqual(audit.inventory(root, 'fixture/repo', 'a' * 40)['unprotected_workflow_sinks'], 3)
            workflow['jobs']['publish']['steps'] = [
                {'uses': 'vanderpol/scap-ng-tools/.github/actions/historical-upload@' + 'a' * 40},
                {'run': audit.DENY_PRELUDE + 'gh release create current-native unapproved.zip'}]
            file.write_text(yaml.safe_dump(workflow))
            self.assertEqual(audit.inventory(root, 'fixture/repo', 'a' * 40)['unprotected_workflow_sinks'], 0)
