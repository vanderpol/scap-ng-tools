"""Fail if the audited copied runtime or isolated semantic port drifts."""

from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'src/scap_ng_tools/converter/_v04_runtime'
INITIAL_SOURCE_COPY_SHA256 = '893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d'
CURRENT_RUNTIME_SHA256 = '54e368599bc11cf9df74da98552bac58e93de374b2e2cd098bd001c8cd0de4e2'
UNCHANGED_SOURCE_SHA256 = 'e50b51edb503793ca20c8046a04b15412eeda34e3fc3da537375fecbde1ca26e'
AUDITED_ADAPTATIONS = {
    # Native 0.4 Item grouping, compiler-derived Input discovery, and
    # source-OVAL unique lexical projection adaptations.
    'v04_direct_authoring_contract.py': '5fa26ee62c5a636144ee182596e6faf972bfba364160de8c1a03208058aba98e',
    'v04_direct_converter.py': '1a0c670bf700028cfa86b8ce1df92370df40acb6c10e46e99406ad7990bbaee2',
    'v04_direct_datatypes.py': '61acd5be0b70b1b4936215af6c5cb947f3e26276abbc39fee6091173c68c1f34',
    'v04_direct_cmdlet_inputs.py': 'e830fbef8889123b81d059b87f2ef575440fb9559b4773ce2f26bc78473936ef',
    'v04_direct_file_behaviors.py': '28c8544e8e7043757cd0577c413cfd398bead40245cf1d6ff36e3af3e83d3ed7',
    'v04_direct_scap_source.py': '09d3bc8f3290250bfd7d91741f90ea6ffba89e8bb17f21f8e9b47e93941d1265',
    'v04_draft_inputs.py': '704d506047a0a7d7a0937b60849e6ebaae255a34894ba32de9efc455c265268f',
    'v04_direct_inventory.py': 'd275992ce013a75945456da73678ebb29649a9e031e113af4c35b953c962a0b8',
    'v04_direct_scalar_behaviors.py': '158b9a8547d47af723a52df9af3ebb072f82f281ad2b7eb575b948f33e143d48',
    'v04_variable_function_migration.py': 'ab08c49569bde0458c4e7a567f131a7965cf35a78a050aa6a5a639eb6ecc3d44',
    'v04_direct_enum_variables.py': '6f8cdab49cbcfb4474b997e9a95421f26e4a11c64c77bf05ef19556b2c443101',
    # New source-fidelity helper; it is reviewed code, not a copied visitor.
    # The direct runtime registry also records pinned OVAL 5.12.3 platform
    # deprecations; its changed digest is intentionally allowlisted below.
    'v04_source_metadata.py': '2dc15ed1cc3e96b48004a70f8c3e9abdf831ce678c168b5d89439aeb15fd02f1',
    'v04_direct_capabilities.json': '0386da0646e577ce88c0525054eadaaea40dd0ceea6e929c6e60ed44c79143c1',
}
SEMANTIC_PORT = {
    'v04_comparison_types.py': 'edb810aa1508ef15b5538a7cf0efc15cff3125646a4144a823200e3a4cdef3aa',
    'v04_input_presence.py': '37f000f8bfa9cde0157667e61cfcf9704a0f404de8622a351facc8a322257669',
    'v04_object_contract.py': 'a63dfc5a3af0d77964853c2b1041a90361ae37881e1c82c7b01daa510d23994f',
    'v04_variable_expressions.py': '4520fb224e4ecb347a338b2bf39ef4a2b7b9622b3e8e5f21081e17d0d163e32b',
}
SOURCE_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'
PINNED_GENERATOR_HELPERS = {
    'generate_capability_schema_v04.py': 'df7545ed9fc7de40363aa64f286a82f2cd5b4d8175070833dbf9590a5c54b986',
    'v04_capability_native.py': '14d8a88474b1238352a6d35e7da247de41fbc65a26b8c5764c9406553807e09b',
    'v04_capability_source.py': 'b2e4a1cb053acc574b7677ef7d94a38905ce9acdd8a418be613840b330ca44e5',
    'v04_editor_annotations.py': 'ed47166e8cc82f9c319c5bc2829c6ffa0c8671682a9b3777e1c541cc37086072',
}


class DirectConverterSourceCopyTests(unittest.TestCase):
    def test_build_time_generator_helpers_remain_exact_pinned_source_copies(self):
        root = ROOT / 'scripts/_v04_generation'
        self.assertEqual({p.name for p in root.glob('*.py')},
                         set(PINNED_GENERATOR_HELPERS))
        for name, expected in PINNED_GENERATOR_HELPERS.items():
            self.assertEqual(sha256((root / name).read_bytes()).hexdigest(), expected)

    def test_runtime_matches_allowlisted_inventory_path_adaptation(self):
        paths = sorted(p for p in RUNTIME.iterdir()
                       if p.suffix in ('.py', '.json') and p.name != '__init__.py')
        self.assertEqual(len(paths), 19)
        digest = sha256()
        unchanged = sha256()
        for path in paths:
            self.assertFalse(path.is_symlink())
            digest.update(path.name.encode('utf-8') + b'\0')
            digest.update(path.read_bytes())
            if path.name in AUDITED_ADAPTATIONS:
                self.assertEqual(sha256(path.read_bytes()).hexdigest(),
                                 AUDITED_ADAPTATIONS[path.name])
            else:
                unchanged.update(path.name.encode('utf-8') + b'\0')
                unchanged.update(path.read_bytes())
        self.assertEqual(digest.hexdigest(), CURRENT_RUNTIME_SHA256)
        self.assertEqual(unchanged.hexdigest(), UNCHANGED_SOURCE_SHA256)

    def test_semantic_port_is_allowlisted_and_generated_pack_is_integrity_pinned(self):
        from scap_ng_tools.converter._v04_semantic import contracts
        directory = ROOT / 'src/scap_ng_tools/converter/_v04_semantic'
        for name, expected in SEMANTIC_PORT.items():
            self.assertEqual(sha256((directory / name).read_bytes()).hexdigest(), expected)
        pack = contracts()
        self.assertEqual(len(pack['capabilities']), 100)
        self.assertEqual(len(pack['behavior_attributes']), 8)
        self.assertEqual(pack['format'], 'scap-ng-portable-0.4.1-semantic-pack/1')
        self.assertEqual(pack['schema_version'], '0.4.1')
        self.assertEqual(pack['frozen_schema_digest'], 'dc650646a24e727e68de242027cca3058683accc531f07bf6ace217609755b24')
        self.assertEqual(pack['oval_commit'], '2f140ee5c5dd1ed9606fcd5afc301f6baeb48706')
        self.assertEqual(pack['generator_helper_sha256']['v04_capability_source.py'], 'b2e4a1cb053acc574b7677ef7d94a38905ce9acdd8a418be613840b330ca44e5')
        self.assertFalse((directory / 'contracts-0.4.0.json').exists())


if __name__ == '__main__':
    unittest.main()
