"""Fail if the audited copied runtime or isolated semantic port drifts."""

from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'src/scap_ng_tools/converter/_v04_runtime'
INITIAL_SOURCE_COPY_SHA256 = '893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d'
CURRENT_RUNTIME_SHA256 = '7cc30989ae1b65c2f2af41120777769fd94b6ca96be1c01196bbf42e85f13d59'
UNCHANGED_SOURCE_SHA256 = '903f2d800a0ffb0e5a1c41bcefc9095c21ba8903c65c5b40cd796b1c1adc4aa6'
AUDITED_ADAPTATIONS = {
    # Native 0.4 Item grouping and compiler-derived Input discovery adaptations.
    'v04_direct_authoring_contract.py': '69258cc3765968074c4cee517510a2c56674f1aebdf4d806627d9fa61a7dd78d',
    'v04_direct_converter.py': '3ac82b2fecd08ead7e2759303c0fc68e1a5c37eefedbbbedc1471720001fa4d4',
    'v04_direct_datatypes.py': '43200abf10f419f2a26ad88959c8a517f619fbf168326c1d96ba7a2d157ff32a',
    'v04_direct_cmdlet_inputs.py': 'e830fbef8889123b81d059b87f2ef575440fb9559b4773ce2f26bc78473936ef',
    'v04_direct_file_behaviors.py': '28c8544e8e7043757cd0577c413cfd398bead40245cf1d6ff36e3af3e83d3ed7',
    'v04_direct_scap_source.py': '8969d250de92050674c849c4934c70506484d8fec9d6d82de84741cfb225d553',
    'v04_draft_inputs.py': '6373bc9a7208f7ad2b2b3cbcd4674c2683d3ecf971c7380d1e3566b7d1367f07',
    'v04_direct_inventory.py': '7b1ac0c502ed1e8d15a07935b677ae8f86e88b88a3efd9174de9fa46ba33f782',
    'v04_direct_scalar_behaviors.py': '158b9a8547d47af723a52df9af3ebb072f82f281ad2b7eb575b948f33e143d48',
    'v04_variable_function_migration.py': 'ab08c49569bde0458c4e7a567f131a7965cf35a78a050aa6a5a639eb6ecc3d44',
    'v04_direct_enum_variables.py': 'b7e6e8a4b85892d19509de16822667d76c2c8e31719ce65f3722ffd6952083a9',
}
SEMANTIC_PORT = {
    'v04_comparison_types.py': 'f4974bc9b8f1acec280dd2c5d6a61daed9d702e89e6ce02fd01b9b9443379f56',
    'v04_input_presence.py': '32fec8715cb69ba56453984b84becc7b43e53e5a2f896680e0752996e011d49e',
    'v04_object_contract.py': 'a63dfc5a3af0d77964853c2b1041a90361ae37881e1c82c7b01daa510d23994f',
    'v04_variable_expressions.py': 'f4d1ea8b606fd411e638ed88af0ac47a087ea8139276dae9f3bbb0a96dd17d0f',
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
        self.assertEqual(len(paths), 18)
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
        self.assertEqual(len(pack['capabilities']), 52)
        self.assertEqual(len(pack['behavior_attributes']), 8)
        self.assertEqual(pack['format'], 'scap-ng-portable-0.4.1-semantic-pack/1')
        self.assertEqual(pack['schema_version'], '0.4.1')
        self.assertEqual(pack['frozen_schema_digest'], '578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829')
        self.assertEqual(pack['oval_commit'], '2f140ee5c5dd1ed9606fcd5afc301f6baeb48706')
        self.assertEqual(pack['generator_helper_sha256']['v04_capability_source.py'], 'b2e4a1cb053acc574b7677ef7d94a38905ce9acdd8a418be613840b330ca44e5')
        self.assertFalse((directory / 'contracts-0.4.0.json').exists())


if __name__ == '__main__':
    unittest.main()
