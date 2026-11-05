"""Fail if the audited copied runtime or isolated semantic port drifts."""

from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'src/scap_ng_tools/converter/_v04_runtime'
INITIAL_SOURCE_COPY_SHA256 = '893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d'
CURRENT_RUNTIME_SHA256 = '5a9df805af030130962d51627f7023c532b46c94c1fec769a3f072e4be1f835c'
UNCHANGED_SOURCE_SHA256 = 'a46c58af4ae9365091e2681d3050ba310ca2e70bb8bea7ed709f0a2d106ae77c'
AUDITED_ADAPTATIONS = {
    # Native 0.4 Item grouping and compiler-derived Input discovery adaptations.
    'v04_direct_authoring_contract.py': '69258cc3765968074c4cee517510a2c56674f1aebdf4d806627d9fa61a7dd78d',
    'v04_direct_converter.py': 'cc4be25bd87d1da8a084f1b4335da17f39b45c8d14a74800004dcbe34b0249ff',
    'v04_direct_scap_source.py': '8969d250de92050674c849c4934c70506484d8fec9d6d82de84741cfb225d553',
    'v04_draft_inputs.py': '486020ce582311610a9de88af8bcf1ac37d829171eabcfa11862af75dbc75ed2',
    'v04_direct_file_behaviors.py': '251d43546d15ddeda730f75bf271c31caf8a7a9c3b266e01a273cffeadeb6ba9',
    'v04_direct_inventory.py': '99a324754b739a9b51d0ae62abed76f8a14d5a172b54ff65beec6fd7ff58d904',
    'v04_direct_scalar_behaviors.py': '158b9a8547d47af723a52df9af3ebb072f82f281ad2b7eb575b948f33e143d48',
}
SEMANTIC_PORT = {
    'v04_comparison_types.py': '1241301693adbf4553e4b1e7072fad8880212dbe4d2441dc7cb2ff20239e3e2c',
    'v04_input_presence.py': 'fa9b680582205010fd011879a01cac3473d3e9d22900840c44f016a9d39062ce',
    'v04_object_contract.py': 'e86aab6bf1e0145c14c4f6313928894fd09d041cb0042498174420721aa78d29',
    'v04_variable_expressions.py': 'e3d71f7aec9dbb8a958a23fe767c8979df1a36880372c63a3c7f5a491162482c',
}
SOURCE_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'
PINNED_GENERATOR_HELPERS = {
    'generate_capability_schema_v04.py': '99f08e62596414a59dcd219c7aefc29c3b0c4a05f7f3f3b8a222f637ebd069d0',
    'v04_capability_native.py': 'b2a961aea7231d74b0a755b1a9b0485f349594d0a3456c09d9ba9c9cf0b648e8',
    'v04_capability_source.py': 'b2e4a1cb053acc574b7677ef7d94a38905ce9acdd8a418be613840b330ca44e5',
    'v04_editor_annotations.py': 'ae85a8a324eeff5b61898612b607d4e04ddc00414f14993d874db6135c4d3175',
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
        self.assertEqual(len(contracts()['capabilities']), 52)
        self.assertEqual(len(contracts()['behavior_attributes']), 8)


if __name__ == '__main__':
    unittest.main()
