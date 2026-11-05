"""Fail if the audited copied runtime or isolated semantic port drifts."""

from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'src/scap_ng_tools/converter/_v04_runtime'
INITIAL_SOURCE_COPY_SHA256 = '893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d'
CURRENT_RUNTIME_SHA256 = 'c56cc533c7a82b36cad4b5b33de446ba569ffebcc572de389c6e7f1eea918ed8'
UNCHANGED_SOURCE_SHA256 = 'de52a62d54bf73838457c9b91a2bdb3a5ad993dc000c0a6c4e1f1545d30c5ccf'
AUDITED_ADAPTATIONS = {
    # Native 0.4 Item grouping and compiler-derived Input discovery adaptations.
    'v04_direct_authoring_contract.py': '69258cc3765968074c4cee517510a2c56674f1aebdf4d806627d9fa61a7dd78d',
    'v04_direct_converter.py': 'a1598c3096639a3bb75f7a74cd30a7d7d4ff955d45932507a400ee678bc22b79',
    'v04_direct_datatypes.py': '43200abf10f419f2a26ad88959c8a517f619fbf168326c1d96ba7a2d157ff32a',
    'v04_direct_cmdlet_inputs.py': 'e830fbef8889123b81d059b87f2ef575440fb9559b4773ce2f26bc78473936ef',
    'v04_direct_file_behaviors.py': '55b30a90cbfcfbf8825545858a19b1b6da460c727964a04acafb762f2de72fc4',
    'v04_direct_scap_source.py': '8969d250de92050674c849c4934c70506484d8fec9d6d82de84741cfb225d553',
    'v04_draft_inputs.py': '787bebc720cbc876d5de5a8077185c87f614f04457fd2d30533835e6952399da',
    'v04_direct_inventory.py': '99a324754b739a9b51d0ae62abed76f8a14d5a172b54ff65beec6fd7ff58d904',
    'v04_direct_scalar_behaviors.py': '158b9a8547d47af723a52df9af3ebb072f82f281ad2b7eb575b948f33e143d48',
    'v04_variable_function_migration.py': '94f9c2a05e83905d424cd22cdba03ff68a382f988a1b42ed2c171358035ad5f1',
}
SEMANTIC_PORT = {
    'v04_comparison_types.py': 'aa2782f9ed3b23d7282ac7b69450650b0827ac76704878e4c6df2539f75394ea',
    'v04_input_presence.py': 'fa9b680582205010fd011879a01cac3473d3e9d22900840c44f016a9d39062ce',
    'v04_object_contract.py': 'e86aab6bf1e0145c14c4f6313928894fd09d041cb0042498174420721aa78d29',
    'v04_variable_expressions.py': '9742e5773fa28094c5511cc9032da3fdc69ad63d88c41d833ab21566a463470d',
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
