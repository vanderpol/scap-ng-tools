"""The full-corpus ledger preserves precise source-hold classifications."""
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    'convert_self_assertion_corpus', ROOT / 'scripts/convert_self_assertion_corpus.py')
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(_MODULE)


class CorpusFailureClassificationTests(unittest.TestCase):
    def test_deprecated_wins_over_unsupported(self):
        self.assertEqual(
            _MODULE.classify_failure('', 'deprecated source capability: package511_test'),
            'deprecated_source_construct')
        self.assertEqual(
            _MODULE.classify_failure('', 'unsupported State field: deprecated kerberos_ticket_events'),
            'deprecated_source_construct')

    def test_canonical_and_source_type_holds_are_distinct(self):
        self.assertEqual(
            _MODULE.classify_failure('', 'unbound external Variable or unsupported possible_restriction'),
            'canonical_input_constraint_hold')
        self.assertEqual(
            _MODULE.classify_failure('', "invalid int literal: 'abc'"),
            'source_typed_literal_invalid')
        self.assertEqual(
            _MODULE.classify_failure('', 'policy source literal must be nonnegative'),
            'source_typed_literal_invalid')

    def test_unknown_remains_converter_failure(self):
        self.assertEqual(_MODULE.classify_failure('', 'unexpected internal diagnostic'),
                         'converter_failure')


if __name__ == '__main__':
    unittest.main()
