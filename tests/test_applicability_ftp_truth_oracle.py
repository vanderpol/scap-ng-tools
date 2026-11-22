"""Independent truth oracle for the pinned Windows Server 2019 FTP CPE fact.

This is intentionally not the RI evaluator and does not alter converter output.
It records the source OVAL check semantics so an empty or failed collection
cannot be mistaken for a positive installed determination.
"""
import unittest


SOURCE_ZIP_SHA256 = '54113f747a0a256f66b8c8db34763daebee3dc2c769041ec5f043ec7ed5948a1'
SOURCE_XML_SHA256 = '9a0a5a76b3a1c6efd4867809d7c4fa5834e2cb441d1513ed7bfa634b9a540fb3'
FACT_DEFINITION = 'oval:navy.navwar.niwcatlantic.scc.windows:def:301'
FACT_TEST = 'oval:navy.navwar.niwcatlantic.scc.windows:tst:301'
CPE_PLATFORM = 'xccdf_navy.navwar.niwcatlantic.scc_platform_FTP'


def source_fact_outcome(items=None, *, acquisition=None):
    """Model only the pinned fact Test's existence/check semantics.

    ``check_existence=at_least_one_exists`` makes an empty selected
    population FALSE. ``check=all`` requires every selected Item to satisfy
    the State predicate ``InstallState != Installed``. Acquisition failures
    are kept as ERROR/UNKNOWN rather than fabricated Items.
    """
    if acquisition in {'error', 'denied', 'unsupported'}:
        return 'error'
    if acquisition == 'unknown':
        return 'unknown'
    items = [] if items is None else list(items)
    if not items:
        return 'false'
    if any(value is None for value in items):
        return 'error'
    return 'true' if all(str(value).casefold() != 'installed' for value in items) else 'false'


def cpe_negate(outcome):
    """CPE 2.3 logical-test negation; source ERROR is not negated."""
    return {'true': 'false', 'false': 'true'}.get(outcome, outcome)


class FTPApplicabilityTruthOracle(unittest.TestCase):
    def test_source_positive_negative_and_empty_collections(self):
        self.assertEqual(cpe_negate(source_fact_outcome(['Installed'])), 'true')
        self.assertEqual(cpe_negate(source_fact_outcome(['Available'])), 'false')
        self.assertEqual(cpe_negate(source_fact_outcome(['Removed'])), 'false')
        # This is the source-content safety concern: at_least_one_exists
        # returns FALSE for no Items, and source NOT makes that TRUE. It is
        # preserved as source semantics, not silently repaired by conversion.
        self.assertEqual(source_fact_outcome([]), 'false')
        self.assertEqual(cpe_negate(source_fact_outcome([])), 'true')

    def test_check_all_and_no_selected_record(self):
        self.assertEqual(cpe_negate(source_fact_outcome(['Installed', 'Available'])), 'true')
        self.assertEqual(source_fact_outcome([]), 'false')  # no selected record

    def test_missing_field_and_acquisition_failures_never_become_positive(self):
        for outcome in ('error', 'denied', 'unsupported'):
            self.assertEqual(cpe_negate(source_fact_outcome(acquisition=outcome)), 'error')
        self.assertEqual(cpe_negate(source_fact_outcome([None])), 'error')
        self.assertEqual(cpe_negate(source_fact_outcome(acquisition='unknown')), 'unknown')

    def test_pinned_identity_is_part_of_the_oracle(self):
        self.assertEqual(len(SOURCE_ZIP_SHA256), 64)
        self.assertEqual(len(SOURCE_XML_SHA256), 64)
        self.assertEqual(FACT_DEFINITION, 'oval:navy.navwar.niwcatlantic.scc.windows:def:301')
        self.assertEqual(FACT_TEST, 'oval:navy.navwar.niwcatlantic.scc.windows:tst:301')
        self.assertEqual(CPE_PLATFORM, 'xccdf_navy.navwar.niwcatlantic.scc_platform_FTP')


if __name__ == '__main__':
    unittest.main()
