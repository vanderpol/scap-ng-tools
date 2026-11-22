"""Regression checks for the reconciled Self-Assertion parity-hold ledger."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/evidence/issue83/five-semantic-holds-20261122.json"


def _ledger() -> dict:
    return json.loads(LEDGER.read_text(encoding="utf-8"))


def test_five_holds_use_current_pins_and_have_no_converter_defect() -> None:
    receipt = _ledger()
    assert receipt["pins"]["source_commit"] == "d91e6ba33841e3202dc27d3e0d469a7abd939b16"
    assert receipt["pins"]["canonical_commit"] == "2d983fcbd7b2367d567ca8ccc689a378d08905e4"
    assert receipt["pins"]["tools_main_commit"] == "d3f54f72e8358dcf433aa567b4f1c3192b4dff58"
    assert receipt["structural_conversion"]["converted_definitions"] == 167
    assert receipt["structural_conversion"]["converted_tests"] == 799
    assert receipt["benchmark_requalification"]["newly_blocked_from_converted"] == 0

    holds = {row["definition_id"]: row for row in receipt["holds"]}
    assert set(holds) == {
        "oval:navy.navwar.niwcatlantic.scc:def:38",
        "oval:org.mitre.oval.test:def:580",
        "oval:org.mitre.oval.test:def:562",
        "oval:org.joval.test:def:20002",
        "oval:navy.navwar.niwcatlantic.scc.test:def:1",
    }
    assert all(not row["converter_defect"] for row in holds.values())
    assert holds["oval:org.mitre.oval.test:def:562"]["conversion"]["tests"] == 18
    assert holds["oval:org.mitre.oval.test:def:562"]["conversion"]["implicit_fixture_or_default"] is False
    assert holds["oval:org.joval.test:def:20002"]["conversion"]["native_datatypes"] == ["string"]
    assert holds["oval:navy.navwar.niwcatlantic.scc.test:def:1"]["source"]["validity"].startswith("XSD valid")


def test_native_subset_is_not_mislabeled_as_oval_equivalence() -> None:
    receipt = _ledger()
    assert receipt["ri_native_subset"]["policy"] != "independent OVAL equivalence"
    for row in receipt["holds"]:
        assert row["independent_oval_equivalence"] == "not_proved"
