"""Authorization test matrix as tests.

Two kinds of checks live here.

* Harness integrity (must always hold): every oracle is confirmed by an independent probe; no finding is unlabeled;
  no fixture or tool crashes; nothing that did not run is counted as a pass; no residue is left on a target; the CLI
  cases map exit codes to the outcomes they must produce.
* Characterization (pinned): the measured outcome of every access (authz_matrix/baseline.json). A change here is a
  behaviour change. Review it, then re-pin with
  `python3 tests/authz_matrix/run_matrix.py --update-baseline --write`.

A green run means the harness is sound and the measured behaviour is the pinned one. It does NOT mean the tool is
correct, and it does NOT mean the coverage is complete.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from authz_matrix import harness, scenarios  # noqa: E402
from authz_matrix.harness import DEVIATIONS, NEEDS_INPUT_STATES  # noqa: E402

BASELINE = HERE / "authz_matrix" / "baseline.json"
_CACHE = {}


def _results():
    if "r" not in _CACHE:
        _CACHE["r"] = harness.run_all(scenarios.CASES)
    return _CACHE["r"]


def _rows():
    return [t for r in _results() for t in r.rows]


def _by_id(case_id):
    return next(r for r in _results() if r.case.id == case_id)


def test_scenario_count():
    assert len({c.scenario for c in scenarios.CASES}) == 26


def test_migrated_scenarios_are_present():
    assert {"S21", "S22", "S23", "S24", "S25", "S26"} <= {c.scenario for c in scenarios.CASES}


def test_outcomes_match_pinned_baseline():
    pinned = json.loads(BASELINE.read_text(encoding="utf-8"))
    current = harness.snapshot(_results())
    changed = [k for k in sorted(set(pinned) | set(current)) if pinned.get(k) != current.get(k)]
    assert not changed, "pinned matrix outcomes changed: " + "; ".join(
        f"{k}: {pinned.get(k)} -> {current.get(k)}" for k in changed[:10])


def test_oracle_labels_are_backed_by_independent_probes():
    bad = [(t.case_id, t.owner, t.accessor, t.verb, t.verify_note) for t in _rows() if not t.verified]
    assert not bad, bad


def test_no_unlabeled_findings_and_no_fixture_errors():
    assert not [(r.case.id, r.unlabeled) for r in _results() if r.unlabeled]
    assert not [(r.case.id, r.fixture_errors) for r in _results() if r.fixture_errors]


def test_no_tool_crash_is_ever_counted_as_a_result():
    assert all(r.tool_error is None for r in _results())
    assert not [t for t in _rows() if t.outcome == "ERROR"]


def test_nothing_that_did_not_run_is_counted_as_a_pass():
    bad = [(t.case_id, t.owner, t.accessor, t.verb, t.state, t.outcome) for t in _rows()
           if (t.state in NEEDS_INPUT_STATES or t.state in ("UNDETERMINED", "SKIPPED")) and t.outcome in ("TP", "TN")]
    assert not bad, bad


def test_every_deviation_is_attributed_to_a_known_gap():
    """FP/FN/UNDETERMINED/NEEDS_INPUT/ERROR must name a registered gap, and a gap annotation must not outlive its deviation."""
    problems = []
    for r in _results():
        for t in r.rows:
            if t.label in (harness.POLICY, harness.INDET):
                continue
            ids = [g for g in t.gap.split(",") if g]
            if (t.outcome in DEVIATIONS) != bool(ids):
                problems.append((t.case_id, t.owner, t.accessor, t.verb, t.outcome, t.gap))
            problems += [(t.case_id, "unknown gap", g) for g in ids if g not in scenarios.GAPS]
    assert not problems, problems


def test_undecidable_accesses_explain_why_and_are_never_fp_or_fn():
    for t in _rows():
        if t.label in (harness.POLICY, harness.INDET):
            assert t.why.strip(), (t.case_id, t.owner, t.accessor)
            assert t.outcome in ("UNDETERMINED", "UNDECIDABLE_FLAGGED", "UNDECIDABLE_SILENT", "NEEDS_INPUT"), \
                (t.case_id, t.outcome)


def test_no_residue_left_on_targets():
    assert sum(r.residue for r in _results()) == 0


def test_cli_exit_codes_map_to_the_outcomes_they_must_produce():
    s18, s19, s20 = (_by_id(c).cli for c in ("S18-cli-no-owns", "S19-cli-setup-fails", "S20-cli-connection-reset"))
    assert s18["returncode"] == 2 and not s18["report_written"] and not s18["crashed"]        # refused: missing input
    assert s19["returncode"] == 3 and s19["report_written"] and s19["report_findings"] >= 1   # setup failed
    assert s20["returncode"] == 4 and not s20["report_written"] and not s20["crashed"]        # transport failure
    for cid in ("S18-cli-no-owns", "S19-cli-setup-fails", "S20-cli-connection-reset"):
        assert all(t.outcome == "NEEDS_INPUT" for t in _by_id(cid).rows), cid


def test_secure_profile_is_not_flagged_and_its_evidence_is_not_misstated():
    r = _by_id("S13-profile-ignore-secure")
    t = next(x for x in r.rows if (x.owner, x.accessor) == ("alice", "bob"))
    assert t.outcome == "TN"
    assert not any("still show the original owner" in e for e in t.evidence)
