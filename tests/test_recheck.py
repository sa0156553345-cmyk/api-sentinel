"""The second pass: a BOLA finding is reported as confirmed only when the same request reproduces it.

The fixtures count requests on purpose. A server whose answer changes between two identical requests is the case the
second pass exists for, and a counter reproduces that case every time. Expected values are written from the rule, not
read back from the implementation.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import api_sentinel as s  # noqa: E402
from authz_matrix.fixtures import DROP, Fixture, Resp, not_found, parts_of, unauthorized  # noqa: E402

OWN = s.OWNER_FIELDS_DEFAULT
URL = "/books/v1/{id}"


class CountingBooks:
    """Two owners and two books, keyed by book_title (the VAmPI shape).

    leaks(user, title, n) says whether the n-th request that user makes for title gets a non-owner's copy of the
    record; any other non-owner request gets 404. owner_fail_from=n makes the owner's n-th and later requests for a
    title answer 500, which is how an owner baseline can fail on the second pass only. drop_after=n closes every
    connection from the (n+1)-th request on, which is how a target can stop answering during the second pass.
    """

    def __init__(self, leaks=lambda user, title, n: True, owner_fail_from=None, drop_after=None):
        self.leaks = leaks
        self.owner_fail_from = owner_fail_from
        self.drop_after = drop_after
        self.books = {"alice-book": ("alice", "alice-secret"), "bob-book": ("bob", "bob-secret")}
        self.users = {"alice-token": "alice", "bob-token": "bob"}
        self.count: dict[tuple[str, str], int] = {}
        self.total = 0

    def __call__(self, req):
        self.total += 1
        if self.drop_after is not None and self.total > self.drop_after:
            return DROP
        user = self.users.get(req.token)
        if user is None:
            return unauthorized()
        parts = parts_of(req)
        if parts == ["books", "v1"] and req.method == "GET":
            return Resp(200, {"Books": [{"book_title": t, "user": o} for t, (o, _) in self.books.items()]})
        if len(parts) != 3 or parts[:2] != ["books", "v1"] or parts[2] not in self.books:
            return not_found()
        title = parts[2]
        owner, secret = self.books[title]
        n = self.count[(user, title)] = self.count.get((user, title), 0) + 1
        if user == owner:
            if self.owner_fail_from is not None and n >= self.owner_fail_from:
                return Resp(500, {"error": "unavailable"})
            return Resp(200, {"book_title": title, "secret": secret, "owner": owner})
        if self.leaks(user, title, n):
            return Resp(200, {"book_title": title, "secret": secret, "owner": owner})
        return not_found()


def alice():
    return s.Identity("alice", {"Authorization": "Bearer alice-token"}, ["alice-book"], params={}, owner_values={})


def bob():
    return s.Identity("bob", {"Authorization": "Bearer bob-token"}, ["bob-book"], params={}, owner_values={})


def confirmed(findings):
    return [f for f in findings if f.check in s.BOLA_CHECKS]


def pairs(findings):
    return {(f.details["owner_identity"], f.details["accessing_identity"], f.details["resource_id"])
            for f in confirmed(findings)}


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


def write_identities(folder):
    path = Path(folder) / "identities.json"
    path.write_text(json.dumps({"identities": [
        {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["alice-book"]},
        {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": ["bob-book"]},
    ]}), encoding="utf-8")
    return str(path)


def leak(owner, accessor, rid, url):
    return s.Finding("authorization-boundary", "high", "medium", 70.0, [f"{accessor} received {rid}"], "verify",
                     url, "GET", status="confirmed",
                     details={"owner_identity": owner, "accessing_identity": accessor, "resource_id": rid,
                              "http_status": 200, "response_bytes": 40})


def undetermined(owner, accessor, rid, url):
    return s.Finding("authorization-undetermined", "info", "low", 0.0, ["cannot decide"], "review", url, "GET",
                     status="needs_input",
                     details={"owner_identity": owner, "accessing_identity": accessor, "resource_id": rid})


def incomplete(owner, rid, url):
    return s.Finding("authorization-incomplete", "info", "low", 0.0, ["baseline failed"], "fix", url, "GET",
                     status="skipped", details={"owner_identity": owner, "resource_id": rid})


# --- The outcome rules, on synthetic findings ----------------------------------------------------------------------

def test_apply_recheck_confirms_only_what_reproduces_and_says_why_the_rest_did_not():
    first = [leak("alice", "bob", "a1", "/a1"),              # reproduces on the second pass
             leak("alice", "bob", "a2", "/a2"),              # does not reproduce
             leak("bob", "alice", "b1", "/b1"),              # the owner's baseline fails on the second pass
             undetermined("alice", "carol", "a3", "/a3")]    # not a BOLA check: passes through unchanged
    second = [leak("alice", "bob", "a1", "/a1"),
              incomplete("bob", "b1", "/b1"),
              leak("alice", "bob", "a9", "/a9")]             # appears only on the second pass
    out, summary = s.apply_recheck(first, second)
    assert summary == {"enabled": True, "ran": True, "candidates": 3, "interrupted": None, "reproduced": 1,
                       "not_reproduced": 1, "not_rechecked": 1, "second_pass_only": 1}
    by_endpoint = {f.endpoint: f for f in out}
    assert by_endpoint["/a1"].check == "authorization-boundary"
    assert by_endpoint["/a1"].details["recheck"] == "reproduced"
    assert by_endpoint["/a2"].check == "authorization-undetermined" and by_endpoint["/a2"].status == "needs_input"
    assert by_endpoint["/a2"].details["recheck"] == "not_reproduced"
    assert by_endpoint["/a2"].evidence[0].startswith("The second pass did not reproduce")
    assert by_endpoint["/b1"].details["recheck"] == "not_rechecked"
    assert by_endpoint["/a9"].details["recheck"] == "second_pass_only"
    assert by_endpoint["/a3"] is first[3]
    assert len(out) == 5
    assert all(f.details["recheck"] == "reproduced" for f in out if f.check in s.BOLA_CHECKS)
    assert all(f.confidence == "low" and f.severity == "info" for f in out if f.check == "authorization-undetermined")


def test_recheck_report_adds_up_the_runs_it_is_given():
    runs = [{"scope": "a", "enabled": True, "ran": True, "candidates": 2, "reproduced": 1, "not_reproduced": 1,
             "not_rechecked": 0, "second_pass_only": 0},
            {"scope": "b", "enabled": True, "ran": False, "candidates": 0, "reproduced": 0, "not_reproduced": 0,
             "not_rechecked": 0, "second_pass_only": 0}]
    report = s.recheck_report(True, runs)
    assert report["totals"] == {"candidates": 2, "reproduced": 1, "not_reproduced": 1, "not_rechecked": 0,
                                "second_pass_only": 0}
    assert report["enabled"] is True and report["runs"] is runs


def test_a_pair_the_first_pass_left_undetermined_is_taken_over_by_a_second_pass_leak_and_keeps_its_reason():
    out, summary = s.apply_recheck([undetermined("bob", "alice", "b5", "/b5")], [leak("bob", "alice", "b5", "/b5")])
    assert len(out) == 1
    f = out[0]
    assert f.check == "authorization-undetermined" and f.details["recheck"] == "second_pass_only"
    assert f.evidence[0].startswith("The leak appeared on the second pass only")
    assert "first pass: cannot decide" in f.evidence
    assert (summary["candidates"], summary["second_pass_only"]) == (0, 1)


def test_an_interrupted_second_pass_reports_every_candidate_as_not_rechecked_with_the_error():
    out, summary = s.apply_recheck([leak("alice", "bob", "a1", "/a1")], [], interrupted="connection reset")
    assert (summary["not_rechecked"], summary["interrupted"]) == (1, "connection reset")
    assert out[0].check == "authorization-undetermined" and out[0].details["recheck"] == "not_rechecked"
    assert "connection reset" in out[0].evidence[0]


def test_coverage_counts_a_check_once_across_both_passes_and_a_check_only_the_second_pass_ran_as_run():
    def entry(kind, owner, by, rid, url, status=200):
        return {"kind": kind, "owner": owner, "accessed_by": by, "resource_id": rid, "url": url, "status": status,
                "size": 10}

    def again(e):
        return {**e, "kind": "recheck", "of": e["kind"]}

    trail = [entry("owner_baseline", "alice", "", "a1", "/a1"),
             entry("owner_baseline", "alice", "", "a2", "/a2", status=500),  # baseline failed on the first pass
             entry("accessor", "alice", "bob", "a1", "/a1"),
             again(entry("owner_baseline", "alice", "", "a1", "/a1")),
             again(entry("owner_baseline", "alice", "", "a2", "/a2")),
             again(entry("accessor", "alice", "bob", "a1", "/a1")),          # the same check: counted once
             again(entry("accessor", "alice", "bob", "a2", "/a2"))]          # a check only the second pass ran
    findings = [leak("alice", "bob", "a1", "/a1"), undetermined("alice", "bob", "a2", "/a2")]
    cov = s._coverage([alice(), bob()], findings, trail)
    assert (cov["checks_run"], cov["confirmed"], cov["undetermined"], cov["passed"]) == (2, 1, 1, 0)
    assert cov["owned_resources_tested"] == 2 and cov["requests_sent"] == 7


# --- The matrix, against a server whose answers depend on how often they were asked ----------------------------------

def test_a_stable_leak_is_confirmed_and_the_second_pass_adds_requests_but_no_checks():
    ids = [alice(), bob()]
    on_trail, off_trail = [], []
    with Fixture(CountingBooks()) as fx, s.resource_id_field("book_title"):
        found_on, run_on = s.run_matrix_with_recheck(fx.base + URL, ids, OWN, 5, on_trail, scope="matrix")
    with Fixture(CountingBooks()) as fx, s.resource_id_field("book_title"):
        found_off, run_off = s.run_matrix_with_recheck(fx.base + URL, ids, OWN, 5, off_trail, scope="matrix",
                                                       recheck=False)
    assert pairs(found_on) == {("alice", "bob", "alice-book"), ("bob", "alice", "bob-book")}
    assert all(f.details["recheck"] == "reproduced" for f in confirmed(found_on))
    assert (run_on["scope"], run_on["ran"], run_on["candidates"], run_on["reproduced"]) == ("matrix", True, 2, 2)
    assert (run_off["enabled"], run_off["ran"], run_off["candidates"]) == (False, False, 0)
    cov_on = s._coverage(ids, found_on, on_trail)
    cov_off = s._coverage(ids, found_off, off_trail)
    for key in ("confirmed", "checks_run", "passed", "owned_resources_tested"):
        assert cov_on[key] == cov_off[key], key
    assert cov_off["requests_sent"] > 0
    assert cov_on["requests_sent"] == 2 * cov_off["requests_sent"]  # the second pass repeats the matrix exactly


def test_a_leak_that_does_not_reproduce_is_undetermined_and_not_confirmed():
    with Fixture(CountingBooks(leaks=lambda user, title, n: n == 1)) as fx, s.resource_id_field("book_title"):
        found, run = s.run_matrix_with_recheck(fx.base + URL, [alice(), bob()], OWN, 5, [], scope="matrix")
    assert confirmed(found) == []
    unresolved = [f for f in found if f.check == "authorization-undetermined"]
    assert len(unresolved) == 2 and all(f.details["recheck"] == "not_reproduced" for f in unresolved)
    assert (run["candidates"], run["not_reproduced"], run["reproduced"]) == (2, 2, 0)


def test_a_leak_seen_only_on_the_second_pass_is_undetermined_and_not_confirmed():
    leaks = lambda user, title, n: title == "alice-book" or (title == "bob-book" and n == 2)  # noqa: E731
    with Fixture(CountingBooks(leaks=leaks)) as fx, s.resource_id_field("book_title"):
        found, run = s.run_matrix_with_recheck(fx.base + URL, [alice(), bob()], OWN, 5, [], scope="matrix")
    assert pairs(found) == {("alice", "bob", "alice-book")}
    seen_once = [f for f in found if f.check == "authorization-undetermined"]
    assert len(seen_once) == 1 and seen_once[0].details["recheck"] == "second_pass_only"
    d = seen_once[0].details
    assert (d["owner_identity"], d["accessing_identity"], d["resource_id"]) == ("bob", "alice", "bob-book")
    assert (run["candidates"], run["reproduced"], run["second_pass_only"]) == (1, 1, 1)


def test_an_owner_baseline_that_fails_on_the_second_pass_is_not_rechecked():
    trail: list = []
    with Fixture(CountingBooks(owner_fail_from=2)) as fx, s.resource_id_field("book_title"):
        found, run = s.run_matrix_with_recheck(fx.base + URL, [alice(), bob()], OWN, 5, trail, scope="matrix")
    assert confirmed(found) == []
    unresolved = [f for f in found if f.check == "authorization-undetermined"]
    assert len(unresolved) == 2 and all(f.details["recheck"] == "not_rechecked" for f in unresolved)
    assert all("could not check" in f.evidence[0] for f in unresolved)
    assert (run["candidates"], run["not_rechecked"], run["reproduced"]) == (2, 2, 0)
    cov = s._coverage([alice(), bob()], found, trail)
    assert (cov["checks_run"], cov["passed"]) == (2, 0)


def test_a_clean_api_gets_no_second_pass_at_all():
    trail: list = []
    with Fixture(CountingBooks(leaks=lambda user, title, n: False)) as fx, s.resource_id_field("book_title"):
        found, run = s.run_matrix_with_recheck(fx.base + URL, [alice(), bob()], OWN, 5, trail, scope="matrix")
    assert found == []
    assert run["ran"] is False and run["candidates"] == 0
    assert not any(entry["kind"] == "recheck" for entry in trail)


# --- The command line: exit codes and the reports ----------------------------------------------------------------------

def cli_against_fresh_server(td, *extra):
    """One CLI run against a new server, so the counters start from zero for every run."""
    with Fixture(CountingBooks(leaks=lambda user, title, n: n == 1)) as fx:
        argv = ["--yes-i-am-authorized", "--url", fx.base + URL, "--identities", write_identities(td),
                "--id-field", "book_title", *extra]
        return run_cli(argv)


def test_the_exit_code_follows_the_second_pass_and_no_recheck_restores_one_pass_behaviour():
    with tempfile.TemporaryDirectory() as td:
        on, off, page_path = Path(td) / "on.json", Path(td) / "off.json", Path(td) / "on.html"
        code_on, _, _ = cli_against_fresh_server(td, "--output", str(on), "--html-output", str(page_path))
        code_off, _, _ = cli_against_fresh_server(td, "--no-recheck", "--output", str(off))
        rep_on = json.loads(on.read_text(encoding="utf-8"))
        rep_off = json.loads(off.read_text(encoding="utf-8"))
        page = page_path.read_text(encoding="utf-8")
    assert code_on == s.EXIT_UNDETERMINED and code_off == s.EXIT_POLICY
    assert rep_on["summary"]["confirmed"] == 0 and rep_on["summary"]["undetermined"] == 2
    assert rep_on["recheck"]["enabled"] is True and rep_on["recheck"]["totals"]["not_reproduced"] == 2
    assert rep_off["summary"]["confirmed"] == 2 and rep_off["recheck"]["enabled"] is False
    assert rep_off["recheck"]["totals"]["candidates"] == 0  # no second pass ran, so there is nothing to count
    assert "Second pass: 0 reproduced, 2 did not reproduce" in page


def test_a_connection_lost_during_the_second_pass_keeps_the_first_pass_evidence_and_exits_6_not_4():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "r.json"
        # The first pass makes four requests (two owner baselines, two cross reads); the second pass starts at the fifth.
        with Fixture(CountingBooks(drop_after=4)) as fx:
            argv = ["--yes-i-am-authorized", "--url", fx.base + URL, "--identities", write_identities(td),
                    "--id-field", "book_title", "--output", str(out)]
            code, text, _ = run_cli(argv)
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_UNDETERMINED
    assert "the second pass stopped" in text
    assert rep["summary"]["confirmed"] == 0 and rep["summary"]["undetermined"] == 2
    run = rep["recheck"]["runs"][0]
    assert run["interrupted"] and run["not_rechecked"] == 2
