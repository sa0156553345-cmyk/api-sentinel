"""The stateful flow's second pass: a finding is confirmed only if a second read shows its effect again.

A read is repeated. A write is never sent again, because a second write is a second destructive action: the owner's
record is read once more instead, and the write's effect must still be there. The fixtures change their answer between
requests on purpose, which is the case the second pass exists for. Expected values are written from the rule, not read
back from the implementation.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import api_sentinel as s  # noqa: E402
from authz_matrix.fixtures import Fixture, OrdersApp, Resp  # noqa: E402

OWN = s.OWNER_FIELDS_DEFAULT
ORDERS = "/orders/{id}"
ALICE_BARE = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": []}
BOB_BARE = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": []}


def alice():
    return s.Identity("alice", {"Authorization": "Bearer alice-token"}, [], params={}, owner_values={})


def bob():
    return s.Identity("bob", {"Authorization": "Bearer bob-token"}, [], params={}, owner_values={})


def _stateful(fx, recheck=True, log=None):
    return s.run_stateful_flow(fx.base + "/orders", fx.base + ORDERS, [alice(), bob()],
                               {"item": "test", "total": 9.99}, 5, allow_destructive=True,
                               owner_fields=OWN, log=log, recheck=recheck)


def _select(findings, check=None, method=None):
    return [f for f in findings
            if (check is None or f.check == check) and (method is None or f.method == method)]


def _order_id(path):
    tail = path.rsplit("/", 1)[-1]
    return int(tail) if tail.isdigit() else None


class _ReadOnce:
    """A non-owner's read of an order succeeds only the first time, as a cache or a race would allow. Later reads of
    the same order answer 403. Every other request goes to the inner application unchanged."""

    def __init__(self, inner):
        self.inner = inner
        self.served = set()

    def __call__(self, req):
        resp = self.inner(req)
        if req.method == "GET" and req.token == "bob-token" and resp.status == 200:
            if req.path in self.served:
                return Resp(403, {"error": "forbidden"})
            self.served.add(req.path)
        return resp


class _ApplyThenRevert:
    """A non-owner's PATCH is applied. The owner's first read after it shows the change, and then the change is
    undone, as a rollback or a lagging replica would do. The fixture counts the PATCH requests it receives."""

    def __init__(self, inner):
        self.inner = inner
        self.undo = {}
        self.patches = 0

    def __call__(self, req):
        oid = _order_id(req.path)
        if req.method == "PATCH" and req.token == "bob-token" and oid in self.inner.orders:
            self.patches += 1
            self.undo[oid] = dict(self.inner.orders[oid])
            return self.inner(req)
        if req.method == "GET" and req.token == "alice-token" and oid in self.undo:
            resp = self.inner(req)
            self.inner.orders[oid] = self.undo.pop(oid)
            return resp
        return self.inner(req)


class _DeleteThenRestore:
    """A non-owner's DELETE removes the order. The owner's first read after it finds the order gone, and then the order
    is restored, as a backup job or a lagging replica would do. The fixture counts the DELETE requests it receives."""

    def __init__(self, inner):
        self.inner = inner
        self.removed = {}
        self.deletes = 0

    def __call__(self, req):
        oid = _order_id(req.path)
        if req.method == "DELETE" and req.token == "bob-token" and oid in self.inner.orders:
            self.deletes += 1
            self.removed[oid] = dict(self.inner.orders[oid])
            return self.inner(req)
        if req.method == "GET" and req.token == "alice-token" and oid in self.removed:
            resp = self.inner(req)
            self.inner.orders[oid] = self.removed.pop(oid)
            return resp
        return self.inner(req)


# --- reads: repeated ----------------------------------------------------------------------------------------------

def test_a_read_that_leaks_once_is_undetermined_when_the_second_read_does_not_repeat_it():
    with Fixture(_ReadOnce(OrdersApp({"GET": "allow", "PATCH": "deny", "DELETE": "deny"}))) as fx:
        found = _stateful(fx)
    assert not [f for f in found if f.check in s.BOLA_CHECKS], found
    reads = _select(found, method="GET")
    assert len(reads) == 1 and reads[0].check == "authorization-undetermined" and reads[0].status == "needs_input"
    assert reads[0].details["recheck"] == "not_reproduced"
    assert s._stateful_recheck_run(found, True)["not_reproduced"] == 1


def test_a_read_that_leaks_on_both_reads_is_confirmed_and_the_second_read_is_in_the_trail():
    log = []
    with Fixture(OrdersApp({"GET": "allow", "PATCH": "deny", "DELETE": "deny"})) as fx:
        found = _stateful(fx, log=log)
    confirmed = _select(found, check="stateful-authorization-boundary", method="GET")
    assert len(confirmed) == 1 and confirmed[0].details["recheck"] == "reproduced"
    rechecks = [e for e in log if e["kind"] == "recheck"]
    assert len(rechecks) == 1 and rechecks[0]["verb"] == "GET" and rechecks[0]["of"] == "attempt"
    assert rechecks[0]["status"] == 200


# --- writes: sent once, the owner's record is read again ------------------------------------------------------------

def test_a_write_is_sent_once_and_is_undetermined_when_its_effect_is_gone_on_the_re_read():
    log = []
    app = _ApplyThenRevert(OrdersApp({"GET": "deny", "PATCH": "allow", "DELETE": "deny"}))
    with Fixture(app) as fx:
        found = _stateful(fx, log=log)
    assert app.patches == 1, "the second pass must not send the write again"
    assert not _select(found, check="stateful-authorization-boundary", method="PATCH"), found
    patch = _select(found, check="authorization-undetermined", method="PATCH")
    assert len(patch) == 1 and patch[0].details["recheck"] == "not_reproduced"
    rechecks = [e for e in log if e["kind"] == "recheck"]
    assert len(rechecks) == 1 and rechecks[0]["verb"] == "GET" and rechecks[0]["of"] == "verify"


def test_a_delete_whose_record_is_back_on_the_re_read_is_undetermined():
    app = _DeleteThenRestore(OrdersApp({"GET": "deny", "PATCH": "deny", "DELETE": "allow"}))
    with Fixture(app) as fx:
        found = _stateful(fx)
    assert app.deletes == 1, "the second pass must not send the delete again"
    assert not _select(found, check="stateful-authorization-boundary", method="DELETE"), found
    gone = _select(found, check="authorization-undetermined", method="DELETE")
    assert len(gone) == 1 and gone[0].details["recheck"] == "not_reproduced"


def test_a_write_whose_effect_persists_is_confirmed_by_the_re_read_of_the_owner_record():
    with Fixture(OrdersApp({"GET": "deny", "PATCH": "allow", "DELETE": "deny"})) as fx:
        found = _stateful(fx)
    patch = _select(found, check="stateful-authorization-boundary", method="PATCH")
    assert len(patch) == 1 and patch[0].details["recheck"] == "reproduced"


# --- switched off: one observation, as before -----------------------------------------------------------------------

def test_no_recheck_keeps_the_one_observation_confirmation_for_reads_and_writes():
    log = []
    with Fixture(_ReadOnce(OrdersApp({"GET": "allow", "PATCH": "deny", "DELETE": "deny"}))) as fx:
        found_read = _stateful(fx, recheck=False, log=log)
    with Fixture(_ApplyThenRevert(OrdersApp({"GET": "deny", "PATCH": "allow", "DELETE": "deny"}))) as fx:
        found_write = _stateful(fx, recheck=False, log=log)
    assert [f.method for f in _select(found_read, check="stateful-authorization-boundary")] == ["GET"]
    write = _select(found_write, check="stateful-authorization-boundary", method="PATCH")
    assert len(write) == 1 and "recheck" not in write[0].details
    assert not any(e["kind"] == "recheck" for e in log)
    assert s._stateful_recheck_run(found_read + found_write, False)["candidates"] == 0


# --- a second read that cannot be made -------------------------------------------------------------------------------

def test_a_second_read_that_cannot_be_made_leaves_the_read_not_rechecked_and_the_flow_completes():
    real_request = s.request
    bob_reads = []

    def flaky(method, url, headers, **kwargs):
        if method == "GET" and headers.get("Authorization") == "Bearer bob-token":
            bob_reads.append(url)
            if len(bob_reads) == 2:
                raise s.TransportError("connection reset by peer")
        return real_request(method, url, headers, **kwargs)

    with Fixture(OrdersApp({"GET": "allow", "PATCH": "deny", "DELETE": "deny"})) as fx, \
            mock.patch.object(s, "request", flaky):
        found = _stateful(fx)
    assert len(bob_reads) == 2
    assert not [f for f in found if f.check in s.BOLA_CHECKS], found
    reads = _select(found, method="GET")
    assert len(reads) == 1 and reads[0].details["recheck"] == "not_rechecked"
    assert "could not complete" in reads[0].evidence[0]
    assert not [f for f in found if f.status == "residue"]
    assert s._stateful_recheck_run(found, True)["not_rechecked"] == 1


# --- the summary --------------------------------------------------------------------------------------------------------

def _finding(recheck=None):
    details = {"owner_identity": "alice"} if recheck is None else {"owner_identity": "alice", "recheck": recheck}
    return s.Finding("authorization-undetermined", "info", "low", 0, ["x"], "y", "/orders/1", "GET",
                     status="needs_input", details=details)


def test_the_stateful_summary_counts_only_the_findings_that_went_through_the_second_pass():
    run = s._stateful_recheck_run([_finding("reproduced"), _finding("not_reproduced"), _finding("not_rechecked"),
                                   _finding()], True)
    assert (run["scope"], run["ran"], run["candidates"]) == ("stateful", True, 3)
    assert (run["reproduced"], run["not_reproduced"], run["not_rechecked"], run["second_pass_only"]) == (1, 1, 1, 0)
    assert s.recheck_report(True, [run])["totals"]["candidates"] == 3
    assert s._stateful_recheck_run([_finding()], True)["ran"] is False
    assert s._stateful_recheck_run([_finding("reproduced")], False)["ran"] is False


# --- the command line -------------------------------------------------------------------------------------------------

def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


def _stateful_argv(fx, identities_path, output, *extra):
    return ["--yes-i-am-authorized", "--url", fx.base + ORDERS, "--identities", identities_path,
            "--output", output, "--stateful", "--allow-destructive", "--collection-url", fx.base + "/orders", *extra]


def test_the_command_line_reports_the_stateful_second_read_and_no_recheck_turns_it_off():
    with tempfile.TemporaryDirectory() as td:
        ids = Path(td) / "identities.json"
        ids.write_text(json.dumps({"identities": [ALICE_BARE, BOB_BARE]}), encoding="utf-8")
        on, off = Path(td) / "on.json", Path(td) / "off.json"
        with Fixture(_ReadOnce(OrdersApp({"GET": "allow", "PATCH": "deny", "DELETE": "deny"}))) as fx:
            code_on, text_on, _ = run_cli(_stateful_argv(fx, str(ids), str(on)))
        with Fixture(_ReadOnce(OrdersApp({"GET": "allow", "PATCH": "deny", "DELETE": "deny"}))) as fx:
            code_off, _, _ = run_cli(_stateful_argv(fx, str(ids), str(off), "--no-recheck"))
        rep_on = json.loads(on.read_text(encoding="utf-8"))
        rep_off = json.loads(off.read_text(encoding="utf-8"))
    assert code_on == s.EXIT_UNDETERMINED and "1 did not reproduce" in text_on
    assert rep_on["summary"]["confirmed"] == 0 and rep_on["recheck"]["runs"][0]["scope"] == "stateful"
    assert rep_on["recheck"]["totals"]["not_reproduced"] == 1
    assert code_off == s.EXIT_POLICY and rep_off["summary"]["confirmed"] == 1
    assert rep_off["recheck"]["enabled"] is False and rep_off["recheck"]["totals"]["candidates"] == 0
