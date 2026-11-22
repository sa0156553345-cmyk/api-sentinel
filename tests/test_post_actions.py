"""POST sub-actions (--actions): an operation such as /cancel is sent once as a non-owner, on a resource the first identity
created, and judged by the owner's own record. The rule: an action has taken effect when the owner's record shows its
'expect' values after the request and did not show them before it. A record that already shows them cannot show the
effect, so nothing is sent. The status code of the request is never the evidence. Expected values are written from that
rule, not read back from the implementation.
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
from authz_matrix.fixtures import (Fixture, OrdersApp, Resp, forbidden, not_found, parts_of,  # noqa: E402
                                   unauthorized, user_of)

OWN = s.OWNER_FIELDS_DEFAULT
ORDERS = "/orders/{id}"
EXPECT = {"status": "cancelled"}
URL = "https://api.example.test/orders/{id}/cancel"
BARE_ALICE = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": []}
BARE_BOB = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": []}
OWNING_ALICE = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}
OWNING_BOB = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": ["2001"]}


def _alice(params=None):
    return s.Identity("alice", {"Authorization": "Bearer alice-token"}, [], params=params or {}, owner_values={})


def _bob(params=None):
    return s.Identity("bob", {"Authorization": "Bearer bob-token"}, [], params=params or {}, owner_values={})


def _cancel(fx):
    return [s.PostAction("cancel", fx.base + "/orders/{id}/cancel", {}, dict(EXPECT))]


def _run_flow(fx, actions, **kwargs):
    return s.run_stateful_flow(fx.base + "/orders", fx.base + ORDERS, [_alice(), _bob()],
                               {"item": "test", "total": 9.99}, 5, allow_destructive=True, owner_fields=OWN,
                               actions=actions, **kwargs)


def _select(findings, check=None, method=None):
    return [f for f in findings
            if (check is None or f.check == check) and (method is None or f.method == method)]


def _order_of(req):
    parts = parts_of(req)
    return int(parts[1]) if len(parts) >= 2 and parts[0] == "orders" and parts[1].isdigit() else None


def _write(directory, name, document):
    path = Path(directory) / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def _loads(document):
    with tempfile.TemporaryDirectory() as td:
        return s.load_post_actions(_write(td, "actions.json", document))


def _cancel_document(fx):
    return {"actions": [{"name": "cancel", "url": fx.base + "/orders/{id}/cancel", "expect": dict(EXPECT)}]}


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


def _stateful_argv(fx, identities_path, output, *extra):
    return ["--yes-i-am-authorized", "--url", fx.base + ORDERS, "--identities", identities_path,
            "--output", output, "--stateful", "--allow-destructive", "--collection-url", fx.base + "/orders", *extra]


class _Recording:
    """Passes every request to the inner application and keeps each request's method and path."""

    def __init__(self, inner):
        self.inner = inner
        self.seen = []

    def __call__(self, req):
        self.seen.append(f"{req.method} {req.path}")
        return self.inner(req)


class _CancelThenRevert:
    """A non-owner's cancel is applied. The owner's first read after it shows the cancellation, and then the record is put
    back, as a rollback or a lagging replica would do. The fixture counts the cancel requests it receives."""

    def __init__(self, inner):
        self.inner = inner
        self.undo = {}
        self.cancels = 0

    def __call__(self, req):
        oid = _order_of(req)
        if req.method == "POST" and parts_of(req)[-1:] == ["cancel"] and req.token == "bob-token" \
                and oid in self.inner.orders:
            self.cancels += 1
            self.undo[oid] = dict(self.inner.orders[oid])
            return self.inner(req)
        if req.method == "GET" and req.token == "alice-token" and oid in self.undo:
            resp = self.inner(req)
            self.inner.orders[oid] = self.undo.pop(oid)
            return resp
        return self.inner(req)


class _CreatedCancelled:
    """Every order is created already cancelled, so the owner's record shows the action's result before any request."""

    def __init__(self, inner):
        self.inner = inner
        self.cancels = 0

    def __call__(self, req):
        if req.method == "POST" and parts_of(req)[-1:] == ["cancel"]:
            self.cancels += 1
        resp = self.inner(req)
        if req.method == "POST" and parts_of(req) == ["orders"] and resp.status == 201:
            self.inner.orders[resp.body["id"]]["status"] = "cancelled"
            resp.body["status"] = "cancelled"
        return resp


class _ParentOnlyChecks:
    """/users/{uid}/orders. The caller must be user uid, but nothing checks that an order inside the path belongs to the
    caller. The owner's own requests succeed, so the owner reads and the cleanup work. Counts every cancel request."""

    def __init__(self):
        self.orders = {}
        self.next_id = 7000
        self.cancel_posts = 0

    def __call__(self, req):
        parts = parts_of(req)
        if req.method == "POST" and parts[-1:] == ["cancel"]:
            self.cancel_posts += 1
        user = user_of(req)
        if not user:
            return unauthorized()
        if len(parts) < 3 or parts[0] != "users" or parts[2] != "orders":
            return not_found()
        if str(user["id"]) != parts[1]:
            return forbidden()
        if len(parts) == 3 and req.method == "POST":
            new = self.next_id
            self.next_id += 1
            self.orders[new] = {"id": new, "user_id": user["id"], "item": "test", "total": 9.99}
            return Resp(201, dict(self.orders[new]))
        oid = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None
        order = self.orders.get(oid)
        if order is None:
            return not_found()
        if len(parts) == 4 and req.method == "GET":
            return Resp(200, dict(order))
        if len(parts) == 4 and req.method == "DELETE":
            del self.orders[oid]
            return Resp(204)
        if len(parts) == 5 and parts[4] == "cancel" and req.method == "POST":
            order["status"] = "cancelled"
            return Resp(200, dict(order))
        return Resp(405, {"error": "method not allowed"})


# --- the loader ------------------------------------------------------------------------------------------------------

def test_a_well_formed_actions_file_loads_and_an_omitted_body_is_an_empty_object():
    found = _loads({"actions": [{"name": "cancel", "url": URL, "expect": {"status": "cancelled"}}]})
    assert [(a.name, a.url, a.body, a.expect) for a in found] == [("cancel", URL, {}, {"status": "cancelled"})]


REFUSED = {
    "no actions list": {"actions": []},
    "a document that is not an object": ["cancel"],
    "an action that is not an object": {"actions": ["cancel"]},
    "no name": {"actions": [{"url": URL, "expect": EXPECT}]},
    "a name that is an HTTP method": {"actions": [{"name": "post", "url": URL, "expect": EXPECT}]},
    "a name with a space": {"actions": [{"name": "cancel now", "url": URL, "expect": EXPECT}]},
    "a duplicate name": {"actions": [{"name": "cancel", "url": URL, "expect": EXPECT},
                                     {"name": "cancel", "url": URL, "expect": EXPECT}]},
    "an unknown key": {"actions": [{"name": "cancel", "url": URL, "expect": EXPECT, "method": "POST"}]},
    "no url": {"actions": [{"name": "cancel", "expect": EXPECT}]},
    "a url without {id}": {"actions": [{"name": "cancel", "url": "https://api.example.test/orders/1/cancel",
                                        "expect": EXPECT}]},
    "a url that is not http": {"actions": [{"name": "cancel", "url": "ftp://api.example.test/orders/{id}/cancel",
                                            "expect": EXPECT}]},
    "a body that is not an object": {"actions": [{"name": "cancel", "url": URL, "body": ["x"], "expect": EXPECT}]},
    "no expect": {"actions": [{"name": "cancel", "url": URL}]},
    "an empty expect": {"actions": [{"name": "cancel", "url": URL, "expect": {}}]},
    "a null expected value": {"actions": [{"name": "cancel", "url": URL, "expect": {"status": None}}]},
}


def test_the_loader_refuses_every_document_it_cannot_run():
    for label, document in REFUSED.items():
        try:
            _loads(document)
        except s.ConfigError as exc:
            assert exc.exit_code == s.EXIT_CONFIG, label
            continue
        raise AssertionError(f"accepted a bad actions file: {label}")
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "actions.json"
        path.write_text("{not json", encoding="utf-8")
        try:
            s.load_post_actions(str(path))
        except s.ConfigError as exc:
            assert "not readable JSON" in str(exc), exc
        else:
            raise AssertionError("accepted a file that is not JSON")


def test_an_action_on_a_host_that_allow_host_does_not_name_is_refused_before_any_request():
    previous = s._ALLOWED_HOSTS
    s._ALLOWED_HOSTS = frozenset({"127.0.0.1"})
    try:
        try:
            _loads({"actions": [{"name": "cancel", "url": "https://api.internal.test/orders/{id}/cancel",
                                 "expect": EXPECT}]})
        except s.ConfigError as exc:
            assert "not in --allow-host" in str(exc), exc
        else:
            raise AssertionError("an action outside --allow-host was accepted")
    finally:
        s._ALLOWED_HOSTS = previous


# --- the engine: one action, judged by the owner's record ----------------------------------------------------------------

def test_an_action_whose_effect_persists_is_confirmed_by_the_owners_record_and_sent_once():
    log = []
    app = _Recording(OrdersApp({"cancel": "allow"}))
    with Fixture(app) as fx:
        found = _run_flow(fx, _cancel(fx), log=log)
    confirmed = _select(found, check="stateful-authorization-boundary", method="POST")
    assert len(confirmed) == 1, found
    d = confirmed[0].details
    assert (d["action"], d["workflow"], d["owner_identity"], d["accessing_identity"], d["recheck"]) == (
        "cancel", "create-then-action", "alice", "bob", "reproduced"), d
    sent = [e for e in log if e["kind"] == "attempt" and e.get("action") == "cancel"]
    assert len(sent) == 1 and sent[0]["status"] == 200, sent
    received = [r for r in app.seen if r.startswith("POST ") and r.endswith("/cancel")]
    assert len(received) == 1, "the server must receive the action once, not only the log"
    owner_reads = [e for e in log if e["kind"] == "recheck" and e["of"] == "verify"]
    assert len(owner_reads) == 1 and owner_reads[0]["verb"] == "GET" and owner_reads[0]["owner"] == "alice", owner_reads


def test_a_refused_action_that_changed_nothing_is_not_a_finding():
    log = []
    with Fixture(OrdersApp({"cancel": "deny"})) as fx:
        found = _run_flow(fx, _cancel(fx), log=log)
    assert not [f for f in found if f.check in s.BOLA_CHECKS], found
    assert not [f for f in found if (f.details or {}).get("action") == "cancel"], found
    assert len([e for e in log if e.get("action") == "cancel"]) == 1


def test_a_success_status_without_an_effect_is_no_effect_and_its_advice_names_the_expect_values():
    with Fixture(OrdersApp({"cancel": "noop"})) as fx:
        found = _run_flow(fx, _cancel(fx))
    no_effect = _select(found, check="stateful-no-effect", method="POST")
    assert len(no_effect) == 1 and no_effect[0].status == "no_effect", found
    assert no_effect[0].details["action"] == "cancel"
    assert "'expect'" in no_effect[0].recommendation, no_effect[0].recommendation
    assert not [f for f in found if f.check in s.BOLA_CHECKS], found


def test_an_action_applied_but_answered_403_or_202_is_confirmed_because_the_record_shows_it():
    for mode, status in (("blind", 403), ("async", 202)):
        with Fixture(OrdersApp({"cancel": mode})) as fx:
            found = _run_flow(fx, _cancel(fx))
        confirmed = _select(found, check="stateful-authorization-boundary", method="POST")
        assert len(confirmed) == 1 and confirmed[0].details["http_status"] == status, (mode, found)


def test_an_action_whose_effect_is_gone_on_the_re_read_is_undetermined_and_is_not_sent_twice():
    app = _CancelThenRevert(OrdersApp({"cancel": "allow"}))
    with Fixture(app) as fx:
        found = _run_flow(fx, _cancel(fx))
    assert app.cancels == 1, "the second pass must not send the action again"
    assert not _select(found, check="stateful-authorization-boundary"), found
    gone = _select(found, check="authorization-undetermined", method="POST")
    assert len(gone) == 1 and gone[0].details["recheck"] == "not_reproduced", found


def test_an_action_is_sent_when_its_record_shows_only_part_of_the_expected_result():
    """'Already shows' means every expected value, not some of them: the total below matches before the request, the
    status does not, so the effect is still visible and the action must be sent."""
    app = _Recording(OrdersApp({"cancel": "allow"}))
    with Fixture(app) as fx:
        actions = [s.PostAction("cancel", fx.base + "/orders/{id}/cancel", {}, {"status": "cancelled", "total": 9.99})]
        found = _run_flow(fx, actions)
    assert len([r for r in app.seen if r.endswith("/cancel")]) == 1, app.seen
    confirmed = _select(found, check="stateful-authorization-boundary", method="POST")
    assert len(confirmed) == 1, found


def test_an_action_is_not_sent_when_the_owners_record_already_shows_its_result():
    app = _CreatedCancelled(OrdersApp({"cancel": "allow"}))
    with Fixture(app) as fx:
        found = _run_flow(fx, _cancel(fx))
    assert app.cancels == 0, "no request may be sent when its effect cannot be seen"
    undetermined = _select(found, check="authorization-undetermined", method="POST")
    assert len(undetermined) == 1 and undetermined[0].status == "needs_input", found
    assert "already shows" in undetermined[0].evidence[0], undetermined[0].evidence
    assert not [f for f in found if f.check in s.BOLA_CHECKS], found


def test_an_action_the_target_rejects_with_422_is_undetermined_and_nothing_is_concluded():
    with Fixture(OrdersApp({"cancel": "validation"})) as fx:
        found = _run_flow(fx, _cancel(fx))
    rejected = _select(found, check="authorization-undetermined", method="POST")
    assert len(rejected) == 1 and "HTTP 422" in rejected[0].evidence[0], found
    assert not [f for f in found if f.check in s.BOLA_CHECKS], found


def test_an_action_is_tried_on_the_accessors_own_parent_segment_as_the_verbs_are():
    app = _ParentOnlyChecks()
    with Fixture(app) as fx:
        found = s.run_stateful_flow(
            fx.base + "/users/{user_id}/orders", fx.base + "/users/{user_id}/orders/{id}",
            [_alice({"user_id": "42"}), _bob({"user_id": "91"})], {"item": "test", "total": 9.99}, 5,
            allow_destructive=True, owner_fields=OWN,
            actions=[s.PostAction("cancel", fx.base + "/users/{user_id}/orders/{id}/cancel", {}, dict(EXPECT))])
    confirmed = _select(found, check="stateful-authorization-boundary", method="POST")
    assert len(confirmed) == 1, found
    assert confirmed[0].endpoint.startswith(fx.base + "/users/91/orders/"), confirmed[0].endpoint
    assert app.cancel_posts == 2, "one request per URL variant: the owner's own parent is refused, the accessor's is not"


def test_a_second_read_of_the_owners_record_that_cannot_be_made_leaves_the_action_not_rechecked():
    real_request = s.request
    state = {"armed": False, "owner_reads": 0}

    def flaky(method, url, headers, **kwargs):
        if method == "POST" and url.endswith("/cancel"):
            state["armed"] = True
        elif method == "GET" and state["armed"] and headers.get("Authorization") == "Bearer alice-token":
            state["owner_reads"] += 1
            if state["owner_reads"] == 2:  # the first is the owner's read after the action, the second the re-read
                raise s.TransportError("connection reset by peer")
        return real_request(method, url, headers, **kwargs)

    with Fixture(OrdersApp({"cancel": "allow"})) as fx, mock.patch.object(s, "request", flaky):
        found = _run_flow(fx, _cancel(fx))
    downgraded = _select(found, method="POST")
    assert len(downgraded) == 1 and downgraded[0].details["recheck"] == "not_rechecked", found
    assert "could not complete" in downgraded[0].evidence[0], downgraded[0].evidence
    assert not [f for f in found if f.status == "residue"], found


def test_without_the_second_pass_one_observation_confirms_the_action_and_nothing_is_repeated():
    log = []
    app = _Recording(OrdersApp({"cancel": "allow"}))
    with Fixture(app) as fx:
        found = _run_flow(fx, _cancel(fx), recheck=False, log=log)
    confirmed = _select(found, check="stateful-authorization-boundary", method="POST")
    assert len(confirmed) == 1 and "recheck" not in confirmed[0].details, found
    assert not any(e["kind"] == "recheck" for e in log)
    assert len([e for e in log if e.get("action") == "cancel"]) == 1
    assert len([r for r in app.seen if r.endswith("/cancel")]) == 1, app.seen


def test_two_actions_are_judged_by_their_own_names():
    with Fixture(OrdersApp({"cancel": "allow", "ship": "deny"})) as fx:
        actions = _cancel(fx) + [s.PostAction("ship", fx.base + "/orders/{id}/ship", {}, {"status": "shipped"})]
        found = _run_flow(fx, actions)
    confirmed = _select(found, check="stateful-authorization-boundary", method="POST")
    assert [f.details["action"] for f in confirmed] == ["cancel"], found
    assert not [f for f in found if (f.details or {}).get("action") == "ship"], found


# --- the command line ----------------------------------------------------------------------------------------------------

def test_the_command_line_refuses_actions_without_stateful_before_any_request():
    with tempfile.TemporaryDirectory() as td:
        ids = _write(td, "identities.json", {"identities": [OWNING_ALICE, OWNING_BOB]})
        app = _Recording(OrdersApp({"cancel": "allow"}))
        with Fixture(app) as fx:
            acts = _write(td, "actions.json", _cancel_document(fx))
            code, _, err = run_cli(["--yes-i-am-authorized", "--url", fx.base + ORDERS, "--identities", ids,
                                    "--actions", acts, "--output", str(Path(td) / "report.json")])
    assert code == s.EXIT_CONFIG and "--stateful" in err, (code, err)
    assert app.seen == [], app.seen


def test_the_command_line_reports_a_confirmed_action_by_name_and_exits_one():
    with tempfile.TemporaryDirectory() as td:
        ids = _write(td, "identities.json", {"identities": [BARE_ALICE, BARE_BOB]})
        report = Path(td) / "report.json"
        with Fixture(OrdersApp({"cancel": "allow"})) as fx:
            acts = _write(td, "actions.json", _cancel_document(fx))
            code, text, _ = run_cli(_stateful_argv(fx, ids, str(report), "--actions", acts))
        data = json.loads(report.read_text(encoding="utf-8"))
    assert code == s.EXIT_POLICY, code
    assert "1 POST action(s)" in text, text
    assert "Action:              cancel" in text, text
    confirmed = [f for f in data["findings"] if f["check"] == "stateful-authorization-boundary"]
    assert len(confirmed) == 1 and confirmed[0]["method"] == "POST", confirmed
    assert confirmed[0]["details"]["action"] == "cancel"
    assert data["summary"]["confirmed"] == 1


def test_a_bad_actions_file_is_a_configuration_error_and_nothing_is_sent():
    with tempfile.TemporaryDirectory() as td:
        ids = _write(td, "identities.json", {"identities": [BARE_ALICE, BARE_BOB]})
        app = _Recording(OrdersApp({"cancel": "allow"}))
        with Fixture(app) as fx:
            acts = _write(td, "actions.json",
                          {"actions": [{"name": "cancel", "url": fx.base + "/orders/{id}/cancel"}]})
            code, _, err = run_cli(_stateful_argv(fx, ids, str(Path(td) / "report.json"), "--actions", acts))
    assert code == s.EXIT_CONFIG and "'expect'" in err, (code, err)
    assert app.seen == [], app.seen
