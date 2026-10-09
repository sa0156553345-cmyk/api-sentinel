"""Engine unit tests: evidence rules, owner verification, cross-user and same-user access, undetermined results,
write effects, opt-in refusals, cleanup, coverage, report categories, SARIF and HTML.

Each test serves a small fixture on loopback and calls the real engine. The expected values are written here, from what
the rule is supposed to do, and are not read back from the implementation.
"""
from __future__ import annotations

import re
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import api_sentinel as s  # noqa: E402
from authz_matrix.fixtures import (CollectionApp, Fixture, NestedApp, OrdersApp, ReprApp, Resp,  # noqa: E402
                                   make_order, seed_orders)

ORDERS = "/orders/{id}"
OWN = s.OWNER_FIELDS_DEFAULT


def alice(owns=("1001",), **kw):
    return s.Identity("alice", {"Authorization": "Bearer alice-token"}, list(owns),
                      params=dict(kw.get("params", {})), owner_values=dict(kw.get("owner_values", {})))


def bob(owns=(), **kw):
    return s.Identity("bob", {"Authorization": "Bearer bob-token"}, list(owns),
                      params=dict(kw.get("params", {})), owner_values=dict(kw.get("owner_values", {})))


def confirmed(findings):
    return [f for f in findings if f.check in s.BOLA_CHECKS]


def undetermined(findings):
    return [f for f in findings if f.status == "needs_input"]


class Recorder:
    """Counts the requests that actually reach a fixture, to prove that nothing was sent."""

    def __init__(self, app):
        self.app = app
        self.calls = []

    def __call__(self, req):
        self.calls.append((req.method, req.path))
        return self.app(req)


def _closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- matrix: evidence rules ---------------------------------------------------------

def test_vulnerable_cross_user_read_is_confirmed_with_evidence():
    with Fixture(OrdersApp({"GET": "allow"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    c = confirmed(found)
    assert len(c) == 1, found
    assert c[0].details["owner_identity"] == "alice" and c[0].details["accessing_identity"] == "bob"
    assert c[0].details["http_status"] == 200 and c[0].severity == "critical"
    assert any("resource_id=1001" in e for e in c[0].evidence)


def test_enforced_ownership_yields_nothing():
    with Fixture(OrdersApp({"GET": "deny"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    assert found == []


def test_owner_reading_their_own_resource_is_never_judged():
    with Fixture(OrdersApp({"GET": "allow"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    assert not [f for f in found if f.details and f.details.get("accessing_identity") == "alice"]


def test_status_200_with_an_error_body_is_not_evidence():
    with Fixture(OrdersApp({"GET": "soft_error"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    assert found == []


def test_schema_match_alone_is_not_evidence():
    """A placeholder with the same keys and types as a real record is not the resource."""
    with Fixture(OrdersApp({"GET": "placeholder"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    assert found == []


def test_a_403_whose_body_carries_the_record_is_detected():
    with Fixture(OrdersApp({"GET": "deny_leak"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    c = confirmed(found)
    assert len(c) == 1 and c[0].details["http_status"] == 403
    assert any("still carries the record" in e for e in c[0].evidence)


def test_identical_body_without_an_identifier_is_undetermined_not_confirmed():
    with Fixture(OrdersApp({"GET": "allow"}, view="no_id")) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    assert confirmed(found) == []
    assert undetermined(found) and all(f.check == "authorization-undetermined" for f in undetermined(found))


def test_owner_record_contradicting_the_declared_owner_is_undetermined():
    with Fixture(OrdersApp({"GET": "allow"}, orders={1001: make_order(1001, 7)})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(owner_values={"user_id": 42}), bob()],
                                              "GET", OWN, 5)
    assert confirmed(found) == []
    assert undetermined(found)
    assert any("contradicts the declared owner" in e for f in undetermined(found) for e in f.evidence)


def test_empty_owner_field_makes_an_identical_copy_undetermined():
    app = OrdersApp({"GET": "deny"}, orders={9001: make_order(9001, None, "Guest order", 5.0)}, ownerless_open=True)
    with Fixture(app) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(("9001",)), bob()], "GET", OWN, 5)
    assert confirmed(found) == []
    assert undetermined(found)


def test_collection_item_absent_from_another_users_list_is_not_confirmed():
    with Fixture(CollectionApp("scoped")) as fx:
        found, _ = s.run_authorization_matrix(fx.base + "/orders", [alice(), bob(("2001",))], "GET", OWN, 5)
    assert confirmed(found) == []


def test_collection_item_present_in_another_users_list_is_confirmed_both_ways():
    with Fixture(CollectionApp("leaky")) as fx:
        found, _ = s.run_authorization_matrix(fx.base + "/orders", [alice(), bob(("2001",))], "GET", OWN, 5)
    pairs = {(f.details["owner_identity"], f.details["accessing_identity"]) for f in confirmed(found)}
    assert pairs == {("alice", "bob"), ("bob", "alice")}


def test_parent_substitution_finds_a_child_leak_that_a_fixed_parent_cannot():
    a = alice(params={"user_id": "42"})
    b = bob(("2001",), params={"user_id": "91"})
    with Fixture(NestedApp("child_vuln")) as fx:
        found, _ = s.run_authorization_matrix(fx.base + "/users/{user_id}/orders/{id}", [a, b], "GET", OWN, 5)
    pairs = {(f.details["owner_identity"], f.details["accessing_identity"]) for f in confirmed(found)}
    assert ("alice", "bob") in pairs and ("bob", "alice") in pairs


def test_child_with_an_owner_check_is_not_confirmed():
    a = alice(params={"user_id": "42"})
    b = bob(("2001",), params={"user_id": "91"})
    with Fixture(NestedApp("child_secure")) as fx:
        found, _ = s.run_authorization_matrix(fx.base + "/users/{user_id}/orders/{id}", [a, b], "GET", OWN, 5)
    assert confirmed(found) == []


def test_partial_status_view_is_silent_by_design():
    with Fixture(OrdersApp({"GET": "partial_status"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "GET", OWN, 5)
    assert confirmed(found) == [] and undetermined(found) == []


def test_a_parameter_with_no_value_for_an_identity_is_a_configuration_error():
    rec = Recorder(NestedApp("child_vuln"))
    with Fixture(rec) as fx:
        try:
            s.run_authorization_matrix(fx.base + "/users/{user_id}/orders/{id}", [alice(), bob()], "GET", OWN, 5)
        except s.ConfigError as exc:
            assert "params.user_id" in str(exc)
        else:
            raise AssertionError("expected ConfigError")
    assert rec.calls == []


def test_matrix_refuses_a_non_get_method_before_any_request():
    rec = Recorder(OrdersApp({"DELETE": "allow"}))
    with Fixture(rec) as fx:
        try:
            s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob()], "DELETE", OWN, 5)
        except s.ConfigError as exc:
            assert "read-only" in str(exc)
        else:
            raise AssertionError("expected ConfigError")
    assert rec.calls == [] and 1001 in rec.app.orders


# --- stateful: writes, opt-in, cleanup ----------------------------------------------------

def _stateful(fx, identities, allow=True, log=None):
    return s.run_stateful_flow(fx.base + "/orders", fx.base + ORDERS, identities,
                               {"item": "test", "total": 9.99}, 5, allow_destructive=allow,
                               owner_fields=OWN, log=log)


def test_stateful_refuses_without_the_opt_in_before_any_request():
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with Fixture(rec) as fx:
        try:
            _stateful(fx, [alice(()), bob(())], allow=False)
        except s.DestructiveOperationRefused as exc:
            assert "--allow-destructive" in str(exc)
        else:
            raise AssertionError("expected DestructiveOperationRefused")
    assert rec.calls == []


def test_a_write_that_has_no_effect_is_not_a_finding():
    with Fixture(OrdersApp({"GET": "hide", "PATCH": "noop", "DELETE": "noop"})) as fx:
        found = _stateful(fx, [alice(()), bob(())])
    assert not [f for f in found if f.check == "stateful-authorization-boundary"]
    assert any(f.check == "stateful-no-effect" and f.method == "PATCH" for f in found)


def test_a_write_applied_despite_a_403_is_critical():
    with Fixture(OrdersApp({"GET": "deny", "PATCH": "blind", "DELETE": "deny"})) as fx:
        found = _stateful(fx, [alice(()), bob(())])
    hits = [f for f in found if f.check == "stateful-authorization-boundary"]
    assert len(hits) == 1 and hits[0].method == "PATCH" and hits[0].severity == "critical"


class _AcceptsButIgnores:
    """Answers 202 Accepted to writes and never applies them. Creation and reads behave normally."""

    def __init__(self):
        self.orders = seed_orders()
        self.next_id = 5000

    def __call__(self, req):
        owner = {"alice-token": 42, "bob-token": 91}.get(req.token)
        if owner is None:
            return Resp(401, {"error": "unauthorized"})
        if req.method == "POST" and req.path == "/orders":
            oid, self.next_id = self.next_id, self.next_id + 1
            self.orders[oid] = make_order(oid, owner, "test", 9.99)
            return Resp(201, dict(self.orders[oid]))
        try:
            oid = int(req.path.rsplit("/", 1)[-1])
        except ValueError:
            return Resp(404, {"error": "not found"})
        order = self.orders.get(oid)
        if order is None:
            return Resp(404, {"error": "not found"})
        if req.method == "GET":
            return Resp(200, dict(order)) if order["user_id"] == owner else Resp(403, {"error": "forbidden"})
        return Resp(202, {"status": "accepted"})


def test_a_202_whose_effect_never_appears_is_undetermined_not_confirmed():
    with Fixture(_AcceptsButIgnores()) as fx:
        found = _stateful(fx, [alice(()), bob(())])
    assert not [f for f in found if f.check == "stateful-authorization-boundary"]
    assert {f.method for f in undetermined(found)} >= {"PATCH", "DELETE"}


def test_stateful_run_leaves_the_target_as_it_found_it():
    app = OrdersApp({"GET": "deny", "PATCH": "deny", "DELETE": "deny"})
    with Fixture(app) as fx:
        found = _stateful(fx, [alice(()), bob(())])
    assert set(app.orders) == {1001, 2001, 3001}
    assert not [f for f in found if f.status == "residue"]


def test_coverage_counts_what_actually_ran():
    # both identities own a resource, so both are owner baselines and both are accessors of the other
    with Fixture(OrdersApp({"GET": "allow"})) as fx:
        found, trail = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob(("2001",))], "GET", OWN, 5)
    cov = s._coverage([alice(), bob(("2001",))], found, trail)
    assert cov["checks_run"] == 2 and cov["confirmed"] == 2 and cov["passed"] == 0
    assert cov["requests_sent"] == len(trail) == 4          # two owner baselines and two accessor reads
    assert cov["owned_resources_tested"] == 2


# --- reports ------------------------------------------------------------------------------

def _sample_findings():
    d = {"owner_identity": "alice", "accessing_identity": "bob", "resource_id": "1001", "http_status": 200,
         "response_bytes": 10}
    return [
        s.Finding("authorization-boundary", "critical", "high", 90, ["leak"], "verify", "http://x/orders/1001", "GET",
                  details=d),
        s.Finding("authorization-undetermined", "info", "low", 0, ["cannot decide"], "provide input",
                  "http://x/orders/2001", "GET", status="needs_input", details=d),
        s.Finding("authorization-incomplete", "info", "low", 0, ["no baseline"], "fix input", "http://x/orders/9",
                  "GET", status="skipped", details={"owner_identity": "carol"}),
        s.Finding("stateful-cleanup", "info", "high", 0, ["left behind"], "remove", "http://x/orders", "DELETE",
                  status="residue", details={"owner_identity": "alice"}),
        s.Finding("stateful-no-effect", "info", "high", 0, ["no change"], "none", "http://x/orders/3", "PATCH",
                  status="no_effect", details=d),
    ]


def test_report_categories_partition_the_findings():
    findings = _sample_findings()
    rep = s.make_report("http://x", None, findings, {"checks_run": 0}, "incomplete")
    assert [f["category"] for f in rep["findings"]] == ["confirmed", "undetermined", "incomplete", "residue", "info"]
    assert rep["summary"] == {"confirmed": 1, "undetermined": 1, "incomplete": 1, "residue": 1, "info": 1}
    assert sum(rep["summary"].values()) == len(findings)
    assert rep["version"] == s.__version__ and rep["schema_version"] == 2 and rep["status"] == "incomplete"


def test_sarif_contains_only_confirmed_findings_and_the_tool_version():
    rep = s.make_report("http://x", None, _sample_findings(), {}, "incomplete")
    sarif = s.render_sarif(rep, "identities.json")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["version"] == s.__version__
    assert len(run["results"]) == 1 and run["results"][0]["ruleId"] == "authorization-boundary"
    assert run["results"][0]["level"] == "error"


def test_html_shows_confirmed_and_undetermined_as_different_things():
    rep = s.make_report("http://x", None, _sample_findings(), {"checks_run": 0, "passed": 0, "requests_sent": 0,
                                                              "owned_resources_tested": 0}, "incomplete")
    html = s.render_html(rep)
    assert "CONFIRMED" in html and "UNDETERMINED" in html and "INCOMPLETE" in html


def test_version_has_a_single_source_of_truth():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "%s"$' % re.escape(s.__version__), text, re.M)


def test_transport_failure_raises_transport_error_not_a_crash():
    try:
        s.request("GET", f"http://127.0.0.1:{_closed_port()}/x", {}, timeout=2)
    except s.TransportError:
        return
    raise AssertionError("expected TransportError")


def test_every_confirmed_finding_carries_the_confirmed_status_and_an_expected_line():
    with Fixture(OrdersApp({"GET": "allow"})) as fx:
        found, _ = s.run_authorization_matrix(fx.base + ORDERS, [alice(), bob(("2001",))], "GET", OWN, 5)
    c = confirmed(found)
    assert c and all(f.status == "confirmed" for f in c)
    assert all(any(e.startswith("expected: ") and "must not receive" in e for e in f.evidence) for f in c)
