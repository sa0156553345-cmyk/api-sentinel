"""Ownership discovery (--discover) and OpenAPI plan mode (--openapi --base-url).

Expected values are written from what the rules say, not read back from the implementation. Every test serves a
loopback fixture and calls the real engine or CLI.
"""
from __future__ import annotations

import contextlib
import io
import json
import socket
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import api_sentinel as s  # noqa: E402
from authz_matrix.fixtures import CollectionApp, Fixture, NestedApp, OrdersApp, Resp, parts_of  # noqa: E402
from test_engine import Recorder  # noqa: E402

OWN = s.OWNER_FIELDS_DEFAULT


class ListAndItems:
    """GET /orders is answered by a listing app; every other route by an item app."""

    def __init__(self, listing, items):
        self.listing, self.items = listing, items

    def __call__(self, req):
        if parts_of(req) == ["orders"] and req.method == "GET":
            return self.listing(req)
        return self.items(req)


def ident(name, token, owns=(), owner_values=None):
    return s.Identity(name, {"Authorization": f"Bearer {token}"}, list(owns), params={},
                      owner_values=dict(owner_values or {}))


def alice(**kw):
    return ident("alice", "alice-token", **kw)


def bob(**kw):
    return ident("bob", "bob-token", **kw)


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


def write_json(folder, name, doc):
    path = Path(folder) / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def identities_file(folder, entries):
    return write_json(folder, "identities.json", {"identities": entries})


ALICE_ENTRY = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}}
BOB_ENTRY = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}}
OPENAPI_ORDERS = {"openapi": "3.0.3", "paths": {
    "/orders": {"get": {"operationId": "listOrders"}},
    "/orders/{orderId}": {"get": {"operationId": "getOrder"}},
}}
PLAN_DOC = {"openapi": "3.0.3", "paths": {
    "/orders": {"get": {}, "post": {}},
    "/orders/{orderId}": {"get": {}, "patch": {}},
    "/invoices/{id}": {"get": {}},
    "/users/{uid}/orders": {"get": {}},
    "/users/{uid}/orders/{id}": {"get": {}},
    "/customers": {"get": {}},
    "/customers/{id}": {"delete": {}},
}}
NESTED_OPENAPI = {"openapi": "3.0.3", "paths": {
    "/users/{user_id}/orders": {"get": {"operationId": "listUserOrders"}},
    "/users/{user_id}/orders/{orderId}": {"get": {"operationId": "getUserOrder"}},
}}


# --- discovery: attribution rules -----------------------------------------------------------------

def test_a_scoped_listing_attributes_each_id_to_the_only_identity_that_sees_it():
    with Fixture(ListAndItems(CollectionApp("scoped"), OrdersApp({"GET": "allow"}))) as fx:
        disc = s.discover_owned_ids([alice(), bob()], fx.base + "/orders", OWN, 5, [])
    assert disc.owns == {"alice": ["1001"], "bob": ["2001"]}
    assert disc.sources == {("alice", "1001"): "listing", ("bob", "2001"): "listing"}
    assert disc.ambiguous == [] and disc.listed_for_other == 0


def test_a_leaky_listing_without_owner_values_leaves_every_id_ambiguous_and_sends_only_the_listings():
    rec = Recorder(ListAndItems(CollectionApp("leaky"), OrdersApp({"GET": "allow"})))
    with Fixture(rec) as fx:
        disc = s.discover_owned_ids([alice(), bob()], fx.base + "/orders", OWN, 5, [])
    assert all(ids == [] for ids in disc.owns.values())
    assert sorted(disc.ambiguous) == ["1001", "2001", "3001"]
    assert len(rec.calls) == 2 and all(path == "/orders" for _, path in rec.calls)


def test_declared_owner_values_attribute_ids_from_a_leaky_listing():
    a = alice(owner_values={"user_id": 42})
    b = bob(owner_values={"user_id": 91})
    with Fixture(ListAndItems(CollectionApp("leaky"), OrdersApp({"GET": "allow"}))) as fx:
        disc = s.discover_owned_ids([a, b], fx.base + "/orders", OWN, 5, [])
    assert disc.owns == {"alice": ["1001"], "bob": ["2001"]}
    assert disc.sources[("alice", "1001")] == "owner-field"
    assert disc.ambiguous == ["3001"]           # owned by carol, who is not an identity: not tested
    assert disc.listed_for_other == 2           # alice's order is shown to bob, and bob's to alice


def test_a_declared_id_stays_with_the_identity_that_declared_it():
    a = alice(owns=["1001"])
    with Fixture(ListAndItems(CollectionApp("leaky"), OrdersApp({"GET": "allow"}))) as fx:
        disc = s.discover_owned_ids([a, bob()], fx.base + "/orders", OWN, 5, [])
    assert "1001" not in disc.owns["alice"] and "1001" not in disc.owns["bob"]
    assert "1001" not in disc.ambiguous


def test_a_listing_that_is_not_json_is_reported_and_attributes_nothing_for_that_identity():
    html_listing = lambda req: Resp(200, "<html>not json</html>", "text/html")  # noqa: E731
    with Fixture(ListAndItems(html_listing, OrdersApp({"GET": "allow"}))) as fx:
        disc = s.discover_owned_ids([alice(), bob()], fx.base + "/orders", OWN, 5, [])
    assert all(row["status"] == "not_listed" for row in disc.per_identity)
    assert all(ids == [] for ids in disc.owns.values())


def test_listing_url_with_an_id_placeholder_is_refused_before_any_request():
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with Fixture(rec) as fx:
        try:
            s.discover_owned_ids([alice(), bob()], fx.base + "/orders/{id}", OWN, 5, [])
        except s.ConfigError as exc:
            assert "must not contain {id}" in str(exc)
        else:
            raise AssertionError("expected ConfigError")
    assert rec.calls == []


def test_list_items_reads_common_envelopes_and_refuses_the_rest():
    assert s._list_items([{"id": 1}]) == [{"id": 1}]
    assert s._list_items({"data": [{"id": 1}], "meta": {}}) == [{"id": 1}]
    assert s._list_items({"orders": [{"id": 1}]}) == [{"id": 1}]
    assert s._list_items({"count": 3}) is None


def test_item_id_uses_the_known_id_keys_and_ignores_compound_values():
    assert s._item_id({"orderId": 7}) == "7"
    assert s._item_id({"id": {"nested": 1}}) is None
    assert s._item_id("1001") is None


# --- discovery: through the CLI --------------------------------------------------------------------

def test_discover_flag_tests_listed_ids_and_marks_them_as_inferred_with_medium_confidence():
    with tempfile.TemporaryDirectory() as td, \
            Fixture(ListAndItems(CollectionApp("scoped"), OrdersApp({"GET": "allow"}))) as fx:
        ids = identities_file(td, [ALICE_ENTRY, BOB_ENTRY])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--identities", ids,
                              "--discover", "--collection-url", fx.base + "/orders", "--output", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
    confirmed = [f for f in rep["findings"] if f["category"] == "confirmed"]
    assert code == s.EXIT_POLICY
    assert len(confirmed) == 2
    assert all(f["confidence"] == "medium" for f in confirmed)
    assert all(f["details"]["ownership_source"] == "listing" for f in confirmed)
    assert all("was inferred from" in " ".join(f["evidence"]) for f in confirmed)
    assert rep["discovery"]["attributed"] == {"alice": 1, "bob": 1}


def test_discover_needs_a_collection_url_and_refuses_before_any_request():
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with tempfile.TemporaryDirectory() as td, Fixture(rec) as fx:
        ids = identities_file(td, [ALICE_ENTRY, BOB_ENTRY])
        code, _, err = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--identities", ids,
                                "--discover", "--output", str(Path(td) / "r.json")])
    assert code == s.EXIT_CONFIG and "--collection-url" in err
    assert rec.calls == []


# --- OpenAPI plan: building the plan ----------------------------------------------------------------

def test_build_plan_maps_single_id_routes_and_explains_every_route_it_does_not_test():
    plan = {p["path"]: p for p in s.build_plan(PLAN_DOC, "http://h.example:8000/")}
    assert set(plan) == {"/orders/{orderId}", "/invoices/{id}", "/users/{uid}/orders", "/users/{uid}/orders/{id}",
                         "/customers/{id}"}
    assert plan["/orders/{orderId}"]["status"] == "planned"
    assert plan["/orders/{orderId}"]["item_url"] == "http://h.example:8000/orders/{id}"
    assert plan["/orders/{orderId}"]["collection_url"] == "http://h.example:8000/orders"
    assert plan["/invoices/{id}"]["status"] == "skipped" and "no GET collection" in plan["/invoices/{id}"]["reason"]
    assert plan["/users/{uid}/orders/{id}"]["status"] == "planned"
    assert plan["/users/{uid}/orders/{id}"]["params_needed"] == ["uid"]
    assert "collection under a parameter" in plan["/users/{uid}/orders"]["reason"]
    assert "no GET on this route" in plan["/customers/{id}"]["reason"]


def test_build_plan_lists_routes_it_cannot_map_with_a_reason_instead_of_dropping_them():
    doc = {"openapi": "3.0.3", "paths": {
        "/files/{id}.json": {"get": {}},
        "/orders": {"get": {}},
        "/orders/{id}": {"get": {}},
        "/orders/{id}/items/{itemId}": {"get": {}},
    }}
    plan = {p["path"]: p for p in s.build_plan(doc, "http://h.example:8000")}
    assert set(plan) == {"/files/{id}.json", "/orders/{id}", "/orders/{id}/items/{itemId}"}
    assert "inside a path segment" in plan["/files/{id}.json"]["reason"]
    assert "collides" in plan["/orders/{id}/items/{itemId}"]["reason"]
    assert plan["/orders/{id}"]["status"] == "planned" and plan["/orders/{id}"]["params_needed"] == []


def plan_entry(report, path):
    return next(p for p in report["plan"] if p["path"] == path)


def _run_nested(kind, identities, rec_app=None):
    """Run plan mode on NESTED_OPENAPI against a NestedApp; return (exit code, report, recorder or None)."""
    app = NestedApp(kind)
    target = Recorder(app) if rec_app else app
    with tempfile.TemporaryDirectory() as td, Fixture(target) as fx:
        spec = write_json(td, "openapi.json", NESTED_OPENAPI)
        ids = identities_file(td, identities)
        out = Path(td) / "r.json"
        code, _, _ = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", fx.base,
                              "--identities", ids, "--output", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
    return code, rep, target if rec_app else None


def test_nested_plan_confirms_a_cross_read_when_the_child_route_checks_only_the_parent():
    code, rep, _ = _run_nested("child_vuln", [{**ALICE_ENTRY, "params": {"user_id": "42"}},
                                              {**BOB_ENTRY, "params": {"user_id": "91"}}])
    route = plan_entry(rep, "/users/{user_id}/orders/{orderId}")
    assert code == s.EXIT_POLICY and route["status"] == "ran" and route["confirmed"] >= 1


def test_nested_plan_against_a_child_route_that_checks_the_owner_is_clean():
    code, rep, _ = _run_nested("child_secure", [{**ALICE_ENTRY, "params": {"user_id": "42"}},
                                                {**BOB_ENTRY, "params": {"user_id": "91"}}])
    route = plan_entry(rep, "/users/{user_id}/orders/{orderId}")
    assert code == s.EXIT_OK and route["status"] == "ran" and route["confirmed"] == 0


def test_a_nested_route_without_parent_values_is_incomplete_and_sends_nothing_for_it():
    code, rep, rec = _run_nested("child_secure", [ALICE_ENTRY, BOB_ENTRY], rec_app=True)
    route = plan_entry(rep, "/users/{user_id}/orders/{orderId}")
    assert code == s.EXIT_INCOMPLETE and route["status"] == "skipped" and "params.user_id" in route["reason"]
    assert any(f["check"] == "plan-item-skipped" and f["category"] == "incomplete" for f in rep["findings"])
    assert not any(path.startswith("/users/") for _, path in rec.calls)


def test_build_plan_refuses_a_base_url_that_is_not_http():
    try:
        s.build_plan(OPENAPI_ORDERS, "127.0.0.1:8000")
    except s.ConfigError as exc:
        assert "http(s) URL" in str(exc)
    else:
        raise AssertionError("expected ConfigError")


# --- OpenAPI plan: through the CLI -----------------------------------------------------------------

def test_plan_only_prints_and_writes_the_plan_and_sends_nothing():
    rec = Recorder(ListAndItems(CollectionApp("scoped"), OrdersApp({"GET": "allow"})))
    with tempfile.TemporaryDirectory() as td, Fixture(rec) as fx:
        spec = write_json(td, "openapi.json", OPENAPI_ORDERS)
        out = Path(td) / "plan.json"
        code, text, _ = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", fx.base,
                                 "--plan-only", "--output", str(out)])
        plan = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_OK and rec.calls == []
    assert plan["plan"][0]["status"] == "planned" and "RUN" in text


def test_plan_run_discovers_ownership_confirms_cross_reads_and_ignores_declared_owns():
    rec = Recorder(ListAndItems(CollectionApp("scoped"), OrdersApp({"GET": "allow"})))
    with tempfile.TemporaryDirectory() as td, Fixture(rec) as fx:
        spec = write_json(td, "openapi.json", OPENAPI_ORDERS)
        ids = identities_file(td, [{**ALICE_ENTRY, "owns": ["9999"]}, {**BOB_ENTRY, "owns": []}])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", fx.base,
                              "--identities", ids, "--output", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
    confirmed = [f for f in rep["findings"] if f["category"] == "confirmed"]
    assert code == s.EXIT_POLICY and rep["mode"] == "openapi-plan"
    assert rep["plan"][0]["status"] == "ran" and rep["plan"][0]["confirmed"] == 2
    assert not any(path.endswith("/9999") for _, path in rec.calls)      # the declared id was not used
    assert {f["details"]["ownership_source"] for f in confirmed} == {"listing"}


def test_plan_against_an_enforcing_api_is_clean():
    with tempfile.TemporaryDirectory() as td, \
            Fixture(ListAndItems(CollectionApp("scoped"), OrdersApp({"GET": "deny"}))) as fx:
        spec = write_json(td, "openapi.json", OPENAPI_ORDERS)
        ids = identities_file(td, [ALICE_ENTRY, BOB_ENTRY])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", fx.base,
                              "--identities", ids, "--output", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_OK and rep["summary"]["confirmed"] == 0 and rep["plan"][0]["status"] == "ran"


def test_a_route_whose_ids_discovery_cannot_attribute_is_incomplete_not_clean():
    with tempfile.TemporaryDirectory() as td, \
            Fixture(ListAndItems(CollectionApp("leaky"), OrdersApp({"GET": "allow"}))) as fx:
        spec = write_json(td, "openapi.json", OPENAPI_ORDERS)
        ids = identities_file(td, [ALICE_ENTRY, BOB_ENTRY])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", fx.base,
                              "--identities", ids, "--output", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_INCOMPLETE
    assert any(f["check"] == "plan-item-skipped" and f["category"] == "incomplete" for f in rep["findings"])
    assert rep["plan"][0]["status"] == "skipped"


def test_plan_mode_refuses_to_combine_with_a_single_url_and_needs_identities():
    with tempfile.TemporaryDirectory() as td:
        spec = write_json(td, "openapi.json", OPENAPI_ORDERS)
        code, _, err = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", "http://127.0.0.1:9",
                                "--url", "http://127.0.0.1:9/orders/{id}"])
        code2, _, err2 = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", "http://127.0.0.1:9"])
    assert code == s.EXIT_CONFIG and "do not combine" in err
    assert code2 == s.EXIT_CONFIG and "needs --identities" in err2


def test_closed_target_in_plan_mode_is_a_transport_failure_not_a_crash():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory() as td:
        spec = write_json(td, "openapi.json", OPENAPI_ORDERS)
        ids = identities_file(td, [ALICE_ENTRY, BOB_ENTRY])
        code, _, err = run_cli(["--yes-i-am-authorized", "--openapi", spec, "--base-url", f"http://127.0.0.1:{port}",
                                "--identities", ids, "--output", str(Path(td) / "r.json")])
    assert code == s.EXIT_TRANSPORT and "Traceback" not in err
