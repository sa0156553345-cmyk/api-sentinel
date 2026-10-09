"""In-process fixture APIs for the authorization test matrix.

Each fixture is a plain callable ``app(req) -> Resp`` served by a stdlib
ThreadingHTTPServer on an ephemeral 127.0.0.1 port. Fixtures never import
api_sentinel: they must not know how the tool works. Ground truth lives in the
fixtures' real behaviour; the harness re-checks every oracle label by probing a
fresh copy of the fixture directly (see harness.verify_access).
"""
from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit


@dataclass
class Req:
    method: str
    path: str
    query: dict
    headers: dict
    body: Any
    token: str


@dataclass
class Resp:
    status: int
    body: Any = None
    content_type: str | None = None
    headers: dict = field(default_factory=dict)


DROP = object()  # sentinel: close the connection without answering


class _Handler(BaseHTTPRequestHandler):
    def _dispatch(self):
        parsed = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body: Any = None
        if raw:
            try:
                body = json.loads(raw)
            except ValueError:
                body = raw
        token = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
        req = Req(self.command, parsed.path, query, dict(self.headers), body, token)
        try:
            resp = self.server.app(req)
        except Exception as exc:  # a fixture bug must fail loudly, not look like a "secure" 500
            self.server.errors.append(repr(exc))
            resp = Resp(500, {"fixture_error": repr(exc)})
        if resp is DROP:
            self.close_connection = True
            return
        self._write(resp)

    def _write(self, resp: Resp):
        body, ctype = resp.body, resp.content_type
        if isinstance(body, (dict, list)):
            payload, ctype = json.dumps(body).encode(), ctype or "application/json"
        elif isinstance(body, str):
            payload, ctype = body.encode(), ctype or "text/plain"
        elif isinstance(body, bytes):
            payload, ctype = body, ctype or "application/octet-stream"
        else:
            payload = b""
        self.send_response(resp.status)
        if payload and ctype:
            self.send_header("Content-Type", ctype)
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _dispatch

    def log_message(self, *args):
        pass


class Fixture:
    """Context manager: serve ``app`` on an ephemeral loopback port."""

    def __init__(self, app):
        self.app = app
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.app = app
        self.server.errors = []
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def errors(self):
        return self.server.errors

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --- shared data ----------------------------------------------------------

USERS = {
    "alice-token": {"id": 42, "name": "alice", "role": "customer"},
    "alice-mobile-token": {"id": 42, "name": "alice", "role": "customer"},  # same account, 2nd session
    "bob-token": {"id": 91, "name": "bob", "role": "customer"},
    "carol-token": {"id": 77, "name": "carol", "role": "customer"},
    "admin-token": {"id": 1, "name": "admin", "role": "admin"},
}


def user_of(req):
    return USERS.get(req.token)


def unauthorized():
    return Resp(401, {"error": "unauthorized"})


def forbidden():
    return Resp(403, {"error": "forbidden"})


def not_found():
    return Resp(404, {"error": "not found"})


def parts_of(req):
    return [p for p in req.path.split("/") if p]


def make_order(oid, owner, item="Keyboard", total=59.99):
    return {"id": oid, "user_id": owner, "item": item, "total": total}


def seed_orders():
    return {
        1001: make_order(1001, 42, "Keyboard", 59.99),
        2001: make_order(2001, 91, "Monitor", 199.0),
        3001: make_order(3001, 77, "Mouse", 19.5),
    }


# --- configurable orders API ---------------------------------------------

class OrdersApp:
    """/orders API. ``non_owner`` maps verb -> behaviour for callers that do not own the order:

    deny         403, no effect
    hide         404, no effect
    allow        performs the operation and answers normally          (BOLA)
    async        performs the operation, answers 202 Accepted          (BOLA, unusual status)
    blind        performs the operation, then answers 403              (BOLA, misleading status)
    noop         no effect, but answers as if it succeeded             (secure, misleading status)
    soft_error   no effect, answers 200 + {"error": "forbidden"}       (secure, misleading status)
    stub         GET only: 200 + restricted stub, no data              (secure, misleading status)
    unsupported  405 for everybody
    deny_leak    403, but the body is the full record (the status misleads; the data is disclosed)
    partial_status  non-owners get 200 {"status": ...} only (partial disclosure)
    placeholder  non-owners get 200 with the same keys and types as a real record but no real data

    view="no_id"  GET answers {item, total} to everybody: no id, no owner field
    view="holder" the owner is stored as "holder": "acct-<id>" instead of user_id (unknown field name)
    """

    def __init__(self, non_owner=None, orders=None, admin_override=False, shares=None,
                 ownerless_open=False, create_responds="body", view=None):
        self.modes = {"GET": "deny", "PATCH": "deny", "PUT": "unsupported", "DELETE": "deny"}
        self.modes.update(non_owner or {})
        self.orders = copy.deepcopy(orders) if orders is not None else seed_orders()
        self.next_id = 5000
        self.admin_override = admin_override
        self.shares = shares or {}
        self.ownerless_open = ownerless_open
        self.create_responds = create_responds
        self.view = view

    def __call__(self, req):
        user = user_of(req)
        parts = parts_of(req)
        if parts == ["orders"] and req.method == "POST":
            if not user:
                return unauthorized()
            body = req.body if isinstance(req.body, dict) else {}
            oid = self.next_id
            self.next_id += 1
            self.orders[oid] = make_order(oid, user["id"], body.get("item", "Widget"), body.get("total", 9.99))
            if self.create_responds == "location":
                return Resp(201, None, headers={"Location": f"/orders/{oid}"})
            return Resp(201, dict(self.orders[oid]))
        if len(parts) == 2 and parts[0] == "orders" and parts[1].isdigit():
            return self._item(req, user, int(parts[1]))
        return not_found()

    def _item(self, req, user, oid):
        if not user:
            return unauthorized()
        verb = req.method
        mode = self.modes.get(verb, "unsupported")
        if mode == "unsupported":
            return Resp(405, {"error": "method not allowed"})
        order = self.orders.get(oid)
        if order is None:
            return not_found()
        if verb == "GET" and self.view == "no_id":
            return Resp(200, {"item": order["item"], "total": order["total"]})
        is_owner = order["user_id"] == user["id"]
        if not is_owner and self.admin_override and user["role"] == "admin":
            is_owner = True
        if not is_owner and order["user_id"] is None and self.ownerless_open:
            is_owner = True
        if not is_owner and verb == "GET" and user["id"] in self.shares.get(oid, []):
            is_owner = True
        if is_owner or mode == "allow":
            return self._perform(verb, req, oid)
        if mode == "deny":
            return forbidden()
        if mode == "hide":
            return not_found()
        if mode == "async":
            self._perform(verb, req, oid)
            return Resp(202, {"status": "accepted"})
        if mode == "blind":
            self._perform(verb, req, oid)
            return forbidden()
        if mode == "noop":
            return Resp(204) if verb == "DELETE" else Resp(200, dict(order))
        if mode == "soft_error":
            return Resp(200, {"error": "forbidden", "code": 403})
        if mode == "stub":
            return Resp(200, {"id": oid, "visibility": "restricted"})
        if mode == "deny_leak":
            return Resp(403, dict(order))
        if mode == "partial_status":
            return Resp(200, {"status": "shipped"})
        if mode == "placeholder":
            return Resp(200, {"id": 0, "user_id": 0, "item": "Unavailable", "total": 0.0})
        raise ValueError(f"unknown mode {mode!r} for {verb}")

    def _perform(self, verb, req, oid):
        order = self.orders[oid]
        if verb == "GET":
            if self.view == "holder":
                return Resp(200, {"id": order["id"], "holder": f"acct-{order['user_id']}",
                                  "item": order["item"], "total": order["total"]})
            return Resp(200, dict(order))
        if verb in ("PATCH", "PUT"):
            body = req.body if isinstance(req.body, dict) else {}
            for key in ("item", "total"):
                if key in body:
                    order[key] = body[key]
            return Resp(200, dict(order))
        if verb == "DELETE":
            del self.orders[oid]
            return Resp(204)
        raise ValueError(verb)


# --- other shapes of API --------------------------------------------------

class DropNonOwner:
    """Vulnerable-looking orders API, but a gateway resets the connection for non-owners."""

    def __init__(self):
        self.inner = OrdersApp({"GET": "allow"})
        self.orders = self.inner.orders

    def __call__(self, req):
        user = user_of(req)
        parts = parts_of(req)
        if user and len(parts) == 2 and parts[0] == "orders" and parts[1].isdigit():
            order = self.inner.orders.get(int(parts[1]))
            if order and order["user_id"] != user["id"]:
                return DROP
        return self.inner(req)


class PostsApp:
    """/posts/{id}: public posts are readable by everyone by design; private ones by the owner only."""

    def __init__(self):
        self.posts = {
            1001: {"id": 1001, "user_id": 42, "title": "Hello", "visibility": "public"},
            2001: {"id": 2001, "user_id": 91, "title": "Notes", "visibility": "public"},
            3001: {"id": 3001, "user_id": 77, "title": "Draft", "visibility": "private"},
        }

    def __call__(self, req):
        user = user_of(req)
        parts = parts_of(req)
        if not user:
            return unauthorized()
        if len(parts) != 2 or parts[0] != "posts" or not parts[1].isdigit():
            return not_found()
        post = self.posts.get(int(parts[1]))
        if post is None:
            return not_found()
        if post["visibility"] == "public" or post["user_id"] == user["id"]:
            return Resp(200, dict(post))
        return forbidden()


class CollectionApp:
    """GET /orders (a list). scoped: caller's own orders. leaky: everybody's orders."""

    def __init__(self, kind):
        self.kind = kind
        self.orders = seed_orders()

    def __call__(self, req):
        user = user_of(req)
        if not user:
            return unauthorized()
        if parts_of(req) != ["orders"] or req.method != "GET":
            return not_found()
        rows = [dict(o) for o in self.orders.values()]
        if self.kind == "scoped":
            rows = [o for o in rows if o["user_id"] == user["id"]]
        return Resp(200, rows)


class FilterApp:
    """GET /orders?customer_id=N. honor: any caller may list any customer (BOLA).
    ignore: always lists the caller's own orders. deny: 403 unless N is the caller."""

    def __init__(self, kind):
        self.kind = kind
        self.orders = seed_orders()

    def __call__(self, req):
        user = user_of(req)
        if not user:
            return unauthorized()
        if parts_of(req) != ["orders"]:
            return not_found()
        try:
            wanted = int(req.query.get("customer_id", ""))
        except ValueError:
            return Resp(400, {"error": "customer_id required"})
        if self.kind == "deny" and wanted != user["id"]:
            return forbidden()
        target = wanted if self.kind in ("honor", "deny") else user["id"]
        return Resp(200, [dict(o) for o in self.orders.values() if o["user_id"] == target])


class ProfileApp:
    """GET /profile/{id}. honor: returns the requested profile (BOLA). ignore: returns the caller's own."""

    def __init__(self, kind):
        self.kind = kind
        self.profiles = {
            42: {"id": 42, "user_id": 42, "name": "alice"},
            91: {"id": 91, "user_id": 91, "name": "bob"},
            77: {"id": 77, "user_id": 77, "name": "carol"},
        }

    def __call__(self, req):
        user = user_of(req)
        parts = parts_of(req)
        if not user:
            return unauthorized()
        if len(parts) != 2 or parts[0] != "profile" or not parts[1].isdigit():
            return not_found()
        pid = user["id"] if self.kind == "ignore" else int(parts[1])
        prof = self.profiles.get(pid)
        return Resp(200, dict(prof)) if prof else not_found()


class NestedApp:
    """/users/{uid}/orders and /users/{uid}/orders/{oid}.

    list_vuln:   anyone may list any user's orders.   list_secure: only that user.
    child_vuln:  caller must equal {uid}, but the order's real owner is never checked.
    child_secure: caller must equal {uid} AND the order must belong to {uid}.
    """

    def __init__(self, kind):
        self.kind = kind
        self.orders = seed_orders()

    def __call__(self, req):
        user = user_of(req)
        parts = parts_of(req)
        if not user:
            return unauthorized()
        if len(parts) == 3 and parts[0] == "users" and parts[2] == "orders" and parts[1].isdigit():
            uid = int(parts[1])
            if self.kind == "list_secure" and user["id"] != uid:
                return forbidden()
            return Resp(200, [dict(o) for o in self.orders.values() if o["user_id"] == uid])
        if len(parts) == 4 and parts[0] == "users" and parts[2] == "orders" and parts[1].isdigit() and parts[3].isdigit():
            uid, oid = int(parts[1]), int(parts[3])
            if user["id"] != uid:
                return forbidden()
            order = self.orders.get(oid)
            if order is None:
                return not_found()
            if self.kind == "child_secure" and order["user_id"] != uid:
                return not_found()
            return Resp(200, dict(order))
        return not_found()


REPR_ROWS = {
    1001: {"owner": 42, "owner_name": "alice", "email": "alice@example.com", "address": "1 Main St",
           "item": "Keyboard", "total": 59.99, "payment_last4": "4242"},
    2001: {"owner": 91, "owner_name": "bob", "email": "bob@example.com", "address": "9 Oak Ave",
           "item": "Monitor", "total": 199.0, "payment_last4": "1111"},
}


class ReprApp:
    """/orders/{id} that ALWAYS leaks to any authenticated caller; only the JSON representation varies."""

    def __init__(self, kind):
        self.kind = kind

    def __call__(self, req):
        user = user_of(req)
        parts = parts_of(req)
        if not user:
            return unauthorized()
        if len(parts) != 2 or parts[0] != "orders" or not parts[1].isdigit():
            return not_found()
        oid = int(parts[1])
        row = REPR_ROWS.get(oid)
        if row is None:
            return not_found()
        return Resp(200, self._render(oid, row, row["owner"] == user["id"]))

    def _render(self, oid, row, viewer_is_owner):
        k = self.kind
        base = {"item": row["item"], "total": row["total"]}
        if k == "created_by":
            return {"id": oid, "created_by": row["owner"], **base}
        if k == "ownerId":
            return {"id": oid, "ownerId": row["owner"], **base}
        if k == "nested_owner":
            return {"id": oid, "owner": {"id": row["owner"], "name": row["owner_name"]}, **base}
        if k == "envelope":
            return {"data": {"id": oid, "user_id": row["owner"], **base}, "meta": {"api": "v2"}}
        if k == "bare":
            return dict(base)
        if k in ("ref_full", "ref_partial"):
            out = {"order_ref": f"ORD-{oid}", "owner_id": row["owner"], "email": row["email"],
                   "address": row["address"], "total": row["total"], "payment_last4": row["payment_last4"]}
            if k == "ref_partial" and not viewer_is_owner:
                del out["payment_last4"]
            return out
        raise ValueError(k)


class DownloadApp:
    """/invoices/{id}: leaks to any authenticated caller, in a non-JSON (or mislabelled) representation."""

    ROWS = {1001: "alice", 2001: "bob"}

    def __init__(self, kind):
        self.kind = kind

    def __call__(self, req):
        user = user_of(req)
        parts = parts_of(req)
        if not user:
            return unauthorized()
        if len(parts) != 2 or parts[0] != "invoices" or not parts[1].isdigit():
            return not_found()
        oid = int(parts[1])
        name = self.ROWS.get(oid)
        if name is None:
            return not_found()
        if self.kind == "pdf":
            return Resp(200, f"%PDF-1.4\n% invoice {oid} for {name}\n%%EOF\n".encode(), "application/pdf")
        return Resp(200, {"id": oid, "owner": name, "amount": 120.0}, "text/plain")
