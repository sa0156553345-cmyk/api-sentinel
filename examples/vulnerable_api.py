#!/usr/bin/env python3
"""
Demo "Orders" API for trying API Sentinel locally. Standard library only: no Flask, no install step.

It is a safe, local target with one intentional bug, and it is not for production use.

  SECURE unset or "0"  -> GET/PATCH/DELETE /orders/<id> do NOT check that the caller owns the order (BOLA).
  SECURE=1             -> the same endpoints check ownership and answer 403 to non-owners.

Run it, then point API Sentinel at it (see the README):

    python3 examples/vulnerable_api.py            # vulnerable mode, http://127.0.0.1:8000
    SECURE=1 python3 examples/vulnerable_api.py   # fixed mode
    PORT=8001 python3 examples/vulnerable_api.py  # optional: another port

Built-in users:
  alice (user_id 42), token alice-token, owns order 1001
  bob   (user_id 91), token bob-token,   owns order 2001
"""
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECURE = os.environ.get("SECURE") == "1"
PORT = int(os.environ.get("PORT", "8000"))

USERS = {
    "alice-token": {"user_id": 42, "name": "alice"},
    "bob-token": {"user_id": 91, "name": "bob"},
}
ORDERS = {
    1001: {"id": 1001, "user_id": 42, "item": "Keyboard", "total": 59.99},
    2001: {"id": 2001, "user_id": 91, "item": "Monitor", "total": 199.0},
}
_lock = threading.Lock()
_next_id = [3000]
_ORDER_PATH = re.compile(r"^/orders/(\d+)$")


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoOrders/1.0"

    def log_message(self, fmt, *args):  # one access-log line per request on stderr
        code = args[1] if len(args) > 1 else "-"
        sys.stderr.write(f"{self.client_address[0]} {self.command} {self.path} {code}\n")

    def _reply(self, status, payload=None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _caller(self):
        auth = self.headers.get("Authorization", "")
        return USERS.get(auth.replace("Bearer ", "", 1).strip())

    def _json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _order_id(self):
        match = _ORDER_PATH.match(self.path.split("?", 1)[0])
        return int(match.group(1)) if match else None

    def _may_touch(self, user, order):
        # The one line that differs between the two modes.
        return (not SECURE) or order["user_id"] == user["user_id"]

    def do_POST(self):
        body = self._json_body()  # read the body first so the connection stays in step
        user = self._caller()
        if self.path.rstrip("/") != "/orders":
            return self._reply(404, {"error": "not found"})
        if not user:
            return self._reply(401, {"error": "unauthorized"})
        with _lock:
            oid = _next_id[0]
            _next_id[0] += 1
            order = {"id": oid, "user_id": user["user_id"], "item": body.get("item", "Widget"),
                     "total": body.get("total", 9.99)}
            ORDERS[oid] = order
        return self._reply(201, order)

    def do_GET(self):
        oid, user = self._order_id(), self._caller()
        if oid is None:
            return self._reply(404, {"error": "not found"})
        if not user:
            return self._reply(401, {"error": "unauthorized"})
        with _lock:
            order = ORDERS.get(oid)
            if not order:
                return self._reply(404, {"error": "not found"})
            if not self._may_touch(user, order):
                return self._reply(403, {"error": "forbidden"})
            return self._reply(200, dict(order))

    def do_PATCH(self):
        body = self._json_body()
        oid, user = self._order_id(), self._caller()
        if oid is None:
            return self._reply(404, {"error": "not found"})
        if not user:
            return self._reply(401, {"error": "unauthorized"})
        with _lock:
            order = ORDERS.get(oid)
            if not order:
                return self._reply(404, {"error": "not found"})
            if not self._may_touch(user, order):
                return self._reply(403, {"error": "forbidden"})
            order.update({k: v for k, v in body.items() if k in {"item", "total"}})
            return self._reply(200, dict(order))

    def do_DELETE(self):
        oid, user = self._order_id(), self._caller()
        if oid is None:
            return self._reply(404, {"error": "not found"})
        if not user:
            return self._reply(401, {"error": "unauthorized"})
        with _lock:
            order = ORDERS.get(oid)
            if not order:
                return self._reply(404, {"error": "not found"})
            if not self._may_touch(user, order):
                return self._reply(403, {"error": "forbidden"})
            del ORDERS[oid]
        return self._reply(204)


def main() -> None:
    mode = "SECURE (ownership checked)" if SECURE else "VULNERABLE (no ownership check)"
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Demo orders API starting on http://127.0.0.1:{PORT}  [{mode}]", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
