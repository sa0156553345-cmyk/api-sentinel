"""--id-field: resources keyed by a field other than id (for example book_title), in matching and in discovery.

The fixture has the shape of VAmPI's /books/v1/{title}: the record has no id field, the owner is named in an 'owner'
field, and the listing is keyed by book_title. Expected values come from the rules, not from the implementation.
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
from authz_matrix.fixtures import Fixture, Resp, not_found, parts_of, unauthorized  # noqa: E402

OWN = s.OWNER_FIELDS_DEFAULT


class BookApp:
    """vuln=True: any authenticated user reads any book. vuln=False: non-owners get 404."""

    def __init__(self, vuln=True):
        self.vuln = vuln
        self.books = {"alice-book": ("alice", "alice-secret"), "bob-book": ("bob", "bob-secret")}
        self.users = {"alice-token": "alice", "bob-token": "bob"}

    def __call__(self, req):
        user = self.users.get(req.token)
        if user is None:
            return unauthorized()
        parts = parts_of(req)
        if parts == ["books", "v1"] and req.method == "GET":
            return Resp(200, {"Books": [{"book_title": t, "user": o} for t, (o, _) in self.books.items()]})
        if len(parts) == 3 and parts[:2] == ["books", "v1"] and parts[2] in self.books:
            owner, secret = self.books[parts[2]]
            if self.vuln or owner == user:
                return Resp(200, {"book_title": parts[2], "secret": secret, "owner": owner})
            return not_found()
        return not_found()


def alice(**kw):
    return s.Identity("alice", {"Authorization": "Bearer alice-token"}, list(kw.get("owns", ["alice-book"])),
                      params={}, owner_values=dict(kw.get("owner_values", {})))


def bob(**kw):
    return s.Identity("bob", {"Authorization": "Bearer bob-token"}, list(kw.get("owns", ["bob-book"])),
                      params={}, owner_values=dict(kw.get("owner_values", {})))


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


def confirmed(findings):
    return [f for f in findings if f.check in s.BOLA_CHECKS]


def test_without_the_id_field_a_title_keyed_record_is_undetermined_not_confirmed():
    with Fixture(BookApp(vuln=True)) as fx:
        found, _ = s.run_authorization_matrix(fx.base + "/books/v1/{id}", [alice(), bob()], "GET", OWN, 5)
    assert confirmed(found) == []
    assert any(f.check == "authorization-undetermined" for f in found)


def test_with_the_id_field_the_identical_copy_confirms_the_leak_at_medium_confidence():
    with Fixture(BookApp(vuln=True)) as fx:
        with s.resource_id_field("book_title"):
            found, _ = s.run_authorization_matrix(fx.base + "/books/v1/{id}", [alice(), bob()], "GET", OWN, 5)
    pairs = {(f.details["owner_identity"], f.details["accessing_identity"], f.details["resource_id"])
             for f in confirmed(found)}
    assert pairs == {("alice", "bob", "alice-book"), ("bob", "alice", "bob-book")}
    assert all(f.confidence == "medium" and f.severity == "high" for f in confirmed(found))


def test_with_the_id_field_a_secure_api_is_clean():
    with Fixture(BookApp(vuln=False)) as fx:
        with s.resource_id_field("book_title"):
            found, _ = s.run_authorization_matrix(fx.base + "/books/v1/{id}", [alice(), bob()], "GET", OWN, 5)
    assert confirmed(found) == []


def test_discovery_with_the_id_field_attributes_books_by_owner_value_and_marks_the_critical_leak():
    with tempfile.TemporaryDirectory() as td, Fixture(BookApp(vuln=True)) as fx:
        ids = Path(td) / "identities.json"
        ids.write_text(json.dumps({"identities": [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owner_values": {"user": "alice"}},
            {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owner_values": {"user": "bob"}},
        ]}), encoding="utf-8")
        out = Path(td) / "r.json"
        code, _, _ = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/books/v1/{id}", "--identities", str(ids),
                              "--discover", "--collection-url", fx.base + "/books/v1", "--id-field", "book_title",
                              "--ownership-fields", "owner,user", "--output", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_POLICY
    assert rep["discovery"]["attributed"] == {"alice": 1, "bob": 1}
    hits = [f for f in rep["findings"] if f["category"] == "confirmed"]
    assert len(hits) == 2
    assert all(f["severity"] == "critical" and f["confidence"] == "medium" for f in hits)
    assert all(f["details"]["ownership_source"] == "owner-field" for f in hits)


def test_the_id_field_setting_is_restored_after_a_run_even_when_it_is_used():
    before = s._active_id_keys
    with tempfile.TemporaryDirectory() as td, Fixture(BookApp(vuln=True)) as fx:
        ids = Path(td) / "identities.json"
        ids.write_text(json.dumps({"identities": [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["alice-book"]},
            {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": ["bob-book"]},
        ]}), encoding="utf-8")
        run_cli(["--yes-i-am-authorized", "--url", fx.base + "/books/v1/{id}", "--identities", str(ids),
                 "--id-field", "book_title", "--output", str(Path(td) / "r.json")])
    assert s._active_id_keys == before == s._RESOURCE_ID_KEYS
