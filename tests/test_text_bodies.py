"""Text bodies (HTML, XML, plain text) and other representations: what the matrix does with a response that is not JSON.

Expected values are written from what the rules say, not read back from the implementation. The CLI tests serve a
loopback fixture and call the real CLI. The unit tests call the judging functions with hand-built responses.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import api_sentinel as s  # noqa: E402
from authz_matrix.fixtures import Fixture, Resp  # noqa: E402

ALICE = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}
BOB = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}}

OWNER_PAGE = """<!doctype html>
<html><head><title>Order 1001</title></head><body>
<h1>Order 1001</h1>
<form method="post"><input type="hidden" name="csrf" value="a1b2c3d4"></form>
<table class="order">
<tr><th>Item</th><td>Keyboard</td></tr>
<tr><th>Total</th><td>59.99</td></tr>
<tr><th>Status</th><td>shipped</td></tr>
<tr><th>Customer</th><td>alice@example.test</td></tr>
</table>
<p>Thank you for your order.</p>
</body></html>"""

# The same template with most values masked, as a partial view of the record would show them.
MASKED_PAGE = """<!doctype html>
<html><head><title>Order 1001</title></head><body>
<h1>Order 1001</h1>
<form method="post"><input type="hidden" name="csrf" value="a1b2c3d4"></form>
<table class="order">
<tr><th>Item</th><td>Ke***</td></tr>
<tr><th>Total</th><td>**.99</td></tr>
<tr><th>Status</th><td>s*******</td></tr>
<tr><th>Customer</th><td>a***@example.test</td></tr>
</table>
<p>Thank you for your order.</p>
</body></html>"""

# The same template for another order: about 95% of its words match the owner's page, and it does not name 1001.
OTHER_ORDER_PAGE = OWNER_PAGE.replace("1001", "9999")

OWNER_XML = ('<?xml version="1.0"?>\n<order id="1001"><item>Keyboard</item><total>59.99</total>'
             '<status>shipped</status><customer>alice@example.test</customer></order>\n')
OWNER_JSON = {"id": 1001, "item": "Keyboard", "total": 59.99, "status": "shipped", "customer": "alice@example.test"}
PDF = b"%PDF-1.4\n% order 1001\n%%EOF\n"


def fp(body: str, content_type: str = "text/html", status: int = 200) -> s.ResponseFP:
    return s.ResponseFP(status=status, elapsed_ms=1.0, size=len(body.encode("utf-8")), content_type=content_type,
                        entropy=0.0, headers=[], shape=None, preview=body[:240], body=body)


# --- The fixtures: the owner's response, and what the accessor gets ---------------------------------------------

def _owner_response(kind: str) -> Resp:
    if kind == "html":
        return Resp(200, OWNER_PAGE, "text/html; charset=utf-8")
    if kind == "xml":
        return Resp(200, OWNER_XML, "application/xml")
    if kind == "json":
        return Resp(200, OWNER_JSON)
    if kind == "pdf":
        return Resp(200, PDF, "application/pdf")
    if kind == "no_id":
        return Resp(200, "<p>Your order has shipped.</p>", "text/html")
    raise ValueError(kind)


def _accessor_response(mode: str, owner: str) -> Resp:
    if mode == "copy":
        return _owner_response(owner)
    if mode == "nonce":  # the owner's page with one per-request token changed
        return Resp(200, OWNER_PAGE.replace("a1b2c3d4", "e5f6a7b8"), "text/html; charset=utf-8")
    if mode == "deny_leak":  # the owner's page under an error status
        page = _owner_response(owner)
        return Resp(403, page.body, page.content_type)
    if mode == "masked":
        return Resp(200, MASKED_PAGE, "text/html; charset=utf-8")
    if mode == "other_order":
        return Resp(200, OTHER_ORDER_PAGE, "text/html; charset=utf-8")
    if mode == "forbidden":
        return Resp(403, "Forbidden", "text/plain")
    if mode == "stub":
        return Resp(200, "<p>Order 1001 is not available to you.</p>", "text/html")
    if mode == "empty":
        return Resp(204)
    if mode == "pdf":
        return Resp(200, PDF, "application/pdf")
    if mode == "json_named":
        return Resp(200, {"id": 1001, "item": "Keyboard"})
    if mode == "text_named":
        return Resp(200, "<p>Order 1001: Keyboard, shipped.</p>", "text/html; charset=utf-8")
    if mode == "text_unnamed":
        return Resp(200, "<p>Nothing here.</p>", "text/html; charset=utf-8")
    raise ValueError(mode)


class PageApp:
    """/orders/1001. alice owns it and always gets the owner's representation. What bob gets is named by ``bob`` (see
    _accessor_response). ``copy_once`` gives bob the owner's page on the first request and 403 after that, so only the
    second pass can show that a leak did not reproduce. ``seen`` records every request that reached the fixture."""

    def __init__(self, bob: str = "copy", owner: str = "html"):
        self.bob, self.owner = bob, owner
        self.seen: list[tuple[str, str]] = []
        self.bob_requests = 0

    def __call__(self, req):
        self.seen.append((req.token, req.path))
        if req.path != "/orders/1001":
            return Resp(404, {"error": "not found"})
        if req.token == "alice-token":
            return _owner_response(self.owner)
        if req.token != "bob-token":
            return Resp(401, {"error": "unauthorized"})
        self.bob_requests += 1
        mode = self.bob
        if mode == "copy_once":
            mode = "copy" if self.bob_requests == 1 else "forbidden"
        return _accessor_response(mode, self.owner)


class ListingApp:
    """/orders as an HTML listing that names order 1001. The check must stop at the owner: a text listing is not judged
    as a collection, so nobody else may be asked for it."""

    def __init__(self):
        self.seen: list[tuple[str, str]] = []

    def __call__(self, req):
        self.seen.append((req.token, req.path))
        if req.path != "/orders":
            return Resp(404, {"error": "not found"})
        return Resp(200, OWNER_PAGE, "text/html; charset=utf-8")


# --- Running the CLI --------------------------------------------------------------------------------------------------

def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue() + err.getvalue()


@dataclass
class Run:
    code: int
    findings: list[dict[str, Any]]
    console: str
    app: Any


def run_matrix(app, template: str = "/orders/{id}") -> Run:
    """The CLI with alice owning 1001 and bob as the accessor. A fixture error fails the test, not the result."""
    with Fixture(app) as fx, tempfile.TemporaryDirectory() as folder:
        identities = Path(folder) / "identities.json"
        identities.write_text(json.dumps({"identities": [ALICE, BOB]}), encoding="utf-8")
        report = Path(folder) / "report.json"
        code, console = run_cli(["--yes-i-am-authorized", "--url", fx.base + template,
                                 "--identities", str(identities), "--output", str(report)])
        assert not fx.server.errors, fx.server.errors
        assert report.exists(), console
        findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
    return Run(code, findings, console, app)


def of(findings, category):
    return [f for f in findings if f["category"] == category]


def evidence_of(findings, category):
    return [" ".join(f["evidence"]) for f in of(findings, category)]


# --- What a body is, and how an id is matched -------------------------------------------------------------------------

def test_body_kinds_are_json_text_or_other():
    for ctype in ("application/json", "application/problem+json"):
        assert s._body_kind(fp("{}", ctype)) == "json", ctype
    for ctype in ("text/html; charset=utf-8", "text/plain", "application/xml", "application/atom+xml",
                  "application/xhtml+xml"):
        assert s._body_kind(fp("x", ctype)) == "text", ctype
    for ctype in ("application/pdf", "image/png", "application/octet-stream", ""):
        assert s._body_kind(fp("x", ctype)) == "other", ctype


def test_an_id_matches_only_as_a_whole_token():
    assert s._mentions("Order 1001 shipped", "1001")
    assert s._mentions("order=1001&x=2", "1001")
    assert not s._mentions("Order 10010 shipped", "1001")
    assert not s._mentions("ref a1001b", "1001")


def test_similarity_is_the_jaccard_index_of_the_word_sets():
    assert s._similarity("order 1001 shipped", "order 1001 shipped") == 1.0
    assert s._similarity("alpha beta", "gamma delta") == 0.0
    assert s._similarity("a b c d", "a b") == 0.5  # {a, b} shared out of {a, b, c, d}


# --- One accessor page, judged as text --------------------------------------------------------------------------------

def test_a_page_identical_to_the_owners_except_for_whitespace_is_a_copy():
    judgement = s._judge_text("1001", OWNER_PAGE, fp(OWNER_PAGE.replace("\n", "\n\n  ")))
    assert judgement.verdict == "leak", judgement
    assert "is identical to the owner's own page" in judgement.reasons[0], judgement.reasons


def test_a_short_owner_page_is_compared_for_identity_only():
    owner = "<p>Order 1001 shipped</p>"
    assert s._judge_text("1001", owner, fp(owner)).verdict == "leak"
    assert s._judge_text("1001", owner, fp("<p>Order 1001 paid</p>")).verdict == "none"


def test_a_page_that_does_not_name_the_resource_is_not_evidence():
    assert s._judge_text("1001", OWNER_PAGE, fp("<p>Nothing here</p>")).verdict == "none"


def test_a_similar_page_under_an_error_status_is_not_evidence():
    assert s._judge_text("1001", OWNER_PAGE, fp(MASKED_PAGE, status=403)).verdict == "none"


def test_a_copy_of_the_template_for_another_order_is_not_evidence_about_this_one():
    # Most words match the owner's page, but the page is about order 9999 and does not name 1001.
    assert s._judge_text("1001", OWNER_PAGE, fp(OTHER_ORDER_PAGE)).verdict == "none"


# --- One accessor response in another representation ------------------------------------------------------------------

def test_an_unreadable_success_in_another_representation_is_undetermined():
    judgement = s._judge_unevaluated("1001", "json", fp("%PDF-1.4 order 1001", "application/pdf"))
    assert judgement.verdict == "undetermined" and "does not evaluate" in judgement.reasons[0], judgement


def test_an_error_an_empty_body_or_an_unrelated_page_is_not_evidence():
    assert s._judge_unevaluated("1001", "json", fp("%PDF-1.4 order 1001", "application/pdf", 403)).verdict == "none"
    assert s._judge_unevaluated("1001", "json", fp("", "application/pdf")).verdict == "none"
    assert s._judge_unevaluated("1001", "json", fp("<p>Nothing here</p>")).verdict == "none"
    assert s._judge_unevaluated("1001", "json", fp("<p>Order 1001</p>", status=403)).verdict == "none"


def test_a_text_or_json_success_that_names_the_record_is_undetermined_when_the_owner_is_another_kind():
    assert s._judge_unevaluated("1001", "json", fp("<p>Order 1001: Keyboard</p>")).verdict == "undetermined"
    assert s._judge_unevaluated("1001", "text", fp('{"id": 1001}', "application/json")).verdict == "undetermined"


def test_a_declared_json_body_that_does_not_parse_and_names_the_record_is_undetermined():
    judgement = s._judge_unevaluated("1001", "json", fp('{"id": 1001, "item": ', "application/json"))
    assert judgement.verdict == "undetermined" and "does not parse" in judgement.reasons[0], judgement


# --- The matrix, end to end -------------------------------------------------------------------------------------------

def test_a_text_copy_of_the_owners_page_is_a_confirmed_leak():
    run = run_matrix(PageApp(bob="copy"))
    assert run.code == s.EXIT_POLICY, run.console
    (finding,) = of(run.findings, "confirmed")
    assert finding["check"] == "authorization-boundary" and finding["confidence"] == "medium", finding
    assert any("is identical to the owner's own page" in line for line in finding["evidence"]), finding["evidence"]


def test_a_near_identical_copy_that_differs_by_one_token_is_still_a_leak():
    run = run_matrix(PageApp(bob="nonce"))
    assert run.code == s.EXIT_POLICY, run.console
    (finding,) = of(run.findings, "confirmed")
    assert any("near-identical copy" in line for line in finding["evidence"]), finding["evidence"]


def test_an_error_status_that_still_carries_the_page_is_a_leak():
    run = run_matrix(PageApp(bob="deny_leak"))
    assert run.code == s.EXIT_POLICY, run.console
    (finding,) = of(run.findings, "confirmed")
    assert any("HTTP 403" in line for line in finding["evidence"]), finding["evidence"]


def test_an_xml_copy_of_the_owners_record_is_a_leak():
    run = run_matrix(PageApp(owner="xml", bob="copy"))
    assert run.code == s.EXIT_POLICY, run.console
    assert len(of(run.findings, "confirmed")) == 1, run.findings


def test_a_masked_view_of_the_record_is_undetermined_not_confirmed():
    run = run_matrix(PageApp(bob="masked"))
    assert run.code == s.EXIT_UNDETERMINED, run.console
    assert not of(run.findings, "confirmed"), run.findings
    assert any(f["check"] == "authorization-undetermined" for f in run.findings), run.findings


def test_a_copy_that_does_not_reproduce_on_the_second_pass_is_undetermined():
    run = run_matrix(PageApp(bob="copy_once"))
    assert run.code == s.EXIT_UNDETERMINED, run.console
    assert not of(run.findings, "confirmed"), run.findings
    assert any(f["details"].get("recheck") == "not_reproduced" for f in run.findings), run.findings


def test_a_403_that_does_not_name_the_order_is_clean():
    run = run_matrix(PageApp(bob="forbidden"))
    assert run.code == s.EXIT_OK, run.console


def test_a_short_stub_that_names_the_order_but_is_not_the_record_is_clean():
    run = run_matrix(PageApp(bob="stub"))
    assert run.code == s.EXIT_OK, run.console


def test_a_page_for_another_order_on_the_same_url_is_clean():
    run = run_matrix(PageApp(bob="other_order"))
    assert run.code == s.EXIT_OK, run.console


def test_an_empty_success_for_another_identity_is_clean():
    run = run_matrix(PageApp(bob="empty"))
    assert run.code == s.EXIT_OK, run.console


def test_a_pdf_for_another_identity_is_undetermined_not_silent():
    run = run_matrix(PageApp(bob="pdf"))
    assert run.code == s.EXIT_UNDETERMINED, run.console
    reasons = evidence_of(run.findings, "undetermined")
    assert any("application/pdf" in text and "does not evaluate" in text for text in reasons), reasons


def test_a_json_response_naming_the_record_to_a_text_owner_is_undetermined():
    run = run_matrix(PageApp(owner="html", bob="json_named"))
    assert run.code == s.EXIT_UNDETERMINED, run.console
    reasons = evidence_of(run.findings, "undetermined")
    assert any("cannot be compared" in text for text in reasons), reasons


def test_a_text_response_naming_the_record_to_a_json_owner_is_undetermined():
    run = run_matrix(PageApp(owner="json", bob="text_named"))
    assert run.code == s.EXIT_UNDETERMINED, run.console
    reasons = evidence_of(run.findings, "undetermined")
    assert any("cannot be compared" in text for text in reasons), reasons


def test_a_text_response_that_does_not_name_the_record_to_a_json_owner_is_clean():
    run = run_matrix(PageApp(owner="json", bob="text_unnamed"))
    assert run.code == s.EXIT_OK, run.console


def test_an_owner_page_without_the_id_stops_the_check_and_no_one_else_is_asked():
    app = PageApp(owner="no_id")
    run = run_matrix(app)
    assert run.code == s.EXIT_INCOMPLETE, run.console
    assert all(token == "alice-token" for token, _ in app.seen), app.seen
    reasons = evidence_of(run.findings, "incomplete")
    assert any("does not contain resource_id=1001" in text for text in reasons), reasons


def test_an_owner_pdf_stops_the_check_and_no_one_else_is_asked():
    app = PageApp(owner="pdf")
    run = run_matrix(app)
    assert run.code == s.EXIT_INCOMPLETE, run.console
    assert all(token == "alice-token" for token, _ in app.seen), app.seen
    reasons = evidence_of(run.findings, "incomplete")
    assert any("application/pdf" in text and "does not evaluate" in text for text in reasons), reasons


def test_a_collection_listing_in_text_is_incomplete_because_collections_are_judged_only_as_json():
    app = ListingApp()
    run = run_matrix(app, template="/orders")
    assert run.code == s.EXIT_INCOMPLETE, run.console
    assert all(token == "alice-token" for token, _ in app.seen), app.seen
    reasons = evidence_of(run.findings, "incomplete")
    assert any("evaluated only as JSON" in text for text in reasons), reasons
