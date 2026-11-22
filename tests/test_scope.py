"""Scope and secrets: ${NAME} environment references, the --allow-host allowlist, and the redirect policy.

Expected values are written from what the rules say, not read back from the implementation. The CLI and the engine run
against loopback fixtures. A pure function is tested directly only where the rule is about that function itself.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import api_sentinel as s  # noqa: E402
from authz_matrix.fixtures import Fixture, OrdersApp, Resp  # noqa: E402
from test_engine import Recorder  # noqa: E402

BOB_LITERAL = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": ["2001"]}


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def environment(**values):
    """Set environment variables for one test, then put the old values back. None unsets a variable."""
    saved = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        s._SECRETS.clear()


def identities_path(folder, entries):
    path = Path(folder) / "identities.json"
    path.write_text(json.dumps({"identities": entries}), encoding="utf-8")
    return str(path)


def closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- ${NAME} references -------------------------------------------------------------------------------------------

def test_a_reference_reads_the_secret_from_the_environment_and_the_file_holds_only_the_name():
    with tempfile.TemporaryDirectory() as folder, environment(SENTINEL_TEST_ALICE="alice-token"):
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer ${SENTINEL_TEST_ALICE}"}, "owns": ["1001"]},
            BOB_LITERAL])
        alice = s.load_identities(path)[0]
        text = Path(path).read_text(encoding="utf-8")
    assert alice.headers == {"Authorization": "Bearer alice-token"}, alice.headers
    assert "alice-token" not in text and "${SENTINEL_TEST_ALICE}" in text, text


def test_references_also_fill_params_and_owner_values_and_leave_non_text_values_alone():
    with tempfile.TemporaryDirectory() as folder, environment(SENTINEL_TEST_UID="42"):
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"},
             "params": {"user_id": "${SENTINEL_TEST_UID}"},
             "owner_values": {"user_id": "${SENTINEL_TEST_UID}", "tenant": 7}},
            BOB_LITERAL])
        alice = s.load_identities(path)[0]
    assert alice.params == {"user_id": "42"}, alice.params
    assert alice.owner_values == {"user_id": "42", "tenant": 7}, alice.owner_values


def test_an_unset_or_empty_variable_is_a_config_error_that_names_it_and_prints_no_value():
    for value in (None, ""):
        with tempfile.TemporaryDirectory() as folder, environment(SENTINEL_TEST_MISSING=value):
            path = identities_path(folder, [
                {"name": "alice", "headers": {"Authorization": "Bearer ${SENTINEL_TEST_MISSING}"}}, BOB_LITERAL])
            try:
                s.load_identities(path)
            except s.ConfigError as exc:
                message, code = str(exc), exc.exit_code
            else:
                raise AssertionError(f"a variable with value {value!r} must be refused")
        assert "SENTINEL_TEST_MISSING" in message and "'alice'" in message, message
        assert code == s.EXIT_CONFIG, code


def test_a_missing_variable_stops_the_cli_before_any_request_is_sent():
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with Fixture(rec) as fx, tempfile.TemporaryDirectory() as folder, environment(SENTINEL_TEST_MISSING=None):
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer ${SENTINEL_TEST_MISSING}"}, "owns": ["1001"]},
            BOB_LITERAL])
        code, _, err = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--identities", path])
    assert code == s.EXIT_CONFIG, (code, err)
    assert "SENTINEL_TEST_MISSING" in err and rec.calls == [], (err, rec.calls)


def test_text_that_is_not_a_reference_is_left_alone():
    with tempfile.TemporaryDirectory() as folder:
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer $NOT_A_REFERENCE", "X-Note": "${not a name}"}},
            BOB_LITERAL])
        alice = s.load_identities(path)[0]
    assert alice.headers == {"Authorization": "Bearer $NOT_A_REFERENCE", "X-Note": "${not a name}"}, alice.headers


# --- Redaction of environment values ---------------------------------------------------------------------------

def test_a_secret_from_the_environment_is_redacted_from_a_report_in_every_serialized_form():
    secret = 'ali"ce\\tok'  # a quote and a backslash, which JSON escapes
    with tempfile.TemporaryDirectory() as folder, environment(SENTINEL_TEST_ESC=secret):
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer ${SENTINEL_TEST_ESC}"}}, BOB_LITERAL])
        s.load_identities(path)
        report = {"summary": {"confirmed": 0},
                  "trail": [{"url": f"http://127.0.0.1:1/orders/{secret}"}],
                  "findings": [{"evidence": [f"token {secret} was echoed back"]}]}
        text = json.dumps(s.redact(report), indent=2)
    assert secret not in text, text
    assert json.dumps(secret)[1:-1] not in text, text  # the JSON-escaped form
    assert "[redacted:SENTINEL_TEST_ESC]" in text, text


def test_a_console_line_never_shows_an_environment_value():
    with tempfile.TemporaryDirectory() as folder, environment(SENTINEL_TEST_CONSOLE="console-secret-7731"):
        s.load_identities(identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer ${SENTINEL_TEST_CONSOLE}"}}, BOB_LITERAL]))
        buffer = io.StringIO()
        print("[x] GET http://127.0.0.1:1/orders/console-secret-7731 failed", file=s._RedactingStream(buffer))
    shown = buffer.getvalue()
    assert "console-secret-7731" not in shown, shown
    assert "[redacted:SENTINEL_TEST_CONSOLE]" in shown, shown


def test_a_transport_error_printed_by_the_cli_hides_an_environment_value_in_its_url():
    port = closed_port()
    url = f"http://127.0.0.1:{port}/users/{{user_id}}/orders/{{id}}"
    with tempfile.TemporaryDirectory() as folder, environment(SENTINEL_TEST_UID="uid-5519"):
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"],
             "params": {"user_id": "${SENTINEL_TEST_UID}"}},
            {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": ["2001"],
             "params": {"user_id": "${SENTINEL_TEST_UID}"}}])
        code, out, err = run_cli(["--yes-i-am-authorized", "--url", url, "--identities", path,
                                  "--output", str(Path(folder) / "report.json")])
    assert "uid-5519" not in out + err, (out, err)
    assert "[redacted:SENTINEL_TEST_UID]" in out + err, (out, err)
    assert code in (s.EXIT_TRANSPORT, s.EXIT_INCOMPLETE), code


def test_a_run_with_secrets_from_the_environment_works_and_none_of_them_reaches_any_output():
    # The tenant value is an environment value that lands in the URL the report quotes, so the report must mask it.
    values = dict(SENTINEL_TEST_ALICE="alice-token", SENTINEL_TEST_BOB="bob-token", SENTINEL_TEST_TENANT="tenant-8842")
    with environment(**values):
        with Fixture(OrdersApp({"GET": "allow"})) as fx, tempfile.TemporaryDirectory() as folder:
            path = identities_path(folder, [
                {"name": "alice", "headers": {"Authorization": "Bearer ${SENTINEL_TEST_ALICE}"}, "owns": ["1001"],
                 "params": {"tenant": "${SENTINEL_TEST_TENANT}"}},
                {"name": "bob", "headers": {"Authorization": "Bearer ${SENTINEL_TEST_BOB}"}, "owns": ["2001"],
                 "params": {"tenant": "${SENTINEL_TEST_TENANT}"}}])
            report = str(Path(folder) / "report.json")
            code, out, err = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}?ref={tenant}",
                                      "--identities", path, "--output", report])
            written = Path(report).read_text(encoding="utf-8")
    # Bob reads Alice's order: a confirmed high finding. Exit 1 also shows that the environment tokens were accepted.
    assert code == s.EXIT_POLICY, (code, err)
    assert "[redacted:SENTINEL_TEST_TENANT]" in written, "the report should quote the URL with the value masked"
    for text in (written, out + err):
        assert not any(value in text for value in values.values()), text[:300]


# --- --allow-host ----------------------------------------------------------------------------------------------

def test_allow_host_refuses_a_target_outside_the_list_and_sends_nothing():
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with Fixture(rec) as fx, tempfile.TemporaryDirectory() as folder:
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}, BOB_LITERAL])
        code, _, err = run_cli(["--yes-i-am-authorized", "--allow-host", "example.invalid",
                                "--url", fx.base + "/orders/{id}", "--identities", path])
    assert code == s.EXIT_CONFIG, (code, err)
    assert "not in --allow-host" in err and rec.calls == [], (err, rec.calls)


def test_allow_host_lets_the_listed_host_run_the_checks():
    with Fixture(OrdersApp({"GET": "allow"})) as fx, tempfile.TemporaryDirectory() as folder:
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}, BOB_LITERAL])
        code, _, err = run_cli(["--yes-i-am-authorized", "--allow-host", "127.0.0.1",
                                "--url", fx.base + "/orders/{id}", "--identities", path,
                                "--output", str(Path(folder) / "report.json")])
    assert code == s.EXIT_POLICY, (code, err)


def test_allow_host_refuses_a_plan_against_another_base_url_before_anything_is_sent():
    spec = {"openapi": "3.0.3", "paths": {
        "/orders": {"get": {"responses": {"200": {"description": "list"}}}},
        "/orders/{id}": {"get": {"responses": {"200": {"description": "one"}}}}}}
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with Fixture(rec) as fx, tempfile.TemporaryDirectory() as folder:
        spec_path = Path(folder) / "openapi.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}, BOB_LITERAL])
        code, _, err = run_cli(["--yes-i-am-authorized", "--openapi", str(spec_path), "--base-url", fx.base,
                                "--allow-host", "example.invalid", "--identities", path])
    assert code == s.EXIT_CONFIG, (code, err)
    assert rec.calls == [], rec.calls


def test_allow_host_takes_host_names_and_refuses_urls_ports_paths_and_bare_ipv6():
    assert s._allowed_hosts(None) is None and s._allowed_hosts([]) is None
    assert s._allowed_hosts(["API.internal", " 127.0.0.1 "]) == frozenset({"api.internal", "127.0.0.1"})
    assert s._allowed_hosts(["[::1]"]) == frozenset({"::1"})
    for bad in ("http://127.0.0.1", "127.0.0.1:8000", "api.internal/orders", "user@api.internal", "::1",
                "api internal", "", "api.internal?x=1"):
        try:
            s._allowed_hosts([bad])
        except s.ConfigError:
            continue
        raise AssertionError(f"--allow-host {bad!r} must be refused")


def test_a_port_in_allow_host_is_refused_by_the_cli_before_any_request():
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with Fixture(rec) as fx, tempfile.TemporaryDirectory() as folder:
        port = fx.server.server_address[1]
        path = identities_path(folder, [
            {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}, BOB_LITERAL])
        code, _, err = run_cli(["--yes-i-am-authorized", "--allow-host", f"127.0.0.1:{port}",
                                "--url", fx.base + "/orders/{id}", "--identities", path])
    assert code == s.EXIT_CONFIG and rec.calls == [] and "host name only" in err, (code, err, rec.calls)


def test_only_http_and_https_URLs_are_used():
    for url in ("file:///etc/hostname", "ftp://127.0.0.1/x", "127.0.0.1:8000/orders"):
        try:
            s.request("GET", url)
        except s.ConfigError as exc:
            assert exc.exit_code == s.EXIT_CONFIG, exc.exit_code
            continue
        raise AssertionError(f"{url!r} must be refused before anything is sent")


# --- Redirects ---------------------------------------------------------------------------------------------------

def test_a_same_origin_redirect_is_followed_and_the_credential_goes_with_it_as_before():
    seen = []

    def app(req):
        seen.append((req.path, req.token))
        if req.path == "/a":
            return Resp(302, headers={"Location": "/b"})
        return Resp(200, {"ok": True})

    with Fixture(app) as fx:
        fp = s.request("GET", fx.base + "/a", headers={"Authorization": "Bearer t-1"})
    assert fp.status == 200, fp.status
    assert seen == [("/a", "t-1"), ("/b", "t-1")], seen


def test_a_cross_origin_redirect_is_not_followed_so_the_credential_never_reaches_the_other_origin():
    elsewhere_seen = []

    def elsewhere(req):
        elsewhere_seen.append((req.path, req.token))
        return Resp(200, {"landed": True})

    with Fixture(elsewhere) as other:
        with Fixture(lambda req: Resp(302, headers={"Location": other.base + "/landing"})) as fx:
            fp = s.request("GET", fx.base + "/go", headers={"Authorization": "Bearer t-1"})
    assert fp.status == 302, fp.status
    assert "location" in fp.headers, fp.headers
    assert elsewhere_seen == [], elsewhere_seen


def test_origin_comparison_ignores_case_and_default_ports_and_nothing_else():
    assert s.same_origin("HTTP://Example.test/x", "http://example.test:80/y")
    assert s.same_origin("https://a.test", "https://a.test:443/")
    assert not s.same_origin("https://a.test", "http://a.test")
    assert not s.same_origin("http://a.test:8080/", "http://a.test/")
    assert not s.same_origin("http://a.test/", "http://b.test/")
    assert not s.same_origin("http://127.0.0.1:1/", "http://localhost:1/")
    assert not s.same_origin("http://a.test/", "not a url")
