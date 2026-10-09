"""Command-line tests: exit codes, the write opt-in, the destructive-method refusal, fail-on semantics, configuration
errors, transport errors, internal errors, and the report files that the CLI writes.

The CLI runs in-process (api_sentinel.cli) against loopback fixtures; stdout and stderr are captured.
"""
from __future__ import annotations

import contextlib
import io
import json
import socket
import sys
import tempfile
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import api_sentinel as s  # noqa: E402
from authz_matrix.fixtures import Fixture, NestedApp, OrdersApp, ReprApp  # noqa: E402

from test_engine import Recorder  # noqa: E402

ALICE = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}
BOB = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": ["2001"]}
ALICE_BARE = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": []}
BOB_BARE = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": []}


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


def write_identities(td, entries, name="identities.json"):
    path = Path(td) / name
    path.write_text(json.dumps({"identities": entries}), encoding="utf-8")
    return str(path)


def closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _base_args(url, ids_path, output, *extra):
    return ["--yes-i-am-authorized", "--url", url, "--identities", ids_path, "--output", output, *extra]


# --- authorization, refusals, configuration -----------------------------------------------

def test_missing_authorization_flag_exits_2():
    code, _, err = run_cli(["--url", "http://127.0.0.1:9/orders/{id}"])
    assert code == s.EXIT_CONFIG and "--yes-i-am-authorized" in err


def test_a_non_get_method_is_refused_and_nothing_is_sent():
    rec = Recorder(OrdersApp({"DELETE": "allow"}))
    with tempfile.TemporaryDirectory() as td, Fixture(rec) as fx:
        ids = write_identities(td, [ALICE, BOB])
        code, _, err = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(Path(td) / "r.json"),
                                          "--method", "DELETE", "--allow-destructive"))
    assert code == s.EXIT_CONFIG and "read-only" in err
    assert rec.calls == [] and 1001 in rec.app.orders


def test_stateful_without_the_opt_in_is_refused_and_nothing_is_sent():
    rec = Recorder(OrdersApp({"GET": "allow"}))
    with tempfile.TemporaryDirectory() as td, Fixture(rec) as fx:
        ids = write_identities(td, [ALICE_BARE, BOB_BARE])
        code, _, err = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(Path(td) / "r.json"),
                                          "--stateful", "--collection-url", fx.base + "/orders"))
    assert code == s.EXIT_CONFIG and "--allow-destructive" in err
    assert rec.calls == []


def test_identities_without_owns_exit_2():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td, [{**ALICE, "owns": []}, {**BOB, "owns": []}])
        code, _, err = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(Path(td) / "r.json")))
    assert code == s.EXIT_CONFIG and "no 'owns'" in err


def test_invalid_identities_json_exits_2():
    with tempfile.TemporaryDirectory() as td:
        bad = Path(td) / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        code, _, err = run_cli(_base_args("http://127.0.0.1:9/orders/{id}", str(bad), str(Path(td) / "r.json")))
    assert code == s.EXIT_CONFIG and "not readable JSON" in err


def test_a_url_parameter_without_an_identity_value_exits_2_before_any_request():
    rec = Recorder(NestedApp("child_vuln"))
    with tempfile.TemporaryDirectory() as td, Fixture(rec) as fx:
        ids = write_identities(td, [ALICE, BOB])
        code, _, err = run_cli(_base_args(fx.base + "/users/{user_id}/orders/{id}", ids, str(Path(td) / "r.json")))
    assert code == s.EXIT_CONFIG and "params.user_id" in err
    assert rec.calls == []


def test_the_example_identities_file_loads():
    ids = s.load_identities(str(ROOT / "examples" / "identities.json"))
    assert [i.name for i in ids] == ["alice", "bob"] and ids[0].owns == ["1001"]


# --- exit codes: the CI contract -----------------------------------------------------------

def test_transport_failure_exits_4_without_a_traceback():
    with tempfile.TemporaryDirectory() as td:
        ids = write_identities(td, [ALICE, BOB])
        code, _, err = run_cli(_base_args(f"http://127.0.0.1:{closed_port()}/orders/{{id}}", ids,
                                          str(Path(td) / "r.json")))
    assert code == s.EXIT_TRANSPORT
    assert "Traceback" not in err and "failed" in err


def test_a_failed_setup_exits_3_and_is_reported_as_setup_failed():
    with tempfile.TemporaryDirectory() as td, \
            Fixture(OrdersApp({"GET": "allow", "PATCH": "allow", "DELETE": "allow"}, create_responds="location")) as fx:
        ids = write_identities(td, [ALICE_BARE, BOB_BARE])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(out),
                                        "--stateful", "--allow-destructive", "--collection-url", fx.base + "/orders"))
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_INCOMPLETE and rep["status"] == "incomplete"
    assert any(f["check"] == "stateful-flow-setup" and f["status"] == "setup_failed" for f in rep["findings"])


def test_an_owner_baseline_that_cannot_be_read_exits_3():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "deny"})) as fx:
        ids = write_identities(td, [{**ALICE, "owns": ["9999"]}, BOB])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(out)))
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_INCOMPLETE
    assert rep["summary"]["incomplete"] >= 1 and rep["summary"]["confirmed"] == 0


def test_a_confirmed_finding_exits_1_by_default():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td, [ALICE, BOB])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(out)))
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_POLICY and rep["summary"]["confirmed"] == 2


def test_a_secure_api_exits_0():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "deny"})) as fx:
        ids = write_identities(td, [ALICE, BOB])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(out)))
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_OK and rep["summary"]["confirmed"] == 0 and rep["status"] == "complete"


def test_fail_on_none_reports_without_failing():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td, [ALICE, BOB])
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(Path(td) / "r.json"), "--fail-on", "none"))
    assert code == s.EXIT_OK


def test_fail_on_separates_high_from_critical():
    """A leak that is only 'high' does not fail a gate set to critical, but fails a gate set to high."""
    with tempfile.TemporaryDirectory() as td, Fixture(ReprApp("ref_full")) as fx:
        ids = write_identities(td, [ALICE, BOB])
        code_critical, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(Path(td) / "a.json"),
                                                 "--fail-on", "critical"))
        code_high, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(Path(td) / "b.json"),
                                             "--fail-on", "high"))
    assert code_critical == s.EXIT_OK and code_high == s.EXIT_POLICY


def test_undetermined_only_exits_6():
    declared = {**ALICE, "owner_values": {"user_id": 7}}   # the record says 42: the declaration contradicts it
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td, [declared, {**BOB, "owns": []}])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(out)))
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_UNDETERMINED
    assert rep["summary"]["confirmed"] == 0 and rep["summary"]["undetermined"] >= 1


def test_an_internal_error_exits_5_with_a_controlled_message():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td, [ALICE, BOB])
        with mock.patch.object(s, "run_authorization_matrix", side_effect=RuntimeError("boom")):
            code, _, err = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(Path(td) / "r.json")))
    assert code == s.EXIT_INTERNAL and "internal error" in err and "Traceback" not in err


def test_fuzz_without_a_baseline_exits_2():
    code, _, err = run_cli(["--yes-i-am-authorized", "--url", "http://127.0.0.1:9/orders/{id}", "--fuzz"])
    assert code == s.EXIT_CONFIG and "--baseline-ids" in err


# --- the write opt-in on a disposable target --------------------------------------------------

def test_stateful_with_the_opt_in_flags_the_vulnerable_api_and_leaves_no_residue():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow", "PATCH": "allow", "DELETE": "allow"})) as fx:
        ids = write_identities(td, [ALICE_BARE, BOB_BARE])
        out = Path(td) / "r.json"
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(out), "--stateful",
                                        "--allow-destructive", "--collection-url", fx.base + "/orders"))
        rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == s.EXIT_POLICY and rep["summary"]["confirmed"] >= 3 and rep["summary"]["residue"] == 0
    assert {f["method"] for f in rep["findings"] if f["category"] == "confirmed"} >= {"GET", "PATCH", "DELETE"}


def test_test_id_shorthand_flags_the_vulnerable_api_and_clears_the_secure_one():
    with tempfile.TemporaryDirectory() as td:
        with Fixture(OrdersApp({"GET": "allow"})) as fx:
            code_v, _, _ = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--test-id", "1001",
                                    "--token-a", "alice-token", "--token-b", "bob-token",
                                    "--output", str(Path(td) / "v.json")])
        with Fixture(OrdersApp({"GET": "deny"})) as fx:
            code_s, _, _ = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--test-id", "1001",
                                    "--token-a", "alice-token", "--token-b", "bob-token",
                                    "--output", str(Path(td) / "s.json")])
    assert code_v == s.EXIT_POLICY and code_s == s.EXIT_OK


# --- report files ------------------------------------------------------------------------------

def test_json_html_and_sarif_are_written_and_agree_with_each_other():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td, [ALICE, BOB])
        out, html, sarif = Path(td) / "r.json", Path(td) / "r.html", Path(td) / "r.sarif"
        code, _, _ = run_cli(_base_args(fx.base + "/orders/{id}", ids, str(out),
                                        "--html-output", str(html), "--sarif-output", str(sarif)))
        rep = json.loads(out.read_text(encoding="utf-8"))
        sar = json.loads(sarif.read_text(encoding="utf-8"))
        page = html.read_text(encoding="utf-8")
    assert code == s.EXIT_POLICY
    assert rep["version"] == s.__version__ and rep["schema_version"] == 2
    assert rep["operator_attested_authorization"] is True and rep["status"] == "complete"
    assert sum(rep["summary"].values()) == len(rep["findings"])
    assert {"checks_run", "passed", "confirmed", "requests_sent", "owned_resources_tested"} <= set(rep["coverage"])
    assert len(sar["runs"][0]["results"]) == rep["summary"]["confirmed"] == 2
    assert sar["runs"][0]["tool"]["driver"]["version"] == s.__version__
    assert "CONFIRMED" in page


def test_a_run_with_no_authorization_check_configured_is_refused_before_any_request():
    code, _, err = run_cli(["--yes-i-am-authorized", "--url", "http://127.0.0.1:9/orders/{id}"])
    assert code == s.EXIT_CONFIG and "nothing to test" in err


def test_baseline_alone_does_not_show_authorization_and_is_refused():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        code, _, err = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--token-a", "alice-token",
                                "--baseline-ids", "1001,1001,1001", "--output", str(Path(td) / "r.json")])
    assert code == s.EXIT_CONFIG and "nothing to test" in err
