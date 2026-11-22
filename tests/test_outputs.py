"""Report output and the CLI surface added in 0.3.0: --report-dir (unique names, never overwritten), --version, and
the refusals that keep those options from being combined with the options they replace.
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
from authz_matrix.fixtures import Fixture, OrdersApp  # noqa: E402

ALICE = {"name": "alice", "headers": {"Authorization": "Bearer alice-token"}, "owns": ["1001"]}
BOB = {"name": "bob", "headers": {"Authorization": "Bearer bob-token"}, "owns": ["2001"]}


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, out.getvalue(), err.getvalue()


def write_identities(folder):
    path = Path(folder) / "identities.json"
    path.write_text(json.dumps({"identities": [ALICE, BOB]}), encoding="utf-8")
    return str(path)


def test_report_dir_writes_three_reports_under_one_name_per_run_and_never_overwrites():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td)
        target = str(Path(td) / "reports")
        argv = ["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--identities", ids,
                "--report-dir", target]
        codes = [run_cli(argv)[0], run_cli(argv)[0]]
        files = sorted(Path(target).iterdir())
        jsons = [p for p in files if p.suffix == ".json"]
        first = json.loads(jsons[0].read_text(encoding="utf-8"))
        html = next(p for p in files if p.suffix == ".html").read_text(encoding="utf-8")
        sarif = json.loads(next(p for p in files if p.suffix == ".sarif").read_text(encoding="utf-8"))
    assert codes == [s.EXIT_POLICY, s.EXIT_POLICY]
    assert len(files) == 6 and len(jsons) == 2
    assert len({p.stem for p in files}) == 2                       # two runs, two names, no overwrite
    assert first["summary"]["confirmed"] == 2 and "CONFIRMED" in html
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == 2


def test_report_dir_cannot_be_combined_with_the_outputs_it_replaces_and_writes_nothing():
    with tempfile.TemporaryDirectory() as td, Fixture(OrdersApp({"GET": "allow"})) as fx:
        ids = write_identities(td)
        target = Path(td) / "reports"
        code, _, err = run_cli(["--yes-i-am-authorized", "--url", fx.base + "/orders/{id}", "--identities", ids,
                                "--report-dir", str(target), "--output", str(Path(td) / "x.json")])
    assert code == s.EXIT_CONFIG and "--report-dir writes all three" in err
    assert not target.exists()


def test_version_flag_prints_the_version_and_exits_0():
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            s.cli(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--version should exit")
    assert s.__version__ in out.getvalue()


def test_base_url_without_openapi_is_refused_before_anything_is_sent():
    code, _, err = run_cli(["--yes-i-am-authorized", "--base-url", "http://127.0.0.1:9"])
    assert code == s.EXIT_CONFIG and "need --openapi" in err


def test_plan_only_without_base_url_is_refused_and_writes_nothing():
    with tempfile.TemporaryDirectory() as td:
        spec = Path(td) / "openapi.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {}}), encoding="utf-8")
        target = Path(td) / "plan.json"
        code, _, err = run_cli(["--yes-i-am-authorized", "--openapi", str(spec), "--plan-only",
                                "--output", str(target)])
    assert code == s.EXIT_CONFIG and "--plan-only needs --base-url" in err
    assert not target.exists()
