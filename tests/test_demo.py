"""End-to-end: the shipped demo API, started as a separate process, checked with the CLI.

The vulnerable demo must be flagged; the secure demo must be clean. Both are run with the same commands the README
documents. Each server gets a free port and is stopped at the end.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import api_sentinel as s  # noqa: E402

DEMO = ROOT / "examples" / "vulnerable_api.py"
IDS = ROOT / "examples" / "identities.json"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def demo_server(secure: bool):
    port = _free_port()
    env = dict(os.environ, PORT=str(port))
    env.pop("SECURE", None)
    if secure:
        env["SECURE"] = "1"
    proc = subprocess.Popen([sys.executable, str(DEMO)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 15
        while True:
            try:
                req = urllib.request.Request(base + "/orders/1001", headers={"Authorization": "Bearer alice-token"})
                with urllib.request.urlopen(req, timeout=2):
                    break
            except Exception:  # noqa: BLE001 - 4xx is fine, the server is up
                try:
                    req = urllib.request.Request(base + "/orders/1001", headers={"Authorization": "Bearer alice-token"})
                    urllib.request.urlopen(req, timeout=2)
                except urllib.error.HTTPError:
                    break
                except Exception:  # noqa: BLE001
                    if time.time() > deadline:
                        raise RuntimeError("demo server did not start")
                    time.sleep(0.2)
                    continue
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s.cli(argv)
    return code, err.getvalue()


def test_demo_vulnerable_is_flagged_by_the_matrix_and_by_the_stateful_flow():
    # Read the reports INSIDE the temporary directory: it is deleted when the block ends.
    with tempfile.TemporaryDirectory() as td, demo_server(secure=False) as base:
        m, st = Path(td) / "matrix.json", Path(td) / "stateful.json"
        code_m, _ = _cli(["--yes-i-am-authorized", "--url", f"{base}/orders/{{id}}", "--identities", str(IDS),
                          "--output", str(m)])
        code_s, _ = _cli(["--yes-i-am-authorized", "--allow-destructive", "--url", f"{base}/orders/{{id}}",
                          "--identities", str(IDS), "--stateful", "--collection-url", f"{base}/orders",
                          "--output", str(st)])
        rep_m = json.loads(m.read_text(encoding="utf-8"))
        rep_s = json.loads(st.read_text(encoding="utf-8"))
    assert code_m == s.EXIT_POLICY and rep_m["summary"]["confirmed"] == 2
    assert code_s == s.EXIT_POLICY and rep_s["summary"]["confirmed"] == 5 and rep_s["summary"]["residue"] == 0


def test_demo_secure_is_clean_under_the_same_commands():
    with tempfile.TemporaryDirectory() as td, demo_server(secure=True) as base:
        m, st = Path(td) / "matrix.json", Path(td) / "stateful.json"
        code_m, _ = _cli(["--yes-i-am-authorized", "--url", f"{base}/orders/{{id}}", "--identities", str(IDS),
                          "--output", str(m)])
        code_s, _ = _cli(["--yes-i-am-authorized", "--allow-destructive", "--url", f"{base}/orders/{{id}}",
                          "--identities", str(IDS), "--stateful", "--collection-url", f"{base}/orders",
                          "--output", str(st)])
        rep_m = json.loads(m.read_text(encoding="utf-8"))
        rep_s = json.loads(st.read_text(encoding="utf-8"))
    assert code_m == s.EXIT_OK and rep_m["summary"]["confirmed"] == 0
    assert code_s == s.EXIT_OK and rep_s["summary"]["confirmed"] == 0 and rep_s["summary"]["residue"] == 0
