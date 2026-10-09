#!/usr/bin/env python3
"""Local emulator of examples/github-workflow-selftest.yml. It is NOT GitHub.

It runs the workflow's steps in order, in a temporary copy of this project, so the project folder is never written to.
  * run steps: bash with GitHub's default flags for bash (-eo pipefail);
  * steps that use the local action (uses: ./): runs the script stored in action.yml with the environment that
    action.yml declares, then reads the outputs that script writes to GITHUB_OUTPUT;
  * third-party actions (actions/checkout, github/codeql-action/upload-sarif): reported as NOT RUN, because they need GitHub.
Job rules it follows: a failing step stops the job unless continue-on-error is set; steps with if: always() still run.

What it does NOT prove: anything that depends on GitHub itself, such as secrets, permissions, the hosted runner, whether
GitHub keeps the outputs of a failed step that has continue-on-error, background processes between steps, and the
SARIF upload.

Requirements: Linux with bash, curl and python3 on PATH; PyYAML (not part of the standard library); port 8000 free.
Usage:  python3 tests/emulate_selftest.py      (exit 0: every emulated step passed; 1: a step failed; 2: port 8000 busy)
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = pathlib.Path("examples") / "github-workflow-selftest.yml"


def port_busy(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


def run(work: pathlib.Path) -> int:
    wf = yaml.safe_load((work / WORKFLOW).read_text(encoding="utf-8"))
    steps = wf["jobs"]["selftest"]["steps"]
    action = yaml.safe_load((work / "action.yml").read_text(encoding="utf-8"))
    act = action["runs"]["steps"][0]
    defaults = {k: str(v.get("default", "")) for k, v in action["inputs"].items()}
    outputs: dict[str, dict[str, str]] = {}
    inputs_ctx: dict[str, str] = {}
    base_env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/root")}

    def expand(text: str) -> str:
        def repl(m: re.Match) -> str:
            expr = m.group(1).strip()
            if expr.startswith("steps."):
                _, sid, _, name = expr.split(".", 3)
                return outputs.get(sid, {}).get(name, "")
            if expr == "github.action_path":
                return str(work)
            if expr.startswith("inputs."):
                return inputs_ctx.get(expr.split(".", 1)[1], "")
            if expr.startswith("secrets."):
                return ""
            raise SystemExit(f"unsupported expression in the workflow: {expr}")
        return re.sub(r"\$\{\{(.*?)\}\}", repl, text)

    def bash(script: pathlib.Path, env: dict) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
                              cwd=work, env=env, capture_output=True, text=True, timeout=280)

    def run_local_action(with_inputs: dict, sid: str) -> subprocess.CompletedProcess:
        inputs_ctx.clear()
        inputs_ctx.update({**defaults, **{k: expand(str(v)) for k, v in with_inputs.items()}})
        env = dict(base_env)
        for k, v in act["env"].items():
            env[k] = expand(str(v))
        gh = work / f".gh_output_{sid}"
        gh.write_text("", encoding="utf-8")
        env["GITHUB_OUTPUT"] = str(gh)
        script = work / f".action_{sid}.sh"
        script.write_text(act["run"], encoding="utf-8")
        proc = bash(script, env)
        outputs[sid] = dict(line.split("=", 1) for line in gh.read_text(encoding="utf-8").splitlines() if "=" in line)
        proc.log_tail = (proc.stdout + proc.stderr).strip()[-200:].replace("\n", " / ")
        return proc

    report: list[tuple[str, str]] = []
    failed = False
    for i, step in enumerate(steps):
        name = step.get("name") or step.get("uses") or "(unnamed step)"
        sid = step.get("id")
        always = str(step.get("if", "")).strip() == "always()"
        coe = bool(step.get("continue-on-error", False))
        if failed and not always:
            report.append(("SKIPPED", name))
            continue
        if "uses" in step:
            if step["uses"] == "actions/checkout@v4":
                report.append(("PASS", name + " (repository is already in place)"))
            elif step["uses"] == "./":
                proc = run_local_action({k: str(v) for k, v in step.get("with", {}).items()}, sid)
                ok = proc.returncode == 0
                tag = f" [exit-code output={outputs[sid].get('exit-code')}]"
                if not ok:
                    tag += f" log: {proc.log_tail[-150:]}"
                if coe and not ok:
                    tag += " (continue-on-error)"
                report.append(("PASS" if ok else f"EXIT {proc.returncode}", name + tag))
                if not ok and not coe:
                    failed = True
            else:
                report.append(("NOT RUN", f"{name} ({step['uses']} needs GitHub; not executed here)"))
            continue
        if "run" in step:
            script = work / f".run_{i}.sh"
            script.write_text(expand(step["run"]), encoding="utf-8")
            proc = bash(script, dict(base_env))
            ok = proc.returncode == 0
            detail = "" if ok else " " + (proc.stdout + proc.stderr).strip()[-220:].replace("\n", " / ")
            report.append(("PASS" if ok else "FAIL", name + detail))
            if not ok and not coe:
                failed = True
            continue
        report.append(("?", name))

    for status, text in report:
        print(f"{status:9} {text}")
    print("JOB RESULT (emulated):", "failure" if failed else "success")
    return 1 if failed else 0


def main() -> int:
    if port_busy(8000):
        print("port 8000 is in use; the self-test needs it free.")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="api-sentinel-selftest-"))
    try:
        shutil.copytree(ROOT, work, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "api-sentinel-report.json"))
        return run(work)
    finally:
        for pid_file in work.glob("*.pid"):  # stop any demo the emulated steps started
            try:
                os.kill(int(pid_file.read_text(encoding="utf-8").strip()), 15)
            except (OSError, ValueError):
                pass
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
