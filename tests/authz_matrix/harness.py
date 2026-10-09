"""Authorization test-matrix harness.

For every Access (owner -> accessor, verb) a scenario declares an oracle label: what is really true about the
fixture. For each case the harness

  1. runs the real api_sentinel: engine functions for matrix/stateful cases, the CLI for cli cases,
  2. independently probes a FRESH copy of the fixture to confirm the label is real (verify_access),
  3. classifies what the tool did against the label.

Every access gets exactly one outcome:

  TP / FN   label VULNERABLE: the tool confirmed it / stayed silent
  TN / FP   label SECURE:     the tool stayed silent / confirmed it
  UNDETERMINED
            the tool itself declined to decide (an undetermined result). Not FP, not FN, not TN.
  UNDECIDABLE_FLAGGED / UNDECIDABLE_SILENT
            label POLICY_DEPENDENT or INDETERMINATE: the truth cannot be decided from the input the tool gets.
            The tool confirmed it / stayed silent. Not FP, not FN.
  NEEDS_INPUT
            the check did not run: refused (missing input or missing opt-in), setup failed, skipped
            (incomplete baseline), or the target was unreachable. Never FN, never TN.
  ERROR
            the harness or the tool crashed. Never TN.

Verdict: PASS = TP or TN; FAIL = FP, FN or ERROR; NOT_DECIDED = everything else.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]  # tests/authz_matrix -> tests -> project root
sys.path.insert(0, str(ROOT))
import api_sentinel as s  # noqa: E402

from .fixtures import Fixture  # noqa: E402

VULNERABLE, SECURE, POLICY, INDET = "VULNERABLE", "SECURE", "POLICY_DEPENDENT", "INDETERMINATE"
EXPECTED = {VULNERABLE: "FINDING", SECURE: "NO_FINDING", POLICY: "NEEDS_INPUT", INDET: "NEEDS_INPUT"}
AUTHZ_CHECKS = {"authorization-boundary", "stateful-authorization-boundary"}
DEFAULT_OWNER_FIELDS = list(s.OWNER_FIELDS_DEFAULT)  # the CLI default, shared with the tool
TIMEOUT = 5.0

OUTCOME_ORDER = ["TP", "TN", "FP", "FN", "UNDETERMINED", "UNDECIDABLE_FLAGGED", "UNDECIDABLE_SILENT",
                 "NEEDS_INPUT", "ERROR"]
# outcomes that must carry a gap annotation when the label is VULNERABLE or SECURE
DEVIATIONS = {"FP", "FN", "UNDETERMINED", "NEEDS_INPUT", "ERROR"}
NEEDS_INPUT_STATES = {"REFUSED", "UNREACHABLE", "SETUP_FAILED", "SKIPPED"}


@dataclass(frozen=True)
class IdSpec:
    name: str
    token: str
    owns: tuple = ()
    params: tuple = ()         # (("user_id", "42"),) fills {user_id} in URL templates
    owner_values: tuple = ()   # (("user_id", 42),) declared ownership values


@dataclass
class Access:
    """One oracle entry: may ``accessor`` do ``verb`` to a resource owned by ``owner``?"""
    owner: str
    accessor: str
    verb: str = "GET"
    label: str = SECURE
    why: str = ""                 # required for POLICY / INDET: why the truth cannot be decided
    gap: str = ""                 # predicted gap id(s) when the tool is expected to deviate
    owner_url: str | None = None
    accessor_url: str | None = None
    leak_marker: bytes | None = None


@dataclass
class Case:
    id: str
    scenario: str
    title: str
    variant: str
    mode: str                       # matrix | stateful | cli
    build: Callable[[], Any]
    ids: list
    url: str
    oracle: list
    method: str = "GET"
    collection_url: str | None = None
    probe_mode: str | None = None   # how to verify the oracle for cli cases
    use_owns: bool = True           # cli: write 'owns' into identities.json?
    notes: str = ""


@dataclass
class ToolRun:
    findings: list = field(default_factory=list)
    error: str | None = None
    refused: str | None = None
    unreachable: str | None = None
    setup_failed: bool = False
    cli: dict | None = None
    requests: int = 0


@dataclass
class AccessResult:
    case_id: str
    scenario: str
    variant: str
    mode: str
    owner: str
    accessor: str
    verb: str
    label: str
    expected: str
    state: str
    outcome: str
    verdict: str
    gap: str
    why: str
    confidence: str
    severity: str
    score: float
    evidence: list
    verified: bool
    verify_note: str


@dataclass
class CaseResult:
    case: Case
    rows: list
    unlabeled: list
    fixture_errors: list
    cli: dict | None
    tool_error: str | None
    requests: int
    residue: int


def classify(label: str, state: str) -> str:
    if state == "ERROR":
        return "ERROR"
    if state in NEEDS_INPUT_STATES:
        return "NEEDS_INPUT"
    if state == "UNDETERMINED":
        return "UNDETERMINED"
    flagged = state == "FINDING"
    if label == VULNERABLE:
        return "TP" if flagged else "FN"
    if label == SECURE:
        return "FP" if flagged else "TN"
    return "UNDECIDABLE_FLAGGED" if flagged else "UNDECIDABLE_SILENT"


def verdict(outcome: str) -> str:
    if outcome in ("TP", "TN"):
        return "PASS"
    if outcome in ("FP", "FN", "ERROR"):
        return "FAIL"
    return "NOT_DECIDED"


# --- running the tool ----------------------------------------------------------

def _identities(case: Case):
    return [s.Identity(i.name, {"Authorization": f"Bearer {i.token}"}, list(i.owns),
                       params=dict(i.params), owner_values=dict(i.owner_values)) for i in case.ids]


def _run_engine(case: Case, fx: Fixture) -> ToolRun:
    ids = _identities(case)
    url = case.url.replace("{base}", fx.base)
    trail: list = []
    try:
        if case.mode == "matrix":
            found, trail = s.run_authorization_matrix(url, ids, case.method, DEFAULT_OWNER_FIELDS, TIMEOUT)
        else:
            coll = case.collection_url.replace("{base}", fx.base)
            # The harness is the operator here. Its targets are loopback fixtures it owns, so the write opt-in is explicit.
            found = s.run_stateful_flow(coll, url, ids, {"item": "Matrix", "total": 9.99}, TIMEOUT,
                                        allow_destructive=True, owner_fields=DEFAULT_OWNER_FIELDS, log=trail)
    except s.ConfigError as exc:  # includes DestructiveOperationRefused
        return ToolRun(refused=str(exc), requests=len(trail))
    except s.TransportError as exc:
        return ToolRun(unreachable=str(exc), requests=len(trail))
    except Exception:
        return ToolRun(error=traceback.format_exc(), requests=len(trail))
    flat = [asdict(f) for f in found]
    return ToolRun(findings=flat, setup_failed=any(f["check"] == "stateful-flow-setup" for f in flat),
                   requests=len(trail))


def _run_cli(case: Case, fx: Fixture) -> ToolRun:
    url = case.url.replace("{base}", fx.base)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        identities = []
        for i in case.ids:
            entry: dict[str, Any] = {"name": i.name, "headers": {"Authorization": f"Bearer {i.token}"}}
            if case.use_owns:
                entry["owns"] = list(i.owns)
            if i.params:
                entry["params"] = dict(i.params)
            if i.owner_values:
                entry["owner_values"] = dict(i.owner_values)
            identities.append(entry)
        (td / "identities.json").write_text(json.dumps({"identities": identities}), encoding="utf-8")
        out = td / "report.json"
        cmd = [sys.executable, str(ROOT / "api_sentinel.py"), "--yes-i-am-authorized", "--url", url,
               "--identities", str(td / "identities.json"), "--output", str(out),
               "--fail-on", "high", "--timeout", "5"]
        if case.collection_url:
            cmd += ["--stateful", "--allow-destructive",
                    "--collection-url", case.collection_url.replace("{base}", fx.base)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=td)
        report = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    last = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
    crashed = proc.returncode == s.EXIT_INTERNAL or "Traceback (most recent call last)" in proc.stderr
    findings = report["findings"] if report else []
    cli = {"returncode": proc.returncode, "report_written": report is not None,
           "report_findings": len(findings), "status": report["status"] if report else None,
           "summary": report["summary"] if report else None, "stderr_last": last, "crashed": crashed}
    if crashed:
        return ToolRun(findings=findings, error=last or "tool crashed", cli=cli)
    if proc.returncode == s.EXIT_CONFIG:
        return ToolRun(refused=last, cli=cli)
    if proc.returncode == s.EXIT_TRANSPORT:
        return ToolRun(unreachable=last, cli=cli)
    if report is None:
        return ToolRun(error=f"exit {proc.returncode} without a report: {last}", cli=cli)
    return ToolRun(findings=findings,
                   setup_failed=any(f["check"] == "stateful-flow-setup" for f in findings), cli=cli)


def _matching(run: ToolRun, a: Access):
    out = []
    for f in run.findings:
        if f["check"] not in AUTHZ_CHECKS:
            continue
        d = f.get("details") or {}
        if (d.get("owner_identity"), d.get("accessing_identity"), f["method"]) == (a.owner, a.accessor, a.verb):
            out.append(f)
    return out


def _keyed(run: ToolRun, a: Access, check: str):
    out = []
    for f in run.findings:
        if f["check"] != check:
            continue
        d = f.get("details") or {}
        if (d.get("owner_identity"), d.get("accessing_identity"), f["method"]) == (a.owner, a.accessor, a.verb):
            out.append(f)
    return out


def _owner_incomplete(run: ToolRun, owner: str) -> bool:
    return any(f["check"] == "authorization-incomplete" and (f.get("details") or {}).get("owner_identity") == owner
               for f in run.findings)


def _state(run: ToolRun, a: Access) -> str:
    if run.error:
        return "ERROR"
    if run.refused:
        return "REFUSED"
    if run.unreachable:
        return "UNREACHABLE"
    if run.setup_failed:
        return "SETUP_FAILED"
    if _matching(run, a):
        return "FINDING"
    if _keyed(run, a, "authorization-undetermined"):
        return "UNDETERMINED"
    if _owner_incomplete(run, a.owner):
        return "SKIPPED"
    return "NO_FINDING"


# --- independent oracle verification (never goes through the tool) ---------------

def _http(method: str, url: str, token: str, body: Any = None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except OSError as e:
        return None, repr(e).encode(), {}


def _created_id(body: bytes, headers: dict):
    try:
        parsed = json.loads(body) if body else None
    except ValueError:
        parsed = None
    if isinstance(parsed, dict) and "id" in parsed:
        return str(parsed["id"])
    loc = headers.get("Location") or headers.get("location")
    return loc.rstrip("/").rsplit("/", 1)[-1] if loc else None


def _applied(app, verb: str, rid: int) -> bool:
    if verb in ("PATCH", "PUT"):
        return app.orders.get(rid, {}).get("total") == 0.01
    if verb == "DELETE":
        return rid not in app.orders
    raise ValueError(verb)


def _fill(template: str, ident: IdSpec, rid, base: str) -> str:
    url = template.replace("{base}", base)
    if rid is not None:
        url = url.replace("{id}", str(rid))
    for key, value in ident.params:
        url = url.replace("{" + key + "}", str(value))
    return url


def verify_access(case: Case, a: Access):
    """Probe a FRESH fixture directly and check the oracle label is real. Returns (ok, note)."""
    spec = {i.name: i for i in case.ids}
    owner, acc = spec[a.owner], spec[a.accessor]
    mode = case.probe_mode or case.mode
    with Fixture(case.build()) as fx:
        if mode == "stateful":
            st, body, hdrs = _http("POST", _fill(case.collection_url, owner, None, fx.base), owner.token,
                                   {"item": "Verify", "total": 9.99})
            rid = _created_id(body, hdrs)
            if st not in (200, 201) or rid is None:
                return False, f"could not create a resource as {owner.name} (HTTP {st})"
        else:
            if not owner.owns:
                return False, "owner has no seeded resource to probe"
            rid = owner.owns[0]
        owner_url = _fill(a.owner_url or case.url, owner, rid, fx.base)
        acc_url = _fill(a.accessor_url, acc, rid, fx.base) if a.accessor_url else owner_url
        if a.verb == "GET":
            so, bo, _ = _http("GET", owner_url, owner.token)
            sa, ba, _ = _http("GET", acc_url, acc.token)
            if so != 200:
                return False, f"owner could not read its own resource (HTTP {so})"
            # Disclosure is judged from the body. A 403 whose body still carries the record discloses it.
            effect = (a.leak_marker in ba) if a.leak_marker else (ba == bo)
            note = (f"accessor GET -> HTTP {sa}; owner's data {'disclosed' if effect else 'not disclosed'} "
                    "(judged from the body, not from the status)")
        else:
            payload = {"total": 0.01} if a.verb in ("PATCH", "PUT") else None
            sa, _ba, _ = _http(a.verb, acc_url, acc.token, payload)
            effect = _applied(fx.app, a.verb, int(rid))
            note = f"accessor {a.verb} -> HTTP {sa}; effect {'applied' if effect else 'not applied'}"
    want = a.label in (VULNERABLE, POLICY, INDET)  # for undecidable labels the access itself must really happen
    ok = effect == want
    return ok, note + ("" if ok else f"  [ORACLE MISMATCH for label {a.label}]")


# --- running a case ------------------------------------------------------------------

def run_case(case: Case) -> CaseResult:
    with Fixture(case.build()) as fx:
        run = _run_cli(case, fx) if case.mode == "cli" else _run_engine(case, fx)
        fixture_errors = list(fx.errors)
    keys = {(a.owner, a.accessor, a.verb) for a in case.oracle}
    unlabeled = []
    for f in run.findings:
        d = f.get("details") or {}
        key = (d.get("owner_identity"), d.get("accessing_identity"), f["method"])
        if f["check"] in AUTHZ_CHECKS and key not in keys:
            unlabeled.append(f)
    residue = sum(1 for f in run.findings if f.get("status") == "residue")
    rows = []
    for a in case.oracle:
        state = _state(run, a)
        hits = _matching(run, a) or _keyed(run, a, "authorization-undetermined")
        best = max(hits, key=lambda f: f["score"]) if hits else None
        outcome = classify(a.label, state)
        ok, note = verify_access(case, a)
        rows.append(AccessResult(
            case.id, case.scenario, case.variant, case.mode, a.owner, a.accessor, a.verb, a.label,
            EXPECTED[a.label], state, outcome, verdict(outcome), a.gap, a.why,
            best["confidence"] if best else "", best["severity"] if best else "",
            best["score"] if best else 0.0, best["evidence"] if best else [], ok, note))
    return CaseResult(case, rows, unlabeled, fixture_errors, run.cli, run.error, run.requests, residue)


def run_all(cases):
    return [run_case(c) for c in cases]


def snapshot(results) -> dict:
    out = {}
    for r in results:
        for t in r.rows:
            out[f"{t.case_id}|{t.owner}>{t.accessor}|{t.verb}"] = {
                "state": t.state, "outcome": t.outcome, "confidence": t.confidence,
                "severity": t.severity, "score": t.score}
    return dict(sorted(out.items()))


def counts(results) -> Counter:
    c = Counter()
    for r in results:
        for t in r.rows:
            c[t.outcome] += 1
    return c


def totals(results) -> dict:
    rows = [t for r in results for t in r.rows]
    v = Counter(t.verdict for t in rows)
    return {
        "scenarios": len({r.case.scenario for r in results}),
        "cases": len(results),
        "accesses": len(rows),
        "pass": v["PASS"], "fail": v["FAIL"], "not_decided": v["NOT_DECIDED"],
        "requests_sent": sum(r.requests for r in results),
        "residue_left_on_target": sum(r.residue for r in results),
        "vulnerable_missed_only_by_abstention": sum(1 for t in rows
                                                    if t.label == VULNERABLE and t.outcome == "UNDETERMINED"),
    }


def pair_table(results, pairs):
    by_id = {r.case.id: r for r in results}
    out = []
    for name, vid, sid in pairs:
        v = [t for t in by_id[vid].rows if t.label == VULNERABLE]
        sc = [t for t in by_id[sid].rows if t.label == SECURE]
        vf = sum(t.state == "FINDING" for t in v)
        sf = sum(t.state == "FINDING" for t in sc)
        if vf == 0:
            verdict_text = "BLIND (vulnerable variant not flagged)"
        elif sf > 0:
            verdict_text = "NOT DISCRIMINATED (secure variant also flagged)"
        elif vf < len(v):
            verdict_text = "DISCRIMINATES, but misses some vulnerable accesses"
        else:
            verdict_text = "DISCRIMINATES"
        out.append((name, vid, sid, f"{vf}/{len(v)}", f"{sf}/{len(sc)}", verdict_text))
    return out
