# API Sentinel

**Authorization (BOLA) regression testing for APIs you are authorized to test.**

API Sentinel answers one question for an API: *can an identity that does not own a resource read or change it?*
You give it two or more identities (for example Alice and Bob), the resources each one owns, and the URL of the
endpoint. It requests each resource as the other identities and reports only what the evidence supports.

It is a command-line tool written in Python with the standard library only. There is nothing to install beyond Python.

> **Authorization warning.** Use API Sentinel only against systems you own or are explicitly authorized to test.
> The stateful mode creates, modifies and deletes resources on the target. Use it only on a disposable environment.
> `--yes-i-am-authorized` is a deliberate attestation that stops accidental runs. It is not a security control, and
> the tool does not check the target against any allowlist.

## What it detects

- **Cross-identity reads of a resource** (`GET /orders/{id}`). Alice's order can be read by Bob.
- **Responses that disclose the record despite a 403.** A "forbidden" body that still carries the owner's data.
- **Caller-specific parents in nested routes.** `/users/{user_id}/orders/{id}`: the accessor's own `user_id` is
  substituted, so a server that checks the parent but not the order's owner is caught.
- **Collection endpoints.** `GET /orders` returns another user's order inside the list.
- **Write verbs, through the opt-in stateful flow.** A PATCH or DELETE by a non-owner is reported only when the owner's
  own read afterwards shows the change or the deletion. A `200` or `204` alone is never a finding.

Each result is one of: **confirmed** (the evidence rules were met; a lead for human validation, not proof),
**undetermined** (the tool declined to decide), **incomplete** (a check could not run), **residue** (a resource the
scan created was left on the target), or **info** (for example, a write that had no effect).

## What it does NOT detect

- **Resources the identities do not declare.** The matrix tests only the ids listed in `owns`. It does not enumerate ids.
- **Intent.** It cannot tell a legitimate admin override, a shared resource or a public resource from a broken access
  check. Those results are reported as undecidable, not as confirmed or cleared.
- **Actions other than GET, PATCH and DELETE** in the stateful flow. PUT and POST sub-actions such as `/cancel` are not tried.
- **Non-JSON responses.** They cannot be evaluated; the check is reported as incomplete, never as passed.
- **Partial views.** A response that carries only part of the record (for example a status) is not judged.
- **Same-principal identities.** Two tokens of one account are treated as two identities.
- **Unauthenticated access, token or JWT claims, GraphQL, gRPC, rate limits, race conditions, business-logic
  authorization, and tenant scoping** beyond the fields you name in `--ownership-fields`.

A clean result does not prove that an API is secure.

## Requirements and installation

The tool is one file, `api_sentinel.py`. It imports only the Python standard library and reads no other file of this
project. The test suite, the authorization matrix, the demo API and the GitHub Actions files are development material:
they are not needed to run the tool.

- Python 3.12 is the tested version. Tested on Linux only; Windows and macOS were not tested. The package declares `requires-python >= 3.9`, but only 3.12 was tested.
- No third-party packages are needed to run the tool or its test suite.

Run it from a clone without installing:

```bash
python3 api_sentinel.py --help
```

Or install it into a virtual environment, which provides the `api-sentinel` command. The first install needs network access: pip fetches the build backend (setuptools):

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
api-sentinel --help
```

## Quick start

The repository includes a deliberately vulnerable demo API and a matching identities file. Start the demo in one
terminal:

```bash
python3 examples/vulnerable_api.py          # http://127.0.0.1:8000 (vulnerable mode)
```

In a second terminal, run the matrix (read-only: it only sends GET):

```bash
python3 api_sentinel.py --yes-i-am-authorized \
  --url "http://127.0.0.1:8000/orders/{id}" \
  --identities examples/identities.json
```

Expected result: two confirmed findings (Bob reads Alice's order 1001, and Alice reads Bob's order 2001), and exit
code `1`. The summary line reads `confirmed=2`.

Add the stateful flow to test writes. This sends PATCH and DELETE to the demo and therefore needs the opt-in:

```bash
python3 api_sentinel.py --yes-i-am-authorized --allow-destructive \
  --url "http://127.0.0.1:8000/orders/{id}" \
  --identities examples/identities.json \
  --stateful --collection-url "http://127.0.0.1:8000/orders"
```

Expected result: five confirmed findings (the two from the matrix, and GET, PATCH and DELETE by Bob on the order that
Alice creates), exit code `1`, and `residue=0`.

### The secure demo

Stop the vulnerable demo and start the secure one with `SECURE=1`. Run the same two commands:

```bash
SECURE=1 python3 examples/vulnerable_api.py
```

Expected result: `confirmed=0` for both commands, and exit code `0`.

## Command-line usage

```text
api-sentinel --yes-i-am-authorized --url URL --identities FILE [options]
```

| Option | Meaning |
|---|---|
| `--yes-i-am-authorized` | Required. Attests that you are authorized to test the target. |
| `--url URL` | Endpoint template containing `{id}`. Other `{names}` are filled from identity `params`. |
| `--identities FILE` | JSON file describing two or more identities (see below). |
| `--allow-destructive` | Opt-in for `--stateful`: allows create, PATCH and DELETE on the target. |
| `--stateful --collection-url URL` | Also run the create-then-cross-access flow. Needs `--allow-destructive`. |
| `--fail-on {none,high,critical}` | Exit `1` when a confirmed finding is at or above this severity. Default: `high`. |
| `--output FILE` | JSON report (default `api-sentinel-report.json`). |
| `--html-output FILE`, `--sarif-output FILE` | Optional HTML and SARIF reports. |
| `--method GET` | Only GET is accepted. Any other method is refused before a request is sent. |
| `--baseline-ids a,b,c`, `--fuzz` | Behavioral baseline. Deviations are reported as undetermined anomalies only. They cannot run alone: a run with no authorization check is refused (exit 2). |
| `--token-a T --token-b T --test-id ID` | Two-identity shorthand: token A owns `ID`; token B must not read it. |
| `--openapi FILE [--graph]` | List the operations in an OpenAPI (JSON) file, or print a heuristic resource graph. It tests nothing: exit `0` only means the file was read. |
| `--ownership-fields a,b,c` | Response fields treated as ownership signals. |
| `--auth-header NAME` | Header that carries the token (default `Authorization`). |
| `--create-body JSON` | JSON object used to create a resource in the stateful flow (default `{"item": "API Sentinel test item", "total": 9.99}`). |
| `--timeout SECONDS`, `--debug` | Request timeout; tracebacks for errors. |

### Identities file

```json
{
  "identities": [
    { "name": "alice", "headers": { "Authorization": "Bearer alice-token" }, "owns": [1001] },
    { "name": "bob",   "headers": { "Authorization": "Bearer bob-token" },   "owns": [2001] }
  ]
}
```

- `owns` lists the resource ids the identity owns. An identity with no `owns` can still be an accessor. The stateful
  flow creates its own resources, so `owns` is not needed there.
- `params` fills `{name}` placeholders in the URL for that identity, for example `{"user_id": "42"}`.
- `owner_values` declares ownership values, for example `{"user_id": 42}`. If the owner's record contradicts the
  declaration, the result is undetermined, not confirmed.

**Keep tokens out of git.** A root-level `identities.json` is listed in `.gitignore`. In CI, write the file from repository secrets
at run time (see the GitHub Actions section).

## Reports

A run that completes (exit 0, 1, 3 or 6) writes a JSON report. A refused run (exit 2), an unreachable target (exit 4) and an internal error (exit 5) write none. `--html-output` and `--sarif-output` add the other two formats.

### JSON

The report has `schema_version` (currently 2), `version`, `status` (`complete` or `incomplete`), `summary`, `coverage`,
`baseline`, the `findings` list and a `disclaimer`. Each finding has a `category`: `confirmed`, `undetermined`,
`incomplete`, `residue` or `info`. The summary counts the same categories, so the counts always agree with the list. The `status` of a confirmed finding
is `confirmed`: it means the evidence rules were met, not that the vulnerability was proven.

`coverage` shows what actually ran: identities, owned resources tested, requests sent, checks run, checks passed,
confirmed, undetermined and incomplete.

### HTML

A single page. Confirmed findings are labelled `CONFIRMED`, and undetermined and incomplete results are labelled
separately. The header shows the same counts as the JSON summary.

### SARIF 2.1.0

Contains **confirmed findings only**; undetermined and incomplete results are not code-scanning alerts. The tool version
is in `tool.driver.version`. The artifact location is the identities file (or the report path when no identities file
is given), and the endpoint is recorded as a logical location.

The SARIF output was checked for its required structure. It has not been validated against the official schema or
uploaded to GitHub code scanning from this environment.

## Exit codes

| Code | Meaning | What to do |
|---:|---|---|
| `0` | Clean: nothing confirmed, nothing undetermined, nothing incomplete. | None. |
| `1` | A confirmed finding at or above `--fail-on`. | Validate the finding (see its evidence). |
| `2` | Configuration problem, or a refused operation (missing `--yes-i-am-authorized`, `--method` other than GET, `--stateful` without `--allow-destructive`, identities with no `owns`, a URL parameter with no value, or nothing to test: no authorization check is configured). | Fix the input. Nothing was sent to the target. |
| `3` | Incomplete: setup failed, or an owner's own resource could not be read, so checks did not run. | Fix the identities or the create endpoint. This is not a pass. |
| `4` | Transport failure: the target refused or reset the connection, or timed out. | Check the URL and the network. |
| `5` | Internal error (a bug in this tool). The message says so; `--debug` shows the traceback. | Report it. |
| `6` | Undetermined: nothing confirmed or incomplete, but some results need human review. | Review the undetermined results. |

`--fail-on none` reports without failing: confirmed findings then leave the exit code unchanged.

## GitHub Actions

The repository contains a composite action (`action.yml`) and a sample workflow
(`examples/github-workflow.yml`). The action passes its inputs through environment variables, not through the script
text. It writes the SARIF file even when the scan stops early, so the upload step does not fail.

Inputs: `url`, `identities`, `collection-url`, `stateful`, `allow-destructive`, `fail-on` (default `high`),
`fail-on-undetermined` (default `false`), `sarif-output`, `json-output`. Outputs: `exit-code`, `sarif`.

**Verification status.** The action's shell script was executed locally with the environment that GitHub passes, for a
confirmed finding (exit 1), a clean run (exit 0), an undetermined result (exit 0 by default, exit 6 when
`fail-on-undetermined` is `true`), a connection error (exit 4) and two kinds of invalid configuration (exit 2). Each
run left a structurally valid SARIF file. **The action has not been run on a GitHub-hosted runner.** The self-test in `examples/github-workflow-selftest.yml` is the way to verify it: copy it to `.github/workflows/` of a test repository, together with `action.yml`, `api_sentinel.py` and `examples/`, run it manually and read its assertions. One step uploads the vulnerable scan's SARIF to the Security tab when code scanning is enabled; that upload does not decide the result. Validate it in your
repository before relying on it.

## Testing

```bash
python3 tests/run_all.py           # the whole suite, standard library only
```

The suite covers the evidence rules, the CLI exit codes and refusals, the report and SARIF outputs, and the vulnerable and
secure demos run as separate processes. The matrix under `tests/authz_matrix/` is a synthetic corpus of 59 cases
(157 accesses). Run it with:

```bash
python3 tests/authz_matrix/run_matrix.py --write
```

The suite needs no third-party package. `--write` also writes `tests/authz_matrix/results.csv` (per-access results; ignored by git).

`python3 tests/emulate_selftest.py` runs the self-test workflow's steps locally, in order, with the action's own script. It is an emulator, not GitHub: it needs PyYAML, Linux with bash, and port 8000 free, and it proves nothing that depends on GitHub itself.

## Outcome glossary (the matrix and the tests)

The matrix gives every access one outcome. Its oracle label is the truth about the fixture, checked by a direct probe.

| Outcome | Meaning |
|---|---|
| TP | The access must be denied and the tool confirmed it. |
| TN | The access must be denied and the tool stayed silent. |
| FP | The access must be denied, but the tool confirmed it: a false alarm. |
| FN | The access must be denied, but the tool stayed silent: a miss. |
| UNDETERMINED | The tool declined to decide. It is not FP or FN. Counted separately, because a vulnerable access it cannot decide is lost recall. |
| UNDECIDABLE_FLAGGED / UNDECIDABLE_SILENT | The truth itself cannot be decided from the input (admin override, sharing, public resource, two tokens of one account). Not FP or FN. |
| NEEDS_INPUT | The check did not run: refused, setup failed, skipped, or the target was unreachable. Never a pass, never an FN. |
| ERROR | The harness or the tool crashed. Never a pass. |

PASS = TP or TN. FAIL = FP, FN or ERROR. NOT DECIDED = everything else. A check that did not run is never counted as a pass.

Measured on the matrix in this version (59 cases, 157 accesses): TP 54, TN 69, FP 0, FN 1, UNDETERMINED 7, UNDECIDABLE_FLAGGED 12, UNDECIDABLE_SILENT 1, NEEDS_INPUT 13, ERROR 0. Verdicts: PASS 123, FAIL 1, NOT DECIDED 33.

## Architecture

- `api_sentinel.py`: the whole tool in one module. It contains the HTTP layer, the identities loader, the matrix and
  evidence rules, the stateful flow, the report builders and the command-line interface.
- `examples/`: the vulnerable and secure demo API (`examples/vulnerable_api.py`), the identities and OpenAPI examples, and the
  sample workflow.
- `action.yml`: the composite GitHub Action.
- `tests/`: the test suite (`run_all.py` runs every `test_*.py`).
- `tests/authz_matrix/`: the synthetic corpus. `fixtures.py` holds the fixture APIs, `scenarios.py` the cases and their
  labels, `harness.py` the outcome logic and the independent oracle probes, and `baseline.json` the pinned outcomes.
- `docs/TEST_MATRIX_RESULTS.md`: the matrix results, generated by `run_matrix.py --write`.

## Limitations

- **PUT and POST.** The stateful flow tries GET, PATCH and DELETE. PUT is never tried (the one FN in the matrix). POST is used only to create the test resource; POST sub-actions such as `/cancel` are never tried.
- **Resources without a known resource id.** A representation with no id the tool recognises (`id`, `orderId`, `order_id`, `resource_id`, `uuid`) cannot be attributed to a resource. The tool reports it as UNDETERMINED rather than guessing; on the matrix this costs 4 vulnerable accesses of recall.
- **Destructive operations.** The only write path is `--stateful`, which needs `--allow-destructive`. No new write operation is added in this version.

- The matrix corpus is small and written by hand. Its counts are not detection rates for real APIs.
- On that corpus the tool has no false positives among the clear cases, and one false negative: a PUT update that the
  stateful flow does not try. Four vulnerable accesses are undetermined because their representations carry no resource id
  the tool recognises; the tool abstains there instead of guessing.
- Non-JSON responses are not evaluated. The check reports incomplete (exit 3 or NEEDS_INPUT in the matrix).
- Resources must be declared. Identifier discovery and enumeration are not implemented.
- `--ownership-fields` is a list of names. Owner fields outside the default list still detect a leak through the
  identical-record rule, but they are not used as ownership evidence.
- The stateful flow writes to the target: it creates resources, patches a field of them and deletes them. It removes
  what it created, and reports anything it could not remove as residue.
- The OpenAPI graph is a heuristic and reads JSON only.
- There is no `--version` flag yet. The version is in the report and the package metadata.

## Troubleshooting

- **Exit 2 with "nothing to test".** No authorization check is configured. Give two identities with `owns`, `--test-id` with both tokens, or `--stateful` with `--allow-destructive`. `--baseline-ids` and `--fuzz` alone never show authorization.
- **Exit 2 with "refusing to run".** Add `--yes-i-am-authorized`.
- **Exit 2 with "--method ... is not supported".** The baseline, fuzz and matrix checks are read-only. Use `--stateful`.
- **Exit 2 with "--stateful creates, modifies and deletes".** Add `--allow-destructive`, and only on a disposable target.
- **Exit 2 with "declares no 'owns' resources".** Each identity that owns something needs an `owns` list.
- **Exit 2 with "has no params.user_id".** A URL placeholder has no value for that identity. Add `params`.
- **Exit 3 with "could not establish its own resource".** The owner cannot read its own resource: check the token and the
  id. A non-JSON response has the same effect.
- **Exit 3 with "create ... did not create a resource".** The create endpoint must return the new id in a JSON body.
- **Exit 4 with "failed: Connection refused".** Nothing is listening at that address.
- **Exit 6.** Open the JSON report, find the `undetermined` entries and read their evidence.

## Roadmap

Not implemented yet, and not claimed anywhere else in this document:

- Generating a test plan automatically from an OpenAPI document.
- Testing undeclared resource ids (enumeration).
- PUT and POST sub-actions in the stateful flow.
- Evaluating non-JSON responses.
- A `--version` flag and a target allowlist.
- Reading secrets from the environment instead of the identities file.
- Testing on Python versions other than 3.12.

## License

MIT. See `LICENSE`.
