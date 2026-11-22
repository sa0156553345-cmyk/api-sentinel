# API Sentinel

**Authorization (BOLA) regression testing for APIs you are authorized to test.**

API Sentinel answers one question for an API: *can an identity that does not own a resource read or change it?*
You give it two or more identities (for example Alice and Bob), the resources each one owns, and the URL of the
endpoint. It requests each resource as the other identities and reports only what the evidence supports.

It is a command-line tool written in Python with the standard library only. There is nothing to install beyond Python.

> **Authorization warning.** Use API Sentinel only against systems you own or are explicitly authorized to test.
> The stateful mode creates, modifies and deletes resources on the target. Use it only on a disposable environment.
> `--yes-i-am-authorized` is a deliberate attestation that stops accidental runs. It is not a security control. Pass
> `--allow-host` with each host you are authorized to test: without it, the tool contacts whatever host the URLs name.

## What it detects

- **Cross-identity reads of a resource** (`GET /orders/{id}`). Alice's order can be read by Bob.
- **Responses that disclose the record despite a 403.** A "forbidden" body that still carries the owner's data.
- **Text responses (HTML, XML, plain text).** The owner's page is compared with the other identity's. An identical or
  near-identical copy that still names the resource is a leak, even under an error status. A similar page that is not a
  copy is undetermined. A page that does not name the resource is not evidence.
- **Caller-specific parents in nested routes.** `/users/{user_id}/orders/{id}`: the accessor's own `user_id` is
  substituted, so a server that checks the parent but not the order's owner is caught.
- **Collection endpoints.** `GET /orders` returns another user's order inside the list.
- **Write verbs, through the opt-in stateful flow.** A PATCH, PUT or DELETE by a non-owner is reported only when the
  owner's own read afterwards shows the change or the deletion, and a second read of the owner's record shows it again.
  The write is sent once. A `200` or `204` alone is never a finding. A write the target rejects as malformed (`400` or
  `422`) is UNDETERMINED, not a pass.
- **POST sub-actions, through the opt-in stateful flow (`--actions FILE`).** An operation such as
  `POST /orders/{id}/cancel`, declared in a file, is sent once by each non-owner. It is reported only when the owner's own
  record afterwards shows the result that the file declares. A status code alone is never a finding.

Each result is one of: **confirmed** (the evidence rules were met and a second pass reproduced them; a lead for human
validation, not proof), **undetermined** (the tool declined to decide, including a leak that did not reproduce),
**incomplete** (a check could not run), **residue** (a resource the scan created was left on the target), or **info**
(for example, a write that had no effect).

## What it does NOT detect

- **Resources nobody declares or lists.** The matrix tests the ids in `owns`, plus the ids that `--discover` or plan mode attribute from a listing. It does not guess ids: there is no neighbour probing and no enumeration.
- **Intent.** It cannot tell a legitimate admin override, a shared resource or a public resource from a broken access
  check. Those results are reported as undecidable, not as confirmed or cleared.
- **Undeclared POST operations.** Only the actions in an `--actions` file are sent, and the tool never discovers one. A
  declared action that returns data and changes nothing in the owner's record cannot be judged either: such a leak is not
  seen.
- **Binary responses (PDF, images), and other formats than the owner's record.** They cannot be compared with the owner's
  record. As the owner's response the check is incomplete. As another identity's successful response it is undetermined
  when it is binary or names the resource.
- **Partial views.** A response that carries only part of the record (for example a status) is not judged.
- **Same-principal identities.** Two tokens of one account are treated as two identities.
- **Unauthenticated access, token or JWT claims, GraphQL, gRPC, rate limits, race conditions, business-logic
  authorization, and tenant scoping** beyond the fields you name in `--ownership-fields`.

A clean result does not prove that an API is secure.

## Requirements and installation

The tool is one file, `api_sentinel.py`. It imports only the Python standard library and reads no other file of this
project. The test suite, the authorization matrix, the demo API and the GitHub Actions files are development material:
they are not needed to run the tool.

- Python 3.9, 3.10, 3.11, 3.12 and 3.13 were tested, with the whole suite passing on each. Tested on Linux only; Windows and macOS were not tested.
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

Add the stateful flow to test writes. This sends PATCH, PUT and DELETE to the demo and therefore needs the opt-in:

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
| `--allow-host HOST` | Host name the tool may contact, for example `staging.example.com`. Repeatable. Every URL is checked before the first request, and a run that names another host is refused with exit `2` before anything is sent. Matches the host name only (no scheme, port or path). See *Scope and secrets*. |
| `--allow-destructive` | Opt-in for `--stateful`: allows create, PATCH, PUT and DELETE on the target, and the POST actions of `--actions`. |
| `--stateful --collection-url URL` | Also run the create-then-cross-access flow. Needs `--allow-destructive`. |
| `--actions FILE` | Also send the POST sub-actions declared in FILE, in the stateful flow. Needs `--stateful` and `--allow-destructive`. See *POST sub-actions*. |
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
| `--discover` | Read each identity's own listing (`--collection-url`, one GET per identity) and test the ids it shows. See *Ownership discovery*. |
| `--report-dir DIR` | Write the JSON, HTML and SARIF reports into DIR under a unique, timestamped name. Existing reports are never overwritten. Not allowed with `--output`, `--html-output` or `--sarif-output`. |
| `--openapi FILE --base-url URL [--plan-only]` | Build a test plan from an OpenAPI file against URL and run it. `--plan-only` prints and saves the plan and sends nothing. See *OpenAPI test plan*. |
| `--version` | Print the version and exit. |
| `--id-field FIELD` | Name of the response field that carries the resource id, for example `book_title`. Used for matching records and for discovery. Replaces the default id names for the run. |
| `--no-recheck` | Skip the second pass that must reproduce each confirmed finding, in the matrix and in the stateful flow. One response is then enough to confirm. See *Confirmation: the second pass*. |

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
- `${NAME}` in a header, `params` or `owner_values` value is replaced with the environment variable `NAME` when the file
  is loaded. An unset or empty variable is refused with exit `2`, and the message names the variable, never its value.

**Keep tokens out of git.** Put the token in the environment, not in the file: write `"Bearer ${ALICE_TOKEN}"` and set
`ALICE_TOKEN` when you run the tool. In CI, set it from repository secrets (see the GitHub Actions section). A root-level
`identities.json` is listed in `.gitignore` as a second line of defence.

## Scope and secrets

- **Allowlist.** `--allow-host` names the hosts the tool may contact. It is checked for every URL the run is given (the
  target, the collection URL, the base URL and the URLs of any `--actions` file) before the first request, so a refused run sends nothing. Host names are
  compared as written in the URL and are not resolved, so a name that points at another address is not caught. Without
  `--allow-host` the tool contacts any host the URLs name, which is why CI runs should set it.
- **Only http and https.** Any other scheme is refused before a request is sent.
- **Redirects stay in their origin.** A redirect is followed only when it keeps the scheme, host and port of the request
  that was sent. Any other redirect is not followed: the 3xx response is recorded as the response, and nothing is sent to
  the location it names. The `Authorization` header therefore never travels to a host the identity was not configured for.
- **Values from the environment are masked.** Everything read through `${NAME}` is replaced with `[redacted:NAME]` in the
  JSON, HTML and SARIF reports and on the console. The mask matches the value wherever it occurs. Use environment
  variables for secrets, and literal values for identifiers you want to see in reports: a one-character identifier taken
  from the environment would be masked wherever that character occurs.

## Confirmation: the second pass

A single response is not enough to confirm an authorization violation. Responses can differ between identical requests
for reasons unrelated to authorization: a cache, a race, a rate limit that briefly opened. So after the first matrix
pass, every confirmed finding is checked again:

- The whole read-only matrix runs a second time, with the same identities, resources and URLs.
- The stateful flow has its own second pass. A read is repeated. A write is not sent again: the owner's record is read
  once more, and the change (or, for a DELETE, the missing record) must still be there. A POST action from `--actions`
  is handled the same way: it is never sent again.
- A finding stays **confirmed** only if the second pass reproduces it: the same owner, accessing identity, resource and URL.
- Otherwise it becomes **undetermined**, and its evidence says why:
  - *did not reproduce*: the same request returned a different result, or the owner's record no longer showed the write;
  - *could not be rechecked*: the owner's own baseline failed on the second pass, so the request could not be repeated;
  - *seen only on the second pass*: the first pass did not confirm it, and one observation is not confirmation. If the
    first pass had judged the same request undetermined, that reason stays in the evidence.

If the target stops answering during the second pass, every candidate that was not repeated is reported as *could not
be rechecked*, with the error, and the first-pass evidence stays in the report. The run then exits `6`, not `4`.

The second pass runs only when the first pass has something to confirm, so a run with no finding sends no extra requests.
Its requests count in `requests sent` in the coverage section. A check that both passes ran counts once, and a check that
only the second pass ran (its owner's baseline failed on the first pass) counts as a check. The stateful flow has no
"seen only on the second pass" case: its second pass only re-reads what the first observation saw. Each stateful check
creates and removes its own resource, so no second pass depends on an earlier one. `--no-recheck` turns the second pass
off, in both parts, and gives the single-response behaviour of earlier versions.

A server that leaks on every request is confirmed. A server that leaks only sometimes is reported as undetermined, not
as confirmed: the tool cannot prove an intermittent leak from one response.

## POST sub-actions (`--actions`)

Some operations change a resource through a POST rather than a PATCH, PUT or DELETE, for example
`POST /orders/{id}/cancel`. `--actions FILE` declares such actions for the stateful flow. They are sent only there, so
they need `--stateful`, and therefore `--allow-destructive`. The tool never discovers an action: an action that is not in
the file is never sent.

```json
{
  "actions": [
    {
      "name": "cancel",
      "url": "https://staging.example.com/orders/{id}/cancel",
      "body": {},
      "expect": { "status": "cancelled" }
    }
  ]
}
```

- `name` labels the action in the report. It starts with a letter, holds letters, digits, `_` or `-` (up to 64
  characters), and is neither an HTTP method name (`GET`, `PATCH`, `PUT`, `DELETE` or `POST`) nor a name already used.
- `url` must contain `{id}`, and it is checked against `--allow-host` before the first request. Other `{names}` are filled
  from each identity's `params`, as for `--url`. A nested route such as `/users/{user_id}/orders/{id}/cancel` is tried with
  the owner's `user_id` and with the accessor's own, as the verbs are.
- `body` is the JSON object sent with the POST. It defaults to `{}`.
- `expect` gives the values the owner's record must show once the action has taken effect, for example
  `{"status": "cancelled"}`. It is required, it must not be empty, and no value may be `null`.

The whole file is checked before any request is sent. Each action is then judged like a write, from the owner's record and
never from the status code:

- If the owner's record already shows every `expect` value before the request, the action is **not sent**. Its effect could
  not be seen, so the result is UNDETERMINED.
- Otherwise the action is sent once, with the non-owner's headers, and the owner's record is read. If the record now shows
  every `expect` value, the action is **confirmed**, whatever status the target answered: a 403 or a 202 that changed the
  record is still confirmed.
- A success status with no change to the record is **no effect**: information, not a finding. Its advice names the `expect`
  values to check.
- A 202 with no change is UNDETERMINED, because the effect may come later. So is a 400 or 422 with no change. Any other
  refusal is not a finding.
- The second pass reads the owner's record again. The action is not sent again. If the record no longer shows the result,
  the finding is UNDETERMINED (*did not reproduce*).

```bash
python3 api_sentinel.py --yes-i-am-authorized --allow-destructive \
  --url "https://staging.example.com/orders/{id}" \
  --identities identities.json \
  --stateful --collection-url "https://staging.example.com/orders" \
  --actions actions.json
```

The demo API has no action endpoint, so this command is for a target that has one. The feature is tested in
`tests/test_post_actions.py` and in the matrix (scenario `S27`).

Limits of the judgement:

- Only declared actions are tried. An undeclared POST is never sent.
- The owner's record is the only evidence. A change made by someone else between the request and the read looks the same,
  and the second read cannot tell the two apart.
- The tool removes only the resource it created. An action that creates another resource leaves that one on the target,
  and the tool does not report it. Run the stateful flow only on a disposable environment.
- A declared action that returns data without changing the record cannot be judged.

## Ownership discovery (`--discover`)

`--discover` reads each identity's own collection listing (`--collection-url`, one GET per identity, first page only) and tests the ids it shows. Ownership is attributed conservatively:

- a declared id stays with the identity that declared it;
- an item whose ownership field equals that identity's `owner_values` belongs to it (`owner-field`), even when a leaky listing shows the item to everybody;
- an id that exactly one identity can see belongs to that identity (`listing`);
- anything else is ambiguous and is **not tested**. The report lists those ids.

Use `--id-field` when records are keyed by a field other than `id`, such as `book_title`. Discovered ids go through the same evidence rules as declared ids. A finding on a discovered id is capped at **medium** confidence, and its evidence says how the ownership was inferred. The report's `discovery` section shows what each listing gave.

```bash
python3 api_sentinel.py --yes-i-am-authorized --discover \
  --url "https://staging.example.com/orders/{id}" \
  --collection-url "https://staging.example.com/orders" \
  --identities identities.json
```

## OpenAPI test plan (`--openapi --base-url`)

Plan mode builds a test plan from an OpenAPI JSON file and runs it against the server you name:

```bash
python3 api_sentinel.py --yes-i-am-authorized --openapi openapi.json \
  --base-url "https://staging.example.com" --plan-only     # print and save the plan; sends nothing
python3 api_sentinel.py --yes-i-am-authorized --openapi openapi.json \
  --base-url "https://staging.example.com" --identities identities.json
```

- A route whose last segment is an identity parameter and that has a GET (for example `/orders/{orderId}`) is tested when the document has a GET collection for its parent (`/orders`, or `/users/{uid}/orders` for a nested route). Ownership is discovered from that collection, as with `--discover`.
- A nested route such as `/users/{uid}/orders/{id}` needs each identity to declare its own value for every parent parameter in `params` (for example `{"uid": "42"}`). Requests for that route use each identity's own parent value, so a server that checks the parent but not the item's owner is caught. An identity without the value makes the route incomplete (exit `3`), and no request is sent for it.
- Every other route appears in the plan with the reason it is not tested: a placeholder inside a path segment (such as `{id}.json`), a parent parameter named `id`, and a collection under a parameter.
- Declared `owns` are ignored in plan mode, because they do not say which resource type they belong to.
- A tested route where discovery attributes no id at all is reported as **incomplete** (exit 3), not as a pass.

## Report files (`--report-dir`)

`--report-dir DIR` writes the JSON, HTML and SARIF reports together under one unique name, such as `api-sentinel-20261121T030000Z-1a2b3c.json`. Each run gets its own name and nothing is overwritten. Use it in CI or on a machine where the working directory is temporary.

## Reports

A run that completes (exit 0, 1, 3 or 6) writes a JSON report. A refused run (exit 2), an unreachable target (exit 4) and an internal error (exit 5) write none. `--html-output` and `--sarif-output` add the other two formats.

### JSON

The report has `schema_version` (currently 2), `version`, `status` (`complete` or `incomplete`), `summary`, `coverage`,
`baseline`, the `findings` list and a `disclaimer`. Each finding has a `category`: `confirmed`, `undetermined`,
`incomplete`, `residue` or `info`. The summary counts the same categories, so the counts always agree with the list. The `status` of a confirmed finding
is `confirmed`: it means the evidence rules were met, not that the vulnerability was proven.

`coverage` shows what actually ran: identities, owned resources tested, requests sent, checks run, checks passed,
confirmed, undetermined and incomplete.

`recheck` shows the second pass: `totals` (candidates, reproduced, not_reproduced, not_rechecked, second_pass_only) and
`runs`, one entry per matrix pass and one for the stateful flow when it runs. Each entry has its `scope` (`matrix`,
`test-id` or `stateful`), its counts, and `interrupted` (the error that stopped the second pass, or `null`). `enabled` is
the setting: it is `false` with `--no-recheck`. A pass with no candidate sends no second pass, and its entry says
`ran: false`.

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
| `0` | Clean: no confirmed finding at or above `--fail-on`, nothing undetermined, nothing incomplete. A confirmed finding below `--fail-on` leaves the exit code unchanged but stays in the report. | None. |
| `1` | A confirmed finding at or above `--fail-on`. | Validate the finding (see its evidence). |
| `2` | Configuration problem, or a refused operation (missing `--yes-i-am-authorized`, `--method` other than GET, `--stateful` without `--allow-destructive`, `--actions` without `--stateful`, an actions file that does not validate, identities with no `owns`, a URL parameter with no value, a host that `--allow-host` does not list, an unset `${NAME}` in the identities file, or nothing to test: no authorization check is configured). | Fix the input. Nothing was sent to the target. |
| `3` | Incomplete: setup failed, or an owner's own resource could not be read, so checks did not run. | Fix the identities or the create endpoint. This is not a pass. |
| `4` | Transport failure: the target refused or reset the connection, or timed out. | Check the URL and the network. |
| `5` | Internal error (a bug in this tool). The message says so; `--debug` shows the traceback. | Report it. |
| `6` | Undetermined: nothing confirmed or incomplete, but some results need human review. This includes leaks that did not reproduce on the second pass. | Review the undetermined results. |

`--fail-on none` reports without failing: confirmed findings then leave the exit code unchanged.

## GitHub Actions

The repository contains a composite action (`action.yml`) and a sample workflow
(`examples/github-workflow.yml`). The action passes its inputs through environment variables, not through the script
text. It writes the SARIF file even when the scan stops early, so the upload step does not fail.

Inputs: `url`, `identities`, `collection-url`, `stateful`, `allow-destructive`, `actions` (path to a POST sub-actions file, relative to the repository root; needs `stateful` and `allow-destructive`), `allow-host` (comma-separated host names), `fail-on` (default `high`),
`fail-on-undetermined` (default `false`), `sarif-output`, `json-output`. Outputs: `exit-code`, `sarif`.

**Verification status.** The action's shell script was executed locally with the environment that GitHub passes, for a
confirmed finding (exit 1), a clean run (exit 0), an undetermined result (exit 0 by default, exit 6 when
`fail-on-undetermined` is `true`), a connection error (exit 4) and two kinds of invalid configuration (exit 2). Each
run left a structurally valid SARIF file. The `allow-host` input was run the same way: an unlisted host gave exit 2
before any request, and a listed host, written with a space after the comma, passed the check. The `actions` input was run the same way. Without `stateful` it gave exit 2 from the command line's own message, before any request. With `stateful`, `allow-destructive` and `actions`, the script passed the file to the command line, which announced one POST action, and the secure demo gave exit 0. That demo has no action endpoint, so the action's request got a 404 and found nothing: the run shows the wiring, not that actions detect anything. The repository self-test workflow at `.github/workflows/api-sentinel-selftest.yml` has been run on a GitHub-hosted `ubuntu-latest` runner. Workflow run #3 completed successfully. The workflow runs the action from the repository root and checks the configured test scenarios. One step uploads the vulnerable scan's SARIF to the Security tab when code scanning is enabled; that upload does not decide the result. Validate it in your
repository before relying on it.

## Testing

```bash
python3 tests/run_all.py           # the whole suite (188 tests), standard library only
```

In this release the suite passed on Python 3.9, 3.10, 3.11, 3.12 and 3.13.

The suite covers the evidence rules, the POST sub-actions, the CLI exit codes and refusals, the report and SARIF outputs,
and the vulnerable and secure demos run as separate processes. The matrix under `tests/authz_matrix/` is a synthetic corpus
of 67 cases (186 accesses). Run it with:

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

Measured on the matrix in this version (67 cases, 186 accesses): TP 63, TN 92, FP 0, FN 0, UNDETERMINED 7, UNDECIDABLE_FLAGGED 12, UNDECIDABLE_SILENT 1, NEEDS_INPUT 11, ERROR 0. Verdicts: PASS 155, FAIL 0, NOT DECIDED 31. In 0.5.1 the stateful flow tries PUT, so the one false negative of 0.5.0 (a PUT update) is now a true positive. The pinned baseline test in `tests/test_matrix.py` checks each access's outcome against `tests/authz_matrix/baseline.json`. The matrix sends 721 requests in total, including the second passes.

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

- **The second pass runs once.** A leak that appears in only some requests can be missed by both passes, or reported as not reproduced. Repeating more often would multiply the requests; that is not implemented.
- **Writes are not repeated.** The stateful second pass reads the owner's record again instead of sending the write a second time. A write is confirmed only when its effect is visible on both reads.
- **POST sub-actions.** The stateful flow tries GET, PATCH, PUT and DELETE, and the actions declared with `--actions`. It
  never discovers an action. Otherwise POST is used only to create the test resource.
- **Resources without a known resource id.** A representation with no id the tool recognises (`id`, `orderId`, `order_id`, `resource_id`, `uuid`) cannot be attributed to a resource. The tool reports it as UNDETERMINED rather than guessing; on the matrix this costs 4 vulnerable accesses of recall.
- **Destructive operations.** The only write path is `--stateful`, which needs `--allow-destructive`. `--actions` runs inside
  it and adds no write path of its own.

- The matrix corpus is small and written by hand. Its counts are not detection rates for real APIs.
- The first measurement against a third-party app covers one endpoint family of one deliberately vulnerable API: 12 cross-user pairs, with the secure twin as the negative control. See `docs/measurements/vampi/` for the results and how to reproduce them. In 0.5.0 the second pass reproduced all 12 pairs, with no false positives on either instance.
- On that corpus the tool has no false positives and no false negatives among the clear cases. Four vulnerable accesses
  are undetermined because their representations carry no resource id
  the tool recognises; the tool abstains there instead of guessing.
- Binary responses are not evaluated. As the owner's response the check reports incomplete (exit 3, or NEEDS_INPUT in the matrix). Text is compared as text, with heuristic thresholds: a copy at 0.9 word similarity or more is a leak, and a similar 2xx page at 0.5 or more is undetermined. These thresholds are checked only against the suite's fixtures. A response in another format than the owner's is not compared; it is undetermined only when it is binary or names the resource. Collections are judged only as JSON.
- Resources must be declared or listed. Discovery reads the first page of one listing per identity. It does not enumerate ids and does not probe neighbouring ids.
- `--ownership-fields` is a list of names. Owner fields outside the default list still detect a leak through the
  identical-record rule, but they are not used as ownership evidence.
- The stateful flow writes to the target: it creates resources, patches a field of them, sends any declared POST actions and
  deletes them. It removes
  what it created, and reports anything it could not remove as residue.
- The OpenAPI graph is a heuristic and reads JSON only.
- The version is printed by `--version`, written to the report, and declared in the package metadata.

## Troubleshooting

- **Exit 2 with "nothing to test".** No authorization check is configured. Give two identities with `owns`, `--test-id` with both tokens, or `--stateful` with `--allow-destructive`. `--baseline-ids` and `--fuzz` alone never show authorization.
- **Exit 2 with "refusing to run".** Add `--yes-i-am-authorized`.
- **Exit 2 with "--method ... is not supported".** The baseline, fuzz and matrix checks are read-only. Use `--stateful`.
- **Exit 2 with "--stateful creates, modifies and deletes".** Add `--allow-destructive`, and only on a disposable target.
- **Exit 2 with "--actions sends POST requests inside the stateful flow".** Add `--stateful`, with `--allow-destructive`,
  `--collection-url` and `--identities`.
- **Exit 2 about the actions file** (for example "needs an 'expect' object" or "is not readable JSON"). The whole file is
  checked before any request, so nothing was sent. Fix the named action and re-run.
- **"already shows the result ... No request was sent" (undetermined).** The owner's record had the `expect` values before
  the action. Choose an `expect` value that the new resource does not already have, and re-run.
- **"but the owner's record did not change" (information).** The target accepted the request, but the record does not show
  the `expect` values afterwards. Check that `expect` names a field the record really carries, with the value it takes after
  the action.
- **Exit 2 with "is not in --allow-host".** The URL names a host that `--allow-host` does not list. Nothing was sent. Add the host if you are authorized to test it, or correct the URL.
- **Exit 2 with "is not set (or is empty) in the environment".** An identity refers to `${NAME}` and that variable is missing or empty. Export it in the shell, or in the CI job's environment.
- **Exit 2 with "declares no 'owns' resources".** Each identity that owns something needs an `owns` list, or run with `--discover` to take the ids from each identity's own listing.
- **Exit 2 with "has no params.user_id".** A URL placeholder has no value for that identity. Add `params`.
- **Exit 3 with "could not establish its own resource".** The owner cannot read its own resource: check the token and the
  id. A binary response, or a text page that does not name the resource id, has the same effect.
- **Exit 3 with "create ... did not create a resource".** The create endpoint must return the new id in a JSON body.
- **Exit 4 with "failed: Connection refused".** Nothing is listening at that address.
- **Exit 6.** Open the JSON report, find the `undetermined` entries and read their evidence.
- **Exit 6 with "did not reproduce" in the evidence.** The same request gave a different answer on the second pass, or, for a write, the owner's record no longer showed the change. Look for caching, race conditions, rate limiting or a replica lagging behind the target, then re-run. `--no-recheck` shows the single-response result, but it is not a verdict.

## Roadmap

Not implemented yet, and not claimed anywhere else in this document:

- Neighbour probing of ids under a request budget, and enumeration.
- Evaluating binary responses (PDF, images).
- Testing on Windows and macOS.

## License

MIT. See `LICENSE`.
