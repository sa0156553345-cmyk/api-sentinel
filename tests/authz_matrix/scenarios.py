"""Authorization scenarios: 26 scenarios, 59 cases.

Oracle labels and gap annotations are PREDICTIONS written before the first run for this version. Labels describe the
truth about each fixture and are checked independently (harness.verify_access). A gap annotation predicts a deviation;
tests/test_matrix.py reports every place where the measured behaviour disagrees with it.

Access(owner, accessor): the accessor tries to read or change a resource owned by ``owner``.
"""
from __future__ import annotations

from .fixtures import (CollectionApp, DownloadApp, DropNonOwner, FilterApp, NestedApp, OrdersApp,
                       PostsApp, ProfileApp, ReprApp, make_order)
from .harness import INDET, POLICY, SECURE, VULNERABLE, Access, Case, IdSpec

GAPS = {
    "G01": "RESOLVED. Stateful writes are judged by the owner's own re-read, not by the status code. A 2xx without an effect is not a finding (stateful-no-effect).",
    "G02": "PARTIALLY RESOLVED. A write whose effect is applied is detected even when it answers 403 or 202 at once. A 202 whose effect is not visible at the re-read is UNDETERMINED. The later-effect path has unit tests only, no matrix fixture.",
    "G03": "OPEN. The stateful flow exercises GET, PATCH and DELETE only; PUT (and POST sub-actions such as /cancel) are never tried.",
    "G04": "OPEN. Matrix mode recognises a leak from a short fixed list of id keys, or from a body identical to the owner's. A non-JSON response cannot be evaluated: the check is incomplete (NEEDS_INPUT), never a pass. A partial view is UNDETERMINED.",
    "G05": "RESOLVED. A schema match, or an id inside a stub, is no longer evidence. A finding needs the requested id in the body and corroboration with the owner's own record.",
    "G06": "RESOLVED, with one consequence. Ownership fields are compared with the owner's record, not merely checked for presence. An empty ownership field in the owner's record means ownership cannot be established: UNDETERMINED.",
    "G07": "RESOLVED. A URL template can carry identity parameters such as {user_id}; the accessor's own parent is substituted, so a caller-specific parent path is tested. A parameter with no value for an identity is a configuration error (exit 2).",
    "G08": "OPEN. The identity model has no role, scope, sharing or public concept. Intended access is reported as a finding and lands in UNDECIDABLE_FLAGGED, because the tool cannot tell policy from BOLA.",
    "G09": "OPEN. Distinct principals are not verified: two tokens of one account are treated as two identities and can produce findings.",
    "G10": "RESOLVED. The matrix is read-only: a non-GET method is refused before any request is sent (exit 2). Writes are possible only through the opt-in stateful flow.",
    "G11": "RESOLVED. Missing input fails closed: no 'owns' or an invalid configuration exits 2 with a message, and a failed setup exits 3. Such cases are NEEDS_INPUT, never silent passes.",
    "G12": "RESOLVED. A transport failure (refused, reset, timeout) exits 4 with one message and no traceback. The check is UNREACHABLE: NEEDS_INPUT, never a pass.",
    "G13": "RESOLVED. Every stateful check creates its own resource and removes it afterwards, so no check depends on an earlier destructive effect.",
    "G15": "OPEN. A create response without a body id (for example 201 with only a Location header) cannot set up the stateful flow. It exits 3 (SETUP_FAILED): never a silent pass.",
    "G16": "OPEN. A bare representation (no resource id and no owner field) cannot be attributed to a resource. The tool abstains (UNDETERMINED) rather than guessing, which costs recall on such APIs.",
}

ORDER_URL = "{base}/orders/{id}"
COLL_URL = "{base}/orders"

ALICE = IdSpec("alice", "alice-token", ("1001",))
BOB = IdSpec("bob", "bob-token", ("2001",))
CAROL = IdSpec("carol", "carol-token", ("3001",))
ADMIN = IdSpec("admin", "admin-token", ())


def bare(*ids):
    """Identities without seeded resources (stateful flows create their own)."""
    return [IdSpec(i.name, i.token, ()) for i in ids]


def perms(names):
    return [(o, a) for o in names for a in names if o != a]


AB = perms(("alice", "bob"))
ABC = perms(("alice", "bob", "carol"))


def reads(pairs, label, **kw):
    return [Access(o, a, "GET", label, **kw) for o, a in pairs]


WHY_ADMIN = "An admin override may be intended; the identities file cannot say 'admin may read everything', so the tool cannot tell policy from BOLA."
WHY_SHARE = "Order 1001 is explicitly shared with bob in the fixture; the tool has no way to be told about sharing."
WHY_PUBLIC = "Public posts are readable by every account by design; the tool has no notion of public resources."
WHY_SAME = "Both identities authenticate as the same account (user 42); the tool cannot know two tokens are one principal."
WHY_OWNERLESS = "Resource 9001 has user_id=null: there is no owner to violate, and nothing says whether it should have one."
WHY_NOID = "The body has no resource id and no owner field, and it is identical for everyone. A template or catch-all response would look the same, so the tool cannot tell which record it is."
WHY_MISMATCH = "The identities file declares that user 42 owns order 1001, but the record says user 7. Either the declaration or the data is wrong, and the tool cannot tell which."
WHY_PARTIAL = "The non-owner receives only a status value. Whether that is a security problem depends on how sensitive the status is, which the API model does not say."

CASES: list[Case] = []

# S01 basic owner / non-owner (matrix)
CASES += [
    Case("S01-vuln", "S01", "Basic owner/non-owner read", "vulnerable", "matrix",
         lambda: OrdersApp({"GET": "allow"}), [ALICE, BOB], ORDER_URL, reads(AB, VULNERABLE)),
    Case("S01-secure", "S01", "Basic owner/non-owner read", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}), [ALICE, BOB], ORDER_URL, reads(AB, SECURE)),
    Case("S01-secure-404", "S01", "Basic read, 404 hides existence", "secure", "matrix",
         lambda: OrdersApp({"GET": "hide"}), [ALICE, BOB], ORDER_URL, reads(AB, SECURE)),
]

# S02 same-role users
CASES += [
    Case("S02-matrix-vuln", "S02", "Three same-role customers", "vulnerable", "matrix",
         lambda: OrdersApp({"GET": "allow"}), [ALICE, BOB, CAROL], ORDER_URL, reads(ABC, VULNERABLE)),
    Case("S02-matrix-secure", "S02", "Three same-role customers", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}), [ALICE, BOB, CAROL], ORDER_URL, reads(ABC, SECURE)),
    Case("S02-stateful-vuln", "S02", "Three customers, stateful flow", "vulnerable", "stateful",
         lambda: OrdersApp({"GET": "allow", "PATCH": "allow", "DELETE": "allow"}),
         bare(ALICE, BOB, CAROL), ORDER_URL,
         [Access("alice", acc, v, VULNERABLE)
          for acc in ("bob", "carol") for v in ("GET", "PATCH", "DELETE")],
         collection_url=COLL_URL),
]


# S03 verb differences (stateful) + matrix with a mutating verb
def verb_case(cid, variant, vuln_verbs):
    modes = {v: ("allow" if v in vuln_verbs else "deny") for v in ("GET", "PATCH", "DELETE")}
    return Case(cid, "S03", f"Verb differences: vulnerable verbs = {sorted(vuln_verbs) or 'none'}", variant,
                "stateful", lambda m=modes: OrdersApp(m), bare(ALICE, BOB), ORDER_URL,
                [Access("alice", "bob", v, VULNERABLE if v in vuln_verbs else SECURE) for v in ("GET", "PATCH", "DELETE")],
                collection_url=COLL_URL)


CASES += [
    verb_case("S03-all-vuln", "vulnerable", {"GET", "PATCH", "DELETE"}),
    verb_case("S03-get-only", "partial", {"GET"}),
    verb_case("S03-patch-only", "partial", {"PATCH"}),
    verb_case("S03-delete-only", "partial", {"DELETE"}),
    verb_case("S03-all-secure", "secure", set()),
    Case("S03-matrix-delete", "S03", "Matrix mode run with --method DELETE", "vulnerable", "matrix",
         lambda: OrdersApp({"DELETE": "allow"}), [ALICE, BOB], ORDER_URL,
         [Access("alice", "bob", "DELETE", VULNERABLE, gap="G10"), Access("bob", "alice", "DELETE", VULNERABLE, gap="G10")],
         method="DELETE"),
]

# S04 PUT-only update
CASES += [
    Case("S04-put-vuln", "S04", "Update only via PUT (PATCH unsupported)", "vulnerable", "stateful",
         lambda: OrdersApp({"GET": "deny", "PATCH": "unsupported", "PUT": "allow", "DELETE": "deny"}),
         bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", "GET", SECURE), Access("alice", "bob", "PATCH", SECURE),
          Access("alice", "bob", "PUT", VULNERABLE, gap="G03"), Access("alice", "bob", "DELETE", SECURE)],
         collection_url=COLL_URL),
    Case("S04-put-secure", "S04", "Update only via PUT (PATCH unsupported)", "secure", "stateful",
         lambda: OrdersApp({"GET": "deny", "PATCH": "unsupported", "PUT": "deny", "DELETE": "deny"}),
         bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", v, SECURE) for v in ("GET", "PATCH", "PUT", "DELETE")],
         collection_url=COLL_URL),
]

# S05 async 202 on mutation
CASES += [
    Case("S05-async-vuln", "S05", "Mutations answered 202 Accepted", "vulnerable", "stateful",
         lambda: OrdersApp({"GET": "deny", "PATCH": "async", "DELETE": "async"}), bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", "GET", SECURE), Access("alice", "bob", "PATCH", VULNERABLE),
          Access("alice", "bob", "DELETE", VULNERABLE)], collection_url=COLL_URL),
    Case("S05-async-secure", "S05", "Mutations answered 202 Accepted", "secure", "stateful",
         lambda: OrdersApp({"GET": "deny", "PATCH": "deny", "DELETE": "deny"}), bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", v, SECURE) for v in ("GET", "PATCH", "DELETE")], collection_url=COLL_URL),
]

# S06 silent no-op success
CASES += [
    Case("S06-noop", "S06", "Non-owner mutations silently do nothing but answer 200/204", "secure", "stateful",
         lambda: OrdersApp({"GET": "hide", "PATCH": "noop", "DELETE": "noop"}), bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", "GET", SECURE), Access("alice", "bob", "PATCH", SECURE),
          Access("alice", "bob", "DELETE", SECURE)], collection_url=COLL_URL),
]

# S07 blind write: 403 but applied
CASES += [
    Case("S07-blind", "S07", "PATCH answers 403 but the write is applied", "vulnerable", "stateful",
         lambda: OrdersApp({"GET": "deny", "PATCH": "blind", "DELETE": "deny"}), bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", "GET", SECURE), Access("alice", "bob", "PATCH", VULNERABLE),
          Access("alice", "bob", "DELETE", SECURE)], collection_url=COLL_URL),
]

# S08 soft-deny with HTTP 200
CASES += [
    Case("S08-soft-error-stateful", "S08", "200 + error envelope on denial (stateful)", "secure", "stateful",
         lambda: OrdersApp({"GET": "soft_error", "PATCH": "soft_error", "DELETE": "soft_error"}),
         bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", v, SECURE) for v in ("GET", "PATCH", "DELETE")], collection_url=COLL_URL),
    Case("S08-soft-error-matrix", "S08", "200 + error envelope on denial (matrix)", "secure", "matrix",
         lambda: OrdersApp({"GET": "soft_error"}), [ALICE, BOB], ORDER_URL, reads(AB, SECURE)),
    Case("S08-stub-matrix", "S08", "200 + restricted stub carrying only the id", "secure", "matrix",
         lambda: OrdersApp({"GET": "stub"}), [ALICE, BOB], ORDER_URL, reads(AB, SECURE)),
]

# S09 ownership-field / id-key naming and representation (vulnerable only: they always leak)
for _kind, _gap in [("created_by", ""), ("ownerId", ""), ("nested_owner", ""), ("envelope", ""),
                    ("bare", "G16"), ("ref_full", ""), ("ref_partial", "G04")]:
    _markers = {"alice": b"alice@example.com", "bob": b"bob@example.com"} if _kind == "ref_partial" else {}
    CASES.append(Case(
        f"S09-{_kind}", "S09", f"Leak with representation '{_kind}'", "vulnerable", "matrix",
        (lambda k=_kind: ReprApp(k)), [ALICE, BOB], ORDER_URL,
        [Access(o, a, "GET", VULNERABLE, gap=_gap, leak_marker=_markers.get(o)) for o, a in AB]))

# S10 non-JSON representations (always leak)
CASES += [
    Case("S10-pdf", "S10", "Invoice download as application/pdf", "vulnerable", "matrix",
         lambda: DownloadApp("pdf"), [ALICE, BOB], "{base}/invoices/{id}", reads(AB, VULNERABLE, gap="G04")),
    Case("S10-json-as-text", "S10", "JSON served as text/plain", "vulnerable", "matrix",
         lambda: DownloadApp("json_as_text"), [ALICE, BOB], "{base}/invoices/{id}", reads(AB, VULNERABLE, gap="G04")),
]

# S11 nested resources
_UA, _UB = IdSpec("alice", "alice-token", ("42",)), IdSpec("bob", "bob-token", ("91",))
# parent-parameterised identities: the caller's own parent id is substituted into /users/{user_id}/orders/{id}
_CA = IdSpec("alice", "alice-token", ("1001",), params=(("user_id", "42"),))
_CB = IdSpec("bob", "bob-token", ("2001",), params=(("user_id", "91"),))
CASES += [
    Case("S11-list-vuln", "S11", "/users/{id}/orders, no caller check", "vulnerable", "matrix",
         lambda: NestedApp("list_vuln"), [_UA, _UB], "{base}/users/{id}/orders", reads(AB, VULNERABLE)),
    Case("S11-list-secure", "S11", "/users/{id}/orders, caller must be {id}", "secure", "matrix",
         lambda: NestedApp("list_secure"), [_UA, _UB], "{base}/users/{id}/orders", reads(AB, SECURE)),
    Case("S11-child-vuln", "S11", "/users/{uid}/orders/{oid}: order's owner never checked", "vulnerable", "matrix",
         lambda: NestedApp("child_vuln"), [_CA, _CB], "{base}/users/{user_id}/orders/{id}",
         [Access("alice", "bob", "GET", VULNERABLE,
                 owner_url="{base}/users/42/orders/{id}", accessor_url="{base}/users/91/orders/{id}"),
          Access("bob", "alice", "GET", VULNERABLE,
                 owner_url="{base}/users/91/orders/{id}", accessor_url="{base}/users/42/orders/{id}")]),
    Case("S11-child-secure", "S11", "/users/{uid}/orders/{oid}: order's owner checked", "secure", "matrix",
         lambda: NestedApp("child_secure"), [_CA, _CB], "{base}/users/{user_id}/orders/{id}",
         [Access("alice", "bob", "GET", SECURE,
                 owner_url="{base}/users/42/orders/{id}", accessor_url="{base}/users/91/orders/{id}"),
          Access("bob", "alice", "GET", SECURE,
                 owner_url="{base}/users/91/orders/{id}", accessor_url="{base}/users/42/orders/{id}")]),
]

# S12 collection endpoint (template has no {id}; each user's list has the same shape)
CASES += [
    Case("S12-scoped-secure", "S12", "GET /orders returns only the caller's orders", "secure", "matrix",
         lambda: CollectionApp("scoped"), [ALICE, BOB], "{base}/orders", reads(AB, SECURE)),
    Case("S12-leaky-vuln", "S12", "GET /orders returns everybody's orders", "vulnerable", "matrix",
         lambda: CollectionApp("leaky"), [ALICE, BOB], "{base}/orders", reads(AB, VULNERABLE)),
]

# S13 filter parameter / endpoints that ignore the id
_FA, _FB = IdSpec("alice", "alice-token", ("42",)), IdSpec("bob", "bob-token", ("91",))
CASES += [
    Case("S13-filter-honor-vuln", "S13", "?customer_id= honoured for any caller", "vulnerable", "matrix",
         lambda: FilterApp("honor"), [_FA, _FB], "{base}/orders?customer_id={id}", reads(AB, VULNERABLE)),
    Case("S13-filter-ignore-secure", "S13", "?customer_id= ignored, caller's own list returned", "secure", "matrix",
         lambda: FilterApp("ignore"), [_FA, _FB], "{base}/orders?customer_id={id}", reads(AB, SECURE)),
    Case("S13-filter-deny-secure", "S13", "?customer_id= must equal the caller", "secure", "matrix",
         lambda: FilterApp("deny"), [_FA, _FB], "{base}/orders?customer_id={id}", reads(AB, SECURE)),
    Case("S13-profile-honor-vuln", "S13", "/profile/{id} honoured for any caller", "vulnerable", "matrix",
         lambda: ProfileApp("honor"), [_FA, _FB], "{base}/profile/{id}", reads(AB, VULNERABLE)),
    Case("S13-profile-ignore-secure", "S13", "/profile/{id} ignores id, returns caller's profile", "secure", "matrix",
         lambda: ProfileApp("ignore"), [_FA, _FB], "{base}/profile/{id}", reads(AB, SECURE)),
]

# S14 admin
CASES += [
    Case("S14-admin-secure", "S14", "Admin may read everything; users may not read each other", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}, admin_override=True), [ALICE, BOB, ADMIN], ORDER_URL,
         reads([("alice", "bob"), ("bob", "alice")], SECURE)
         + reads([("alice", "admin"), ("bob", "admin")], POLICY, why=WHY_ADMIN, gap="G08")),
    Case("S14-admin-vuln", "S14", "Users may read each other AND admin may read everything", "vulnerable", "matrix",
         lambda: OrdersApp({"GET": "allow"}, admin_override=True), [ALICE, BOB, ADMIN], ORDER_URL,
         reads([("alice", "bob"), ("bob", "alice")], VULNERABLE)
         + reads([("alice", "admin"), ("bob", "admin")], POLICY, why=WHY_ADMIN, gap="G08")),
]

# S15 intentional sharing
_NOT_SHARED = [p for p in ABC if p != ("alice", "bob")]
CASES += [
    Case("S15-share-secure", "S15", "Alice shared order 1001 with bob", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}, shares={1001: [91]}), [ALICE, BOB, CAROL], ORDER_URL,
         [Access("alice", "bob", "GET", POLICY, why=WHY_SHARE, gap="G08")] + reads(_NOT_SHARED, SECURE)),
    Case("S15-share-vuln", "S15", "Share exists, but everybody can read everything", "vulnerable", "matrix",
         lambda: OrdersApp({"GET": "allow"}, shares={1001: [91]}), [ALICE, BOB, CAROL], ORDER_URL,
         [Access("alice", "bob", "GET", POLICY, why=WHY_SHARE, gap="G08")] + reads(_NOT_SHARED, VULNERABLE)),
]

# S16 public resources
CASES += [
    Case("S16-public", "S16", "Public posts are readable by design; carol's draft is private", "secure", "matrix",
         lambda: PostsApp(), [ALICE, BOB, CAROL], "{base}/posts/{id}",
         reads([("alice", "bob"), ("alice", "carol"), ("bob", "alice"), ("bob", "carol")], POLICY,
               why=WHY_PUBLIC, gap="G08")
         + reads([("carol", "alice"), ("carol", "bob")], SECURE)),
]

# S17 ambiguous ownership
_AW = IdSpec("alice-web", "alice-token", ("1001",))
_AM = IdSpec("alice-mobile", "alice-mobile-token", ("1002",))
CASES += [
    Case("S17-same-principal", "S17", "Two sessions of the same account configured as two identities", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}, orders={1001: make_order(1001, 42), 1002: make_order(1002, 42, "Mouse", 19.5)}),
         [_AW, _AM], ORDER_URL,
         [Access("alice-web", "alice-mobile", "GET", INDET, why=WHY_SAME, gap="G09"),
          Access("alice-mobile", "alice-web", "GET", INDET, why=WHY_SAME, gap="G09")]),
    Case("S17-ownerless", "S17", "Resource with user_id=null readable by everybody", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}, orders={9001: make_order(9001, None, "Guest order", 5.0)}, ownerless_open=True),
         [IdSpec("alice", "alice-token", ("9001",)), IdSpec("bob", "bob-token", ())], ORDER_URL,
         [Access("alice", "bob", "GET", INDET, why=WHY_OWNERLESS, gap="G06")]),
]

# S18-S20: end-to-end CLI behaviour (exit codes, warnings, reports)
CASES += [
    Case("S18-cli-no-owns", "S18", "Identities file without 'owns' (missing ownership input)", "vulnerable", "cli",
         lambda: OrdersApp({"GET": "allow"}), [ALICE, BOB], ORDER_URL,
         [Access(o, a, "GET", VULNERABLE, gap="G11") for o, a in AB], probe_mode="matrix", use_owns=False),
    Case("S19-cli-setup-fails", "S19", "Create answers 201 + Location header, empty body", "vulnerable", "cli",
         lambda: OrdersApp({"GET": "allow", "PATCH": "allow", "DELETE": "allow"}, create_responds="location"),
         bare(ALICE, BOB), ORDER_URL,
         [Access("alice", "bob", v, VULNERABLE, gap="G15") for v in ("GET", "PATCH", "DELETE")],
         collection_url=COLL_URL, probe_mode="stateful", use_owns=False),
    Case("S20-cli-connection-reset", "S20", "Gateway resets the connection for non-owners", "secure", "cli",
         lambda: DropNonOwner(), [ALICE, BOB], ORDER_URL,
         [Access(o, a, "GET", SECURE, gap="G12") for o, a in AB], probe_mode="matrix"),
]

# S21 non-200 response that still carries the owner's record (ported from the parallel matrix)
CASES += [
    Case("S21-deny-body-vuln", "S21", "403 response carries the full order", "vulnerable", "matrix",
         lambda: OrdersApp({"GET": "deny_leak"}), [ALICE, BOB], ORDER_URL, reads(AB, VULNERABLE)),
    Case("S21-deny-body-secure", "S21", "403 response carries no order data", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}), [ALICE, BOB], ORDER_URL, reads(AB, SECURE)),
]

# S22 body without a resource id or owner field, identical for everyone (missing ownership information)
CASES += [
    Case("S22-no-id-body", "S22", "Body has no id and no owner field; identical for everyone", "indeterminate", "matrix",
         lambda: OrdersApp({"GET": "allow"}, view="no_id"), [ALICE, BOB], ORDER_URL,
         [Access("alice", "bob", "GET", INDET, why=WHY_NOID)]),
]

# S23 declared owner contradicts the record (ambiguous ownership)
_ALICE_DECLARED = IdSpec("alice", "alice-token", ("1001",), owner_values=(("user_id", 42),))
CASES += [
    Case("S23-owner-mismatch", "S23", "Declared owner (user 42) contradicts the record (user 7)", "indeterminate", "matrix",
         lambda: OrdersApp({"GET": "allow"}, orders={1001: make_order(1001, 7)}), [_ALICE_DECLARED, BOB], ORDER_URL,
         [Access("alice", "bob", "GET", INDET, why=WHY_MISMATCH)]),
]

# S24 non-owner gets a status-only view (partial disclosure)
CASES += [
    Case("S24-partial-status", "S24", "Non-owner gets a status-only view; owner gets the full record", "indeterminate",
         "matrix", lambda: OrdersApp({"GET": "partial_status"}), [ALICE, BOB], ORDER_URL,
         [Access("alice", "bob", "GET", INDET, why=WHY_PARTIAL, leak_marker=b'"shipped"')]),
]

# S25 owner stored under a field name the tool does not know (not a default owner field)
CASES += [
    Case("S25-holder-vuln", "S25", "Owner stored as 'holder' (not a default owner field); everyone may read", "vulnerable",
         "matrix", lambda: OrdersApp({"GET": "allow"}, view="holder"), [ALICE, BOB], ORDER_URL, reads(AB, VULNERABLE)),
    Case("S25-holder-secure", "S25", "Owner stored as 'holder'; non-owners are denied", "secure", "matrix",
         lambda: OrdersApp({"GET": "deny"}, view="holder"), [ALICE, BOB], ORDER_URL, reads(AB, SECURE)),
]

# S26 placeholder with the same keys and types as a real record (a schema match that is not a resource)
CASES += [
    Case("S26-placeholder-same-schema", "S26", "Non-owner gets a placeholder with the same keys and types", "secure",
         "matrix", lambda: OrdersApp({"GET": "placeholder"}), [ALICE, BOB], ORDER_URL, reads(AB, SECURE)),
]

# (pair name, vulnerable case id, secure case id)
PAIRS = [
    ("S01 owner/non-owner", "S01-vuln", "S01-secure"),
    ("S02 same-role (matrix)", "S02-matrix-vuln", "S02-matrix-secure"),
    ("S03 verbs (stateful)", "S03-all-vuln", "S03-all-secure"),
    ("S04 PUT-only update", "S04-put-vuln", "S04-put-secure"),
    ("S05 async 202", "S05-async-vuln", "S05-async-secure"),
    ("S11 nested list", "S11-list-vuln", "S11-list-secure"),
    ("S11 nested child", "S11-child-vuln", "S11-child-secure"),
    ("S12 collection", "S12-leaky-vuln", "S12-scoped-secure"),
    ("S13 filter vs ignore", "S13-filter-honor-vuln", "S13-filter-ignore-secure"),
    ("S13 filter vs deny", "S13-filter-honor-vuln", "S13-filter-deny-secure"),
    ("S13 profile", "S13-profile-honor-vuln", "S13-profile-ignore-secure"),
    ("S14 admin", "S14-admin-vuln", "S14-admin-secure"),
    ("S15 sharing", "S15-share-vuln", "S15-share-secure"),
    ("S21 403 with record", "S21-deny-body-vuln", "S21-deny-body-secure"),
    ("S25 holder field", "S25-holder-vuln", "S25-holder-secure"),
]
