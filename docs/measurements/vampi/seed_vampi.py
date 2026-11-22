import json, sys, urllib.request
def call(base, method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None
base, side = sys.argv[1], sys.argv[2]
call(base, "GET", "/createdb")
books = {"alice": ["alice-book", "alice-book-2"], "bob": ["bob-book", "bob-book-2"], "carol": ["carol-book", "carol-book-2"]}
tokens = {}
for name, titles in books.items():
    call(base, "POST", "/users/v1/register", {"username": name, "password": "pw-" + name, "email": f"{name}@example.com"})
    tokens[name] = call(base, "POST", "/users/v1/login", {"username": name, "password": "pw-" + name})[1]["auth_token"]
    for t in titles:
        st, _ = call(base, "POST", "/books/v1", {"book_title": t, "secret": f"secret-of-{t}"}, tokens[name])
        assert st == 200, (name, t, st)
hdr = lambda n: {"Authorization": f"Bearer {tokens[n]}"}
json.dump({"identities": [{"name": n, "headers": hdr(n), "owns": books[n]} for n in books]},
          open(f"identities-{side}.json", "w"), indent=2)
json.dump({"identities": [{"name": n, "headers": hdr(n), "owner_values": {"user": n}} for n in books]},
          open(f"identities-disc-{side}.json", "w"), indent=2)
print("seeded", side, sum(len(v) for v in books.values()), "books")
