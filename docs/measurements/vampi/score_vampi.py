"""Score one run against ground truth. Truth: vuln instance -> every cross-user read is a leak; secure -> none.
Pairs are (owner, accessor, book). Confirmed = category 'confirmed'. Undetermined is counted separately."""
import json, sys
report, side = sys.argv[1], sys.argv[2]
r = json.load(open(report))
owners = {"alice": ["alice-book", "alice-book-2"], "bob": ["bob-book", "bob-book-2"], "carol": ["carol-book", "carol-book-2"]}
book_owner = {t: o for o, ts in owners.items() for t in ts}
pairs = [(book_owner[t], a, t) for t in book_owner for a in owners if a != book_owner[t]]
truth = {p: side == "vuln" for p in pairs}
found, undet = set(), set()
for f in r["findings"]:
    d = f.get("details") or {}
    if not d.get("owner_identity"): continue
    key = (d["owner_identity"], d["accessing_identity"], str(d["resource_id"]))
    if f["category"] == "confirmed": found.add(key)
    if f["category"] == "undetermined": undet.add(key)
tp = sum(1 for p in pairs if truth[p] and p in found)
fn = sum(1 for p in pairs if truth[p] and p not in found)
fp = sum(1 for p in found if p in truth and not truth[p])
other = sum(1 for p in found if p not in truth)
print(f"  pairs={len(pairs)}  TP={tp}  FN={fn}  FP={fp}  (confirmed on pairs outside truth: {other})  undetermined={len(undet)}  exit-related summary={r['summary']}")
