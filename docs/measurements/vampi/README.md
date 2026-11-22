# Measurement against VAmPI (0.4.0 and 0.5.0)

This is the first measurement of API Sentinel against an application it was not written for. The target is
[VAmPI](https://github.com/erev0s/VAmPI), an intentionally vulnerable Flask API with a global switch: `vulnerable=1`
(the default) or `vulnerable=0` (ownership checked).

## What was measured, and what was not

- **Corpus:** one endpoint family, `GET /books/v1/{book_title}`, three users with two books each, so 12 cross-user
  pairs per instance. The vulnerable instance leaks every cross-user read. The secure instance returns 404 for them.
- **Ground truth** was checked by hand with curl before any run (bob reads alice's book: 200 on vulnerable, 404 on secure).
- **Not measured:** the other VAmPI endpoints, and every other API. 12 pairs is a small sample. These numbers are not a
  detection rate for real APIs. Writes (PUT, PATCH, DELETE) were not part of this corpus.
- **Setup changes:** VAmPI pins SQLAlchemy 2.0.2, which does not import on Python 3.13. SQLAlchemy was upgraded to 2.0.58
  and the rest of the pins were kept. The secure copy was moved to port 5001, because the app hard-codes port 5000.

## Results

Each run: 12 pairs per instance. TP = confirmed where the truth is "leak". FP = confirmed on the secure instance.

| Run | Options | Vulnerable: TP | Vulnerable: undetermined | Secure: FP |
|---|---|---|---|---|
| 0.3.0, owner field named | `--ownership-fields owner,user,user_id` | 12 / 12 | 0 | 0 |
| 0.3.0, nothing named | (default fields) | 0 / 12 | 12 | 0 |
| 0.3.0, discovery | `--discover --collection-url .../books/v1` | 0 / 12 | 0 | 0 |
| 0.4.0, id field | `--id-field book_title` | 12 / 12 | 0 | 0 |
| 0.4.0, discovery + id field | `--discover --id-field book_title`, owner values | 12 / 12 | 0 | 0 |
| 0.5.0, id field (second pass on) | `--id-field book_title` | 12 / 12 | 0 | 0 |
| 0.5.0, id field, `--no-recheck` | `--id-field book_title --no-recheck` | 12 / 12 | 0 | 0 |
| 0.5.0, discovery + id field (second pass on) | `--discover --id-field book_title`, owner values | 12 / 12 | 0 | 0 |
| 0.5.0, nothing named (second pass on) | (default fields) | 0 / 12 | 12 | 0 |

What the rows show:

- **Without the owner field name, the tool does not call the bug.** It reports 12 undetermined results, which is the
  designed behaviour. The cost is that the user has to know the field name.
- **Discovery was blind in 0.3.0.** VAmPI's items have no `id` field, so no ids were listed. 0.4.0 adds `--id-field`,
  and discovery then attributes all six books, using the declared owner values.
- **Evidence strength differs.** Without an owner field, the 0.4.0 result comes from the identical-copy rule: *high*
  severity, *medium* confidence. With owner evidence it is *critical*, and still *medium* when the ownership was inferred
  from a listing.

What the 0.5.0 rows add:

- **The second pass confirmed every pair again.** Each of the 12 vulnerable pairs was reproduced on the second pass, so
  none was downgraded. VAmPI gave the same answer to every request in these runs, so this run shows no change. It does
  not test the case the second pass exists for (an answer that changes between requests). That case is covered by `tests/test_recheck.py`.
- **Cost.** On the vulnerable instance the second pass repeats the matrix: 36 requests instead of 18 for the id-field
  run, and 39 instead of 21 with discovery. On the secure instance nothing needs confirming, so no second pass runs:
  18 requests, the same as 0.4.0.
- **Owner field not named, 0.5.0:** still 12 undetermined. The second pass does not change a judgement the tool cannot make.

## Reproduce

```bash
git clone https://github.com/erev0s/VAmPI.git vampi-vuln && cp -r vampi-vuln vampi-secure
# vampi-vuln: python3 app.py                       (port 5000, vulnerable=1)
# vampi-secure: change port=5000 to port=5001 in app.py, then: vulnerable=0 python3 app.py
python3 seed_vampi.py http://127.0.0.1:5000 vuln     # writes identities-vuln.json and identities-disc-vuln.json
python3 seed_vampi.py http://127.0.0.1:5001 secure
python3 ../../../api_sentinel.py --yes-i-am-authorized --url "http://127.0.0.1:5000/books/v1/{id}" \
  --identities identities-vuln.json --id-field book_title --output run.json
python3 score_vampi.py run.json vuln
```
