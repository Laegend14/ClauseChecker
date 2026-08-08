# Deploying ClauseCheck

ClauseCheck is a standalone contract with no constructor arguments, no external
dependencies, and no frontend. Deployment is a single file upload.

**No private key is needed to verify this contract.** The entire test suite runs in
gltest's Direct Mode, which mocks the LLM and web layers — no node, no keys, no network,
no tokens. Deploy from your own Studio account when you want to exercise it against real
validators.

---

## Before deploying

Confirm the contract is clean locally:

```bash
genvm-lint check contracts/ClauseCheck.py
```

```bash
python -m pytest tests/ -q
```

Optionally, confirm the consensus guards are actually load-bearing:

```bash
python tools/mutation_test.py
```

---

## Runner version

Line 1 of the contract pins the SDK runner:

```python
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
```

This is the docs-canonical hash and is the version to deploy. `genvm-lint` may print an
informational note that a newer runner exists — that note is safe to ignore. Studio pins
its own runner versions, and this hash is the one guaranteed to resolve there. Only
change it if your Studio instance rejects it.

---

## Deploy in GenLayer Studio

1. Open Studio and create a new contract.
2. Paste the full contents of [`contracts/ClauseCheck.py`](contracts/ClauseCheck.py).
3. Deploy. The constructor takes **no arguments** — `__init__` only initializes empty
   storage.
4. Note the deployed address.

---

## Smoke test after deploying

This sequence exercises the deterministic path, the consensus path, and the read
surface. It takes about five calls.

### 1. Create and populate a policy

`create_policy`

| arg | value |
|---|---|
| `policy_id` | `grant-milestone` |
| `title` | `Grant Milestone Review` |
| `max_major_failures` | `0` |

`add_clause` — call four times:

| `clause_id` | `kind` | `severity` | `text` | `predicate` |
|---|---|---|---|---|
| `deliverable-shipped` | `INTERPRETIVE` | `FATAL` | The report must state that the milestone deliverable was completed and shipped. | *(empty)* |
| `budget-disclosed` | `INTERPRETIVE` | `MAJOR` | The report must disclose how the grant funds were spent. | *(empty)* |
| `no-unapproved-scope-change` | `INTERPRETIVE` | `MAJOR` | The report must not describe changes to the agreed scope that were made without prior approval. | *(empty)* |
| `length-cap` | `MECHANICAL` | `ADVISORY` | The report must be at most 400 words. | `max_words:400` |

`seal_policy` with `policy_id = grant-milestone`.

Sealing is required — `submit` rejects unsealed policies. After sealing, `add_clause`
will fail; that is the point. Use `fork_policy` to amend.

### 2. Submit a subject

`submit`

| arg | value |
|---|---|
| `policy_id` | `grant-milestone` |
| `subject` | the report text below |
| `source_uri` | `https://example.org/report` (recorded only, never fetched) |

```
Milestone 2 Report — Ledger Reconciliation Service

We completed and shipped the reconciliation service to production on March 14.
The service now processes roughly 40,000 statements per day.

Budget: of the 50,000 GEN tranche, 38,000 GEN went to two contract engineers,
7,500 GEN to infrastructure, and 4,500 GEN remains unspent and is carried forward.

We also replaced the originally agreed Postgres backend with ClickHouse without
raising it with the grants committee first.

Repository: https://example.org/ledger-recon
```

`submit` returns the `case_id`.

### 3. Adjudicate

Call `adjudicate` with that `case_id`. This is the consensus call — it runs the
interpretive clauses through `run_nondet_unsafe` and takes longer than the others while
validators re-derive their own verdict vectors.

### 4. Read the result

`get_outcome(case_id)` should return **`REJECTED`**.

The report discloses an unapproved scope change, `no-unapproved-scope-change` is `MAJOR`,
and `max_major_failures` is `0` — so one major failure exceeds the allowance. The
rejection is computed by `_aggregate` in contract code, not decided by a model.

`get_ruling(case_id)` returns the full verdict vector. Expect roughly:

| clause | verdict | evidence |
|---|---|---|
| `deliverable-shipped` | `PASS` | *(empty — `PASS` needs no citation)* |
| `budget-disclosed` | `PASS` | *(empty)* |
| `no-unapproved-scope-change` | `FAIL` | a verbatim span containing *"replaced the originally agreed Postgres backend with ClickHouse without"* |
| `length-cap` | `PASS` | *(empty — mechanical, evaluated in pure Python)* |

**The evidence field is the thing to look at.** That quote was checked character-for-
character against the stored subject by both the leader and every validator. If a model
had invented it, `_apply_grounding` would have downgraded the verdict to `UNCLEAR` and
the outcome would read `NEEDS_REVIEW` instead.

### 5. Optional — confirm the clean path

Submit a second case with the scope-change paragraph deleted, adjudicate, and confirm
`get_outcome` returns `APPROVED`.

---

## What to expect on the consensus call

- `adjudicate` is the only method that invokes an LLM. Everything else is deterministic
  and finalizes at normal speed.
- Validators run the same prompt independently, so the call costs one model invocation
  per participating node.
- If validators disagree — for instance because the model is genuinely uncertain on a
  borderline clause — the transaction is retried with a different leader. Up to
  `MAX_ATTEMPTS = 3` adjudications are permitted per case.
- A vague policy will produce `NEEDS_REVIEW` rather than a confident answer. That is
  correct behavior, not a failure: the contract surfaces ambiguity instead of guessing.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `[EXPECTED] policy is not sealed` on `submit` | Call `seal_policy` first. |
| `[EXPECTED] policy is sealed` on `add_clause` | Sealed policies are immutable — use `fork_policy`. |
| `[EXPECTED] only the policy owner may do this` | Policy mutations are restricted to the creating address. |
| `[LLM_ERROR] model returned no decidable verdicts` | The model returned nothing usable. Validators disagree by design, forcing a retry. |
| Outcome is `NEEDS_REVIEW` unexpectedly | A blocking clause came back `UNCLEAR`. Check `get_ruling` — usually the clause wording is ambiguous or the subject genuinely doesn't address it. |
| `[EXPECTED] max adjudication attempts reached` | Three attempts used. Escalate to human review. |
| Deploy rejected on the `Depends` line | Your Studio runner differs; update the hash to the one your instance reports. |
