# Consensus design

This document explains how ClauseCheck uses GenLayer's Optimistic Democracy, what its
validator actually verifies, and which attacks it does and does not stop.

The short version: **the model produces evidence, the contract produces the decision, and
the validator re-derives both before comparing.**

---

## 1. Where non-determinism lives

Most of the contract is ordinary deterministic Python. The consensus surface is
deliberately narrow.

| Stage | Deterministic? | Notes |
|---|---|---|
| `create_policy` / `add_clause` / `seal_policy` / `fork_policy` | yes | pure storage |
| `submit` | yes | pins subject text on-chain |
| Mechanical clause evaluation | yes | pure Python, runs before any nondet block |
| **Interpretive clause evaluation** | **no** | `gl.vm.run_nondet_unsafe` |
| Aggregation (`_aggregate`) | yes | runs on the verdict vector, in contract code |
| Persistence of rulings and outcome | yes | |

Only step 4 crosses the non-deterministic boundary, and it crosses it carrying a
constrained payload: a fixed-length vector of enum values plus quoted spans. Nothing
about the *decision rule* is ever delegated to a model.

### Why the subject is pinned, not fetched

`submit` writes the submission text into contract storage. `source_uri` is recorded as
provenance and is **never dereferenced during adjudication**.

If the contract fetched the URL at adjudication time, three things break:

- Different validators would fetch at different moments and could see different bytes.
  Consensus would fail for reasons having nothing to do with the policy.
- The evidence grounding check (§3.3) needs a single canonical text to check quotes
  against. Two nodes holding different texts cannot agree on whether a quote is real.
- The ruling would stop being reproducible the moment the page changed. An auditor
  reading the case a year later must be able to see exactly what was judged.

Pinning costs storage and caps submission size. It buys reproducibility, which for an
adjudication primitive is not optional.

---

## 2. The leader's job

```python
def leader_fn() -> dict:
    raw = gl.nondet.exec_prompt(prompt, response_format="json")
    parsed = _collect_verdicts(raw, interpretive_ids)
    grounded = _apply_grounding(parsed, subject)

    if not _response_is_usable(grounded):
        raise gl.vm.UserError(f"{ERR_LLM} model returned no usable verdicts")
    return _strip_provenance(grounded)
```

Three things happen here, and each one narrows what a model can influence.

**`_collect_verdicts` constrains the output space and tracks provenance.** The on-chain policy
defines the clause set — clause IDs the model invents are discarded, and clauses it omits are filled
in as `UNCLEAR` with provenance `SRC_DEFAULTED`. Valid enum verdicts for known clauses are tagged
as `SRC_MODEL`. Malformed JSON, wrong types, and illegal enum values all collapse to `UNCLEAR`
(`SRC_DEFAULTED`) rather than raising. This is fail-closed: `UNCLEAR` on a blocking clause routes
the case to `NEEDS_REVIEW`, never to `APPROVED`.

**`_apply_grounding` downgrades unsupported accusations.** A `FAIL` whose evidence quote
does not appear in the subject becomes `UNCLEAR` with provenance `SRC_DOWNGRADED` and the rationale
`"Cited evidence not found in subject text; downgraded."` An ungrounded `FAIL` cannot
reach storage through the honest path.

**`_response_is_usable` distinguishes undecidability from unusable output.** 
- When the pinned subject genuinely does not contain enough information to decide any clause,
  the model returns a complete vector of `UNCLEAR`s (`SRC_MODEL`). This is a legitimate reading
  of an underdetermined submission: `_response_is_usable` accepts it, and `_aggregate` routes
  it to `NEEDS_REVIEW`.
- Conversely, if the model outputs malformed data, omitted all clauses, or fabricated quotes
  for every single failure (leaving only `SRC_DEFAULTED` or `SRC_DOWNGRADED`), `_response_is_usable`
  returns `False`. The leader raises `[LLM_ERROR]`, causing validators to disagree and forcing
  a retry with a different leader rather than recording a vacuous ruling.

Before returning across the consensus boundary, `_strip_provenance` removes the internal
provenance tags so validators only evaluate clean verdict vectors.

### Prompt injection posture

The submission is untrusted text being fed to a model. The mitigations are structural
rather than filter-based:

- The prompt is assembled in contract code from on-chain clause text. A caller cannot
  supply prompt fragments.
- The subject is fenced in explicit `-----BEGIN SUBMISSION-----` markers and labeled as
  data to evaluate, with an instruction never to follow instructions inside it.
- The output space is a fixed enum over a known clause-ID set. Even a fully successful
  injection cannot introduce a new clause, change a severity, or set the outcome —
  `_collect_verdicts` drops unknown IDs and `_aggregate` owns the decision.
- The prompt explicitly tells the model that deciding overall approval is **not its
  task**.

The strongest injection available to an attacker is flipping their own clause verdicts
to `PASS`. That attack has to survive the validator, which independently evaluates the
same text and — if the injection is unreliable, as they generally are — produces a
`PASS`↔`FAIL` contradiction.

---

## 3. The validator's job

This is the part the submission category is really asking about, so it's worth being
precise about what a *weak* validator looks like:

```python
# The anti-pattern. Do not do this.
def validator_fn(leader_result):
    data = leader_result.calldata
    return (isinstance(data, dict)
            and all(v["verdict"] in ("PASS", "FAIL", "UNCLEAR") for v in data.values()))
```

That validator proves the leader emitted well-formed JSON. It cannot distinguish a
careful evaluation from a fabricated one, so consensus degrades to trusting whoever was
elected leader. ClauseCheck's validator runs four checks, none of which is a shape check.

### 3.1 Independent re-derivation

```python
mine = leader_fn()               # <- form our own complete answer FIRST
theirs = leader_result.calldata  # <- only now look at the leader's
```

The validator runs the identical evaluation pipeline and builds a full verdict vector of
its own **before reading the leader's answer**. Ordering matters: reading first invites
anchoring, and a validator that has already seen the answer is checking, not deriving.

This single line is what makes every subsequent comparison meaningful. Everything else
compares two independently produced artifacts.

### 3.2 Asymmetric per-clause comparison

Not all disagreement means the same thing, and treating it uniformly gives you either a
validator that rubber-stamps or a chain that never finalizes.

| Disagreement | Treatment | Why |
|---|---|---|
| `PASS` vs `FAIL` | **always reject** | A direct contradiction about the same fixed text. One side is wrong; neither should win by default. |
| any drift on a `FATAL` clause | **always reject** | `FATAL` failures reject the whole case. Zero tolerance where the stakes are highest. |
| `X` vs `UNCLEAR` on `MAJOR`/`ADVISORY` | tolerated, up to `MAX_DRIFT_CLAUSES = 1` | Confidence drift on a borderline clause is normal model variance, not dishonesty. |
| drift on 2+ clauses | **reject** | Two independent judgment gaps means the evaluations diverged, not that one clause was borderline. |

The drift allowance is a deliberate, bounded loosening. Without it, two honest
validators would routinely reject each other over ordinary variance and no case would
finalize. With it unbounded, a leader could hide behind "everything is unclear". One
clause, never `FATAL`, still subject to §3.4.

### 3.3 Evidence grounding

```python
for clause_id in interpretive_ids:
    their_entry = theirs[clause_id]
    if their_entry.get("verdict") != VERDICT_FAIL:
        continue
    if not _quote_is_grounded(subject, their_entry.get("evidence", "")):
        return False
```

Every `FAIL` the leader reports must cite a quote that genuinely appears in the pinned
subject. This is `in` on a normalized string — no judgment, no second model call,
identical on every node.

`_normalize` collapses whitespace and case before matching, because models reflow text
they quote. It stops there deliberately: no fuzzy matching, no embeddings, no
"semantically similar". The moment grounding becomes approximate it stops being a
verifiable check.

Quotes shorter than 8 normalized characters are rejected — a single common word appears
in almost any document and proves nothing.

**Note the asymmetry: `PASS` requires no citation.** Compliance is frequently
demonstrated by absence — "contains no confidential material", "does not exceed the
budget" — and there is no quote that shows a thing is missing. Demanding one would
actively incentivize fabrication. The abuse this leaves open, a leader passing
everything, is caught by §3.1 producing a contradiction.

### 3.4 Aggregate equality

```python
return _aggregate(their_flat, severities, max_major) == _aggregate(
    my_flat, severities, max_major
)
```

The per-clause vector is the mechanism; the stored outcome is what other contracts read
and what money moves on. Both vectors — mechanical clauses included — go through the
same deterministic aggregation and the case-level results must match.

This is the backstop for §3.2's tolerance band. Drift is allowed only when it is
provably outcome-neutral: a single `UNCLEAR` on a `MAJOR` clause is tolerated at step 2,
but if it flips the case from `APPROVED` to `NEEDS_REVIEW`, step 4 rejects it.

### 3.5 When the leader raises

```python
if not isinstance(leader_result, gl.vm.Return):
    return _leader_errors_match(leader_result, leader_fn)
```

Errors need consensus too, and the two kinds are treated differently:

- **`[EXPECTED]`** — deterministic business-logic failure (unknown case, sealed policy,
  attempts exhausted). The validator re-runs, and agrees only if it hits the same wall
  with the same message. Genuine consensus on a failure.
- **`[LLM_ERROR]`** — the model returned nothing usable. The validator **always
  disagrees**, forcing a retry with a different leader. A transient model failure should
  not become a permanent on-chain ruling.
- **Validator succeeded where the leader raised** — disagree. The leader's failure was
  not reproducible.

---

## 4. Threat model

| Attack | Caught by | Notes |
|---|---|---|
| Leader fabricates a quote to justify a `FAIL` | §3.1 contradiction, §3.3 grounding | Caught twice over when verdicts differ; §3.3 alone when they agree. |
| Leader attaches a fake citation to a *real* failure | §3.3 grounding **only** | Verdicts match, aggregate matches. Isolated by `test_validator_rejects_forgery_it_cannot_detect_by_disagreement`. |
| Leader passes every clause to force approval | §3.1 + §3.2 | Validator's independent `FAIL` produces a contradiction. |
| Leader fails a clause to block a legitimate submission | §3.1 + §3.3 | Needs both a matching independent judgment and a real quote. |
| Leader omits an inconvenient clause | §3.2 (`their_entry` not a dict → reject) | Also fails closed in `_collect_verdicts` on the honest path. |
| Leader invents extra clauses | `_collect_verdicts` drops unknown IDs | Policy defines the clause set, not the model. |
| Submission contains prompt injection | Structural constraints (§2) + §3.1 | Injection must work identically on every validator to survive. |
| Leader returns malformed JSON | `_collect_verdicts` → all `UNCLEAR` → `[LLM_ERROR]` | Retry, not a ruling. |
| Leader edits the subject text | Not possible | Subject is pinned at `submit`; the nondet block receives a copy. |
| Source document changes after submission | Not possible | `source_uri` is never fetched. |

### Not defended against

Being explicit about this, because a primitive others build on should state its edges:

- **A leader that quotes real text and interprets it wrongly.** Grounding proves the
  quote exists, not that the inference from it is sound. That case rests entirely on
  §3.1 — the validator reaching a different conclusion. Grounding exists to make
  *fabrication* impossible, which is the cheaper and far more common attack.
- **A systematically biased model.** If every node runs a model that reads a clause the
  same wrong way, they will agree. This is inherent to Optimistic Democracy and is why
  `NEEDS_REVIEW` exists as a first-class outcome rather than a failure state.
- **A policy whose clauses are ambiguous.** Vague clauses produce `UNCLEAR` verdicts and
  route cases to review. The contract surfaces the ambiguity instead of hiding it, but
  it cannot fix a badly written policy.

---

## 5. Mutation testing

A green test suite proves the code handles the cases you thought of. It does not prove
your tests would notice if a guard were deleted. `tools/mutation_test.py` checks that
directly: it disables each consensus guard in turn, re-runs the suite, and reports
whether anything failed.

```bash
python tools/mutation_test.py
```

Current results — every guard is load-bearing and individually observable:

```
Baseline (unmutated contract):
  51 passed in 5.54s

[KILLED  ] validator skips independent re-derivation      -> 5 failed, 46 passed
[KILLED  ] PASS<->FAIL contradiction tolerated            -> 1 failed, 50 passed
[KILLED  ] FATAL clauses lose zero-tolerance              -> 1 failed, 50 passed
[KILLED  ] drift allowance removed (unbounded drift)      -> 1 failed, 50 passed
[KILLED  ] validator stops grounding leader evidence      -> 1 failed, 50 passed
[KILLED  ] aggregate equality check removed               -> 1 failed, 50 passed
[KILLED  ] leader grounding removed                       -> 1 failed, 50 passed
[KILLED  ] omitted clauses no longer fail closed          -> 1 failed, 50 passed
[KILLED  ] unknown clause ids accepted from model         -> 1 failed, 50 passed
[KILLED  ] ADVISORY failures block approval               -> 1 failed, 50 passed

All 10 mutants killed. Every consensus guard is load-bearing.
```

Two results are worth reading closely.

**Independent re-derivation breaks 5 tests at once.** Replacing `mine = leader_fn()`
with `mine = theirs` — which is precisely the difference between a real validator and a
format-only one — collapses five independent consensus tests simultaneously. That is the
concrete demonstration that this validator's checks are anchored to an independently
derived answer rather than to the leader's.

**Grounding initially survived, and that was a real finding.** In an earlier run this
mutant passed all tests. The forged-evidence test that was supposed to cover it was
actually being caught one step earlier, by the `PASS`↔`FAIL` contradiction check — the
guard was tested only incidentally. That gap is exactly what mutation testing is for.
`test_validator_rejects_forgery_it_cannot_detect_by_disagreement` was added to isolate
it: matching verdicts, matching aggregate outcome, fake citation. It is now the only
test that fails when grounding is removed.

The mutation script refuses to run a mutant whose source anchor no longer matches
exactly once, so a future refactor cannot silently turn these checks into no-ops.

---

## 6. Reading the source

The consensus core is `_adjudicate_interpretive` in
[`contracts/ClauseCheck.py`](contracts/ClauseCheck.py) — the two closures and the
`gl.vm.run_nondet_unsafe` call are about 70 lines and are meant to be read top to
bottom. The four numbered checks in §3 correspond to the four numbered comments in
`validator_fn`.

Supporting pure functions, all independently testable:

| Function | |
|---|---|
| `_normalize` | whitespace/case collapse for quote matching |
| `_quote_is_grounded` | the containment check behind §3.3 |
| `_eval_mechanical` | deterministic predicates, never reaches the LLM |
| `_aggregate` | **the decision rule** — verdict vector → outcome |
| `_build_prompt` | prompt assembly and injection posture |
| `_collect_verdicts` | defensive parsing with provenance tracking, fail-closed |
| `_apply_grounding` | downgrades unsupported `FAIL`s |
| `_response_is_usable` | separates underdetermined vectors from unusable/fabricated model output |
| `_strip_provenance` | drops internal provenance tags before crossing consensus boundary |
| `_leader_errors_match` | error consensus (§3.5) |
