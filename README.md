# ClauseCheck

**A natural-language policy compliance primitive for GenLayer.**

ClauseCheck answers one question that a surprising number of on-chain use cases reduce
to: *does this submission satisfy this set of rules written in English?*

Bounty acceptance criteria. DAO charter constraints. Grant milestone requirements.
Listing guidelines. Content standards. SLA terms. Today each of these gets rebuilt from
scratch as a bespoke "ask the LLM if it's okay" contract. ClauseCheck is the reusable
layer underneath them.

```
   policy (versioned, sealed)          submission (pinned on-chain)
              |                                    |
              +----------------+-------------------+
                               |
                    per-clause verdict vector
              PASS / FAIL / UNCLEAR  +  verbatim evidence
                               |
                 deterministic aggregation in contract code
                               |
              APPROVED | REJECTED | NEEDS_REVIEW
```

---

## Why this isn't "AI decides X"

The naive version of this contract hands the whole policy and the whole submission to a
model and asks *"approve or reject?"* That produces a single opaque judgment. Validators
can only re-ask the same question and hope the answer matches, and the entire decision
rule lives inside a model nobody can audit.

ClauseCheck **decomposes the judgment**:

1. **A policy is a list of individually-addressable clauses**, each with a registered
   `kind` and `severity`. Clauses are stored on-chain and sealed before use.
2. **Mechanical clauses never reach the model.** Length limits, required terms, forbidden
   terms — these are pure Python predicates evaluated outside any non-deterministic
   block. They cost no LLM budget and cannot disagree across nodes.
3. **The model only produces a verdict vector** — one `PASS`/`FAIL`/`UNCLEAR` per
   interpretive clause, each `FAIL` carrying a verbatim quote from the submission.
   The prompt explicitly instructs it *not* to decide the overall outcome.
4. **The outcome is computed in deterministic contract code** (`_aggregate`) from that
   vector plus each clause's severity. This function is readable, auditable, and
   identical on every node. The model's influence is bounded to per-clause calls.

The decision rule is on-chain. The model is a per-clause sensor, not the judge.

---

## How consensus is used

Full detail in **[CONSENSUS.md](CONSENSUS.md)**. In brief, `adjudicate` runs the
interpretive clauses through `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`, and the
validator applies four independent checks:

| # | Check | Why it isn't a format check |
|---|-------|-----------------------------|
| 1 | **Independent re-derivation** | The validator calls `leader_fn()` and forms its own complete verdict vector *before* reading the leader's. |
| 2 | **Asymmetric per-clause comparison** | `PASS`↔`FAIL` contradictions always fail. `FATAL` clauses get zero tolerance. Only bounded `UNCLEAR` drift on lower-severity clauses is accepted. |
| 3 | **Evidence grounding** | Every quote the leader cites for a `FAIL` must appear verbatim in the on-chain submission. A string containment test against source data — a hallucinated citation is caught deterministically, with no judgment involved. |
| 4 | **Aggregate equality** | Both vectors are run through the same deterministic aggregation and the resulting case outcomes must match. |

A format-only validator checks JSON shape, enum membership, and confidence bounds — it
proves the leader formatted its answer correctly and nothing else. Every check above is
against either source data or an independently derived answer.

The test suite exercises both ways a leader can lie. In
`test_validator_rejects_forged_leader_evidence`, the leader fabricates a `FAIL` outright;
the validator catches it on contradiction — it derived `PASS` itself. The harder case is
`test_validator_rejects_forgery_it_cannot_detect_by_disagreement`, where leader and
validator **agree** on every verdict and both aggregate to the same outcome, and the
only defect is a citation that does not exist in the submission. Only the grounding
check catches that one.

---

## State design

```python
Clause      clause_id, kind, severity, text, predicate
Policy      policy_id, version, title, owner, sealed, max_major_failures, clauses[]
ClauseRuling  clause_id, verdict, severity, evidence, rationale
Case        case_id, policy_id, policy_version, submitter, subject, source_uri,
            outcome, attempts, decided_at, rulings[]
```

Three decisions worth calling out:

**Policies seal, then fork.** A sealed policy is immutable. Amending it means
`fork_policy`, which copies the clauses into a new policy at `version + 1`. Rulings
reference `(policy_id, policy_version)`, so an auditor can always reconstruct the exact
rules a decision was made under. Mutating a policy in place would silently invalidate
every ruling made under it.

**Submissions are pinned, not linked.** `submit` stores the subject text on-chain.
`source_uri` is provenance metadata and is **never dereferenced**. Re-fetching a URL at
adjudication time would let different nodes see different bytes — consensus would fail
for reasons unrelated to the policy, and the ruling would stop being reproducible the
moment the page changed. `get_subject` returns the exact adjudicated text forever.

**Severity is snapshotted into each ruling.** A `ClauseRuling` records the severity in
force when the ruling was made, so re-reading an old case doesn't reinterpret it under
today's rules.

---

## Outcomes

`_aggregate` maps a verdict vector to one of three outcomes:

| Condition | Outcome |
|---|---|
| any `FATAL` clause `FAIL`s | `REJECTED` |
| `MAJOR` failures exceed `max_major_failures` | `REJECTED` |
| any `FATAL`/`MAJOR` clause is `UNCLEAR` | `NEEDS_REVIEW` |
| otherwise | `APPROVED` |

`ADVISORY` clauses are recorded but never block. `NEEDS_REVIEW` is a genuine third state,
not a failure: it means the submission text does not settle the question, and the case can
be re-adjudicated (up to `MAX_ATTEMPTS`) or escalated to humans. **Nothing is ever
silently approved** — every parse failure, omitted clause, and ungrounded accusation
collapses to `UNCLEAR`, which routes blocking clauses to review rather than approval.

---

## Usage

### Define a policy

```python
check = gl.get_contract_at(clausecheck_address)

check.emit(on="finalized").create_policy("grant-milestone", "Grant Milestone Review", 0)

check.emit(on="finalized").add_clause(
    "grant-milestone", "deliverable-shipped",
    "INTERPRETIVE", "FATAL",
    "The report must state that the milestone deliverable was completed and shipped.",
    "",
)
check.emit(on="finalized").add_clause(
    "grant-milestone", "length-cap",
    "MECHANICAL", "ADVISORY",
    "The report must be at most 400 words.",
    "max_words:400",
)

check.emit(on="finalized").seal_policy("grant-milestone")
```

Supported mechanical predicates: `max_words:N`, `min_words:N`, `must_contain:TEXT`,
`must_not_contain:TEXT`. Matching is whitespace- and case-insensitive. An unknown
predicate returns `UNCLEAR` rather than passing — fail closed.

### Adjudicate a submission

```python
case_id = check.submit("grant-milestone", report_text, "https://example.org/report")
check.emit(on="finalized").adjudicate(case_id)
```

### Gate your own contract on the result

This is the integration surface. Escrow release, bounty payout, proposal queueing,
listing approval:

```python
@gl.public.write
def release_escrow(self, case_id: str):
    checker = gl.get_contract_at(self.clausecheck_address)
    if checker.view().get_outcome(case_id) != "APPROVED":
        raise gl.vm.UserError("compliance not established")
    ...
```

`get_ruling(case_id)` returns the full verdict vector with evidence and rationale for
each clause — enough to render a reviewer UI or to justify the decision to the submitter.

One deployment serves many policies; the registry and the adjudication engine are
independent.

---

## Layout

| Path | |
|---|---|
| [`contracts/ClauseCheck.py`](contracts/ClauseCheck.py) | the contract |
| [`tests/test_clausecheck.py`](tests/test_clausecheck.py) | 51 Direct Mode tests |
| [`tools/mutation_test.py`](tools/mutation_test.py) | disables each guard, checks the suite notices |
| [`CONSENSUS.md`](CONSENSUS.md) | consensus design and threat model |
| [`DEPLOY.md`](DEPLOY.md) | GenLayer Studio deployment walkthrough |

## Running the tests

```bash
pip install genlayer-test genvm-linter
```

```bash
python -m pytest tests/ -q
```

Direct Mode mocks the LLM and web layers, so the suite runs fully offline with no node,
no keys, and no network. It runs with `strict_mocks` and `check_pickling` enabled.

Lint and validate the contract against the GenVM SDK:

```bash
genvm-lint check contracts/ClauseCheck.py
```

### Test coverage

| Area | What's covered |
|---|---|
| Policy lifecycle | creation, clause validation, sealing, immutability, ownership, forking |
| Mechanical clauses | all four predicates, both polarities, normalization, no LLM reached |
| Aggregation | `FATAL`/`MAJOR`/`ADVISORY` interaction, allowance boundaries, `UNCLEAR` routing |
| Model defenses | fabricated evidence, invented clause IDs, omitted clauses, garbage enums, unparseable output |
| Consensus | agreement, contradiction, `FATAL` drift, bounded drift, drift overflow, outcome divergence, forged leader results, dropped clauses, leader errors |

The consensus guards are **mutation-tested**. Each guard is disabled in turn and the
suite re-run; a guard whose removal nobody notices is a guard that isn't really there.
All 10 mutants are killed:

```bash
python tools/mutation_test.py
```

See [CONSENSUS.md](CONSENSUS.md#5-mutation-testing) for the full results.

---

## Limitations

Stated plainly, because a primitive other people build on should be honest about its
edges:

- **Grounding is containment, not semantics.** A leader can quote a real sentence and
  attach a wrong interpretation. That failure is caught by check 1 (independent
  re-derivation), not by grounding. Grounding exists to make *fabrication* impossible,
  which is the cheaper and more common attack.
- **`PASS` requires no citation.** Compliance is frequently demonstrated by absence
  ("contains no confidential material"), and demanding a quote there would incentivize
  fabrication. A leader that passes everything is caught by the validator's independent
  re-derivation producing a `PASS`↔`FAIL` contradiction.
- **The drift allowance is a deliberate loosening.** `MAX_DRIFT_CLAUSES = 1` permits one
  non-`FATAL` clause to differ by `UNCLEAR` between leader and validator. Without it,
  honest validators would reject each other on ordinary model variance and no case would
  ever finalize. It is bounded, excluded from `FATAL` clauses, and still gated by
  aggregate equality.
- **Subject size is capped** at `MAX_SUBJECT_CHARS = 20000`. Larger documents need
  chunking, which would change the consensus surface and is deliberately out of scope.
- **Policy quality is the operator's problem.** Vague clauses produce `UNCLEAR` verdicts
  and `NEEDS_REVIEW` outcomes. That is the correct behavior — the contract surfaces
  ambiguity rather than hiding it — but it does mean a badly written policy yields a
  contract that mostly asks for human review.
