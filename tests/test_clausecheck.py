"""
Direct Mode tests for ClauseCheck.

Layered per the GenLayer testing guide:

  1. Pure storage / lifecycle — no non-determinism at all.
  2. Mechanical clause evaluation — deterministic, never reaches the LLM.
  3. Deterministic aggregation — the outcome rule, exercised through the contract.
  4. Interpretive adjudication with mocked LLM — parsing, grounding, injection defenses.
  5. Consensus — `direct_vm.run_validator()`, including forged leader results.

Layer 5 is the important one. `run_validator(leader_result=...)` lets a test hand the
validator a leader answer the leader never actually produced, which is exactly the
malicious-leader case a validator exists to stop.
"""

import json

import pytest

CONTRACT = "contracts/ClauseCheck.py"

# A realistic grant-milestone report. Every span the tests quote appears here verbatim,
# so grounding checks operate against real text rather than a fixture placeholder.
SUBJECT = """
Milestone 2 Report — Ledger Reconciliation Service

We completed and shipped the reconciliation service to production on March 14.
The service now processes roughly 40,000 statements per day.

Budget: of the 50,000 GEN tranche, 38,000 GEN went to two contract engineers,
7,500 GEN to infrastructure, and 4,500 GEN remains unspent and is carried forward.

We also replaced the originally agreed Postgres backend with ClickHouse without
raising it with the grants committee first.

Repository: https://example.org/ledger-recon
Demo: https://example.org/ledger-recon/demo
"""

CLAUSES = [
    # (clause_id, kind, severity, text, predicate)
    (
        "deliverable-shipped",
        "INTERPRETIVE",
        "FATAL",
        "The report must state that the milestone deliverable was completed and shipped.",
        "",
    ),
    (
        "budget-disclosed",
        "INTERPRETIVE",
        "MAJOR",
        "The report must disclose how the grant funds were spent.",
        "",
    ),
    (
        "no-unapproved-scope-change",
        "INTERPRETIVE",
        "MAJOR",
        "The report must not describe changes to the agreed scope that were made "
        "without prior approval.",
        "",
    ),
    (
        "links-provided",
        "INTERPRETIVE",
        "ADVISORY",
        "The report should link to the delivered work.",
        "",
    ),
    (
        "length-cap",
        "MECHANICAL",
        "ADVISORY",
        "The report must be at most 400 words.",
        "max_words:400",
    ),
]

INTERPRETIVE_IDS = [c[0] for c in CLAUSES if c[1] == "INTERPRETIVE"]


# ---------------------------------------------------------------------------- helpers


def build_policy(contract, policy_id="grant-milestone", max_major_failures=0,
                 clauses=CLAUSES, seal=True):
    contract.create_policy(policy_id, "Grant Milestone Review", max_major_failures)
    for clause_id, kind, severity, text, predicate in clauses:
        contract.add_clause(policy_id, clause_id, kind, severity, text, predicate)
    if seal:
        contract.seal_policy(policy_id)
    return policy_id


def llm_json(verdicts):
    """verdicts: {clause_id: (verdict, evidence)} -> mock LLM response string."""
    return json.dumps(
        {
            "verdicts": [
                {
                    "clause_id": clause_id,
                    "verdict": verdict,
                    "evidence": evidence,
                    "rationale": "test rationale",
                }
                for clause_id, (verdict, evidence) in verdicts.items()
            ]
        }
    )


# A compliant read of the subject: everything passes except the scope change, which is
# genuinely present in the text and is quoted verbatim.
VERDICTS_TYPICAL = {
    "deliverable-shipped": ("PASS", ""),
    "budget-disclosed": ("PASS", ""),
    "no-unapproved-scope-change": (
        "FAIL",
        "replaced the originally agreed Postgres backend with ClickHouse without",
    ),
    "links-provided": ("PASS", ""),
}

VERDICTS_ALL_CLEAN = {
    "deliverable-shipped": ("PASS", ""),
    "budget-disclosed": ("PASS", ""),
    "no-unapproved-scope-change": ("PASS", ""),
    "links-provided": ("PASS", ""),
}


@pytest.fixture
def contract(direct_vm, direct_deploy):
    direct_vm.warp("2026-03-20T12:00:00+00:00")
    # strict_mocks surfaces prompts no mock matched, so a test can never silently
    # exercise a different code path than the one it names. check_pickling forces the
    # @allow_storage dataclasses through serialization on every call.
    direct_vm.strict_mocks = True
    direct_vm.check_pickling = True
    return direct_deploy(CONTRACT)


# ------------------------------------------------------------- 1. policy lifecycle


def test_create_and_seal_policy(contract):
    build_policy(contract)
    policy = contract.get_policy("grant-milestone")

    assert policy["sealed"] is True
    assert policy["version"] == 1
    assert len(policy["clauses"]) == 5
    assert contract.list_policies() == ["grant-milestone"]


def test_duplicate_policy_rejected(direct_vm, contract):
    build_policy(contract)
    with direct_vm.expect_revert("policy already exists"):
        contract.create_policy("grant-milestone", "Duplicate", 0)


def test_duplicate_clause_rejected(direct_vm, contract):
    contract.create_policy("p", "P", 0)
    contract.add_clause("p", "c1", "INTERPRETIVE", "MAJOR", "Rule text.", "")
    with direct_vm.expect_revert("duplicate clause_id"):
        contract.add_clause("p", "c1", "INTERPRETIVE", "MAJOR", "Other text.", "")


def test_invalid_kind_and_severity_rejected(direct_vm, contract):
    contract.create_policy("p", "P", 0)
    with direct_vm.expect_revert("invalid kind"):
        contract.add_clause("p", "c1", "VIBES", "MAJOR", "Rule text.", "")
    with direct_vm.expect_revert("invalid severity"):
        contract.add_clause("p", "c1", "INTERPRETIVE", "CATASTROPHIC", "Rule text.", "")


def test_unsupported_mechanical_predicate_rejected(direct_vm, contract):
    contract.create_policy("p", "P", 0)
    with direct_vm.expect_revert("unsupported mechanical predicate"):
        contract.add_clause("p", "c1", "MECHANICAL", "MAJOR", "Rule.", "vibes_check:9")


def test_empty_policy_cannot_be_sealed(direct_vm, contract):
    contract.create_policy("p", "P", 0)
    with direct_vm.expect_revert("cannot seal an empty policy"):
        contract.seal_policy("p")


def test_sealed_policy_is_immutable(direct_vm, contract):
    build_policy(contract)
    with direct_vm.expect_revert("policy is sealed"):
        contract.add_clause(
            "grant-milestone", "extra", "INTERPRETIVE", "MAJOR", "Late rule.", ""
        )


def test_only_owner_may_add_clauses(direct_vm, contract, direct_bob):
    contract.create_policy("p", "P", 0)
    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("only the policy owner"):
            contract.add_clause("p", "c1", "INTERPRETIVE", "MAJOR", "Rule.", "")


def test_fork_copies_clauses_and_bumps_version(contract):
    build_policy(contract)
    contract.fork_policy("grant-milestone", "grant-milestone-v2", "Grant Review v2")

    forked = contract.get_policy("grant-milestone-v2")
    assert forked["version"] == 2
    assert forked["sealed"] is False
    assert [c["clause_id"] for c in forked["clauses"]] == [c[0] for c in CLAUSES]

    # The original stays sealed and untouched — rulings against it remain reproducible.
    assert contract.get_policy("grant-milestone")["sealed"] is True


def test_cannot_submit_to_unsealed_policy(direct_vm, contract):
    build_policy(contract, seal=False)
    with direct_vm.expect_revert("policy is not sealed"):
        contract.submit("grant-milestone", SUBJECT, "")


def test_submit_pins_subject_and_policy_version(contract):
    build_policy(contract)
    case_id = contract.submit("grant-milestone", SUBJECT, "https://example.org/report")

    ruling = contract.get_ruling(case_id)
    assert ruling["outcome"] == "PENDING"
    assert ruling["policy_version"] == 1
    assert ruling["source_uri"] == "https://example.org/report"
    # The adjudicated text is retrievable forever, independent of the source URI.
    assert contract.get_subject(case_id) == SUBJECT


def test_empty_subject_rejected(direct_vm, contract):
    build_policy(contract)
    with direct_vm.expect_revert("subject must not be empty"):
        contract.submit("grant-milestone", "", "")


# ------------------------------------------------- 2. mechanical clauses (no LLM)


@pytest.mark.parametrize(
    "predicate,subject,expected",
    [
        ("max_words:5", "one two three", "PASS"),
        ("max_words:2", "one two three", "FAIL"),
        ("min_words:3", "one two three", "PASS"),
        ("min_words:4", "one two three", "FAIL"),
        ("must_contain:Acceptance Criteria", "See ACCEPTANCE   criteria below", "PASS"),
        ("must_contain:Acceptance Criteria", "No such section here", "FAIL"),
        ("must_not_contain:confidential", "This is CONFIDENTIAL material", "FAIL"),
        ("must_not_contain:confidential", "This is public material", "PASS"),
    ],
)
def test_mechanical_predicates(contract, predicate, subject, expected):
    """A fully-mechanical policy adjudicates with zero non-deterministic calls."""
    contract.create_policy("mech", "Mechanical", 0)
    contract.add_clause("mech", "rule", "MECHANICAL", "FATAL", "Rule.", predicate)
    contract.seal_policy("mech")

    case_id = contract.submit("mech", subject, "")
    contract.adjudicate(case_id)  # no mock_llm registered — proves no LLM is reached

    ruling = contract.get_ruling(case_id)
    assert ruling["rulings"][0]["verdict"] == expected
    assert ruling["outcome"] == ("APPROVED" if expected == "PASS" else "REJECTED")


def test_mechanical_predicate_matching_is_whitespace_and_case_insensitive(contract):
    contract.create_policy("mech", "Mechanical", 0)
    contract.add_clause(
        "mech", "rule", "MECHANICAL", "FATAL", "Rule.", "must_contain:shipped to production"
    )
    contract.seal_policy("mech")

    case_id = contract.submit("mech", "We\n  SHIPPED   TO\tProduction last week.", "")
    contract.adjudicate(case_id)
    assert contract.get_outcome(case_id) == "APPROVED"


# ------------------------------------------------------ 3. deterministic aggregation


def aggregation_case(contract, direct_vm, severities, verdicts, max_major_failures=0):
    """Build a one-clause-per-severity policy and drive it to a decided outcome."""
    clauses = [
        (f"c{i}", "INTERPRETIVE", sev, f"Rule {i}.", "")
        for i, sev in enumerate(severities)
    ]
    build_policy(
        contract, "agg", max_major_failures=max_major_failures, clauses=clauses
    )
    direct_vm.mock_llm(r".*", llm_json(verdicts))
    case_id = contract.submit("agg", SUBJECT, "")
    contract.adjudicate(case_id)
    return contract.get_outcome(case_id)


def test_fatal_failure_rejects(contract, direct_vm):
    outcome = aggregation_case(
        contract,
        direct_vm,
        ["FATAL", "MAJOR"],
        {
            "c0": ("FAIL", "processes roughly 40,000 statements per day"),
            "c1": ("PASS", ""),
        },
    )
    assert outcome == "REJECTED"


def test_advisory_failure_does_not_block_approval(contract, direct_vm):
    outcome = aggregation_case(
        contract,
        direct_vm,
        ["FATAL", "ADVISORY"],
        {
            "c0": ("PASS", ""),
            "c1": ("FAIL", "processes roughly 40,000 statements per day"),
        },
    )
    assert outcome == "APPROVED"


def test_major_failures_within_allowance_approve(contract, direct_vm):
    outcome = aggregation_case(
        contract,
        direct_vm,
        ["MAJOR", "MAJOR"],
        {
            "c0": ("FAIL", "processes roughly 40,000 statements per day"),
            "c1": ("PASS", ""),
        },
        max_major_failures=1,
    )
    assert outcome == "APPROVED"


def test_major_failures_over_allowance_reject(contract, direct_vm):
    outcome = aggregation_case(
        contract,
        direct_vm,
        ["MAJOR", "MAJOR"],
        {
            "c0": ("FAIL", "processes roughly 40,000 statements per day"),
            "c1": ("FAIL", "7,500 GEN to infrastructure"),
        },
        max_major_failures=1,
    )
    assert outcome == "REJECTED"


def test_unclear_on_blocking_clause_needs_review(contract, direct_vm):
    outcome = aggregation_case(
        contract,
        direct_vm,
        ["FATAL", "MAJOR"],
        {"c0": ("UNCLEAR", ""), "c1": ("PASS", "")},
    )
    assert outcome == "NEEDS_REVIEW"


def test_unclear_on_advisory_clause_still_approves(contract, direct_vm):
    outcome = aggregation_case(
        contract,
        direct_vm,
        ["FATAL", "ADVISORY"],
        {"c0": ("PASS", ""), "c1": ("UNCLEAR", "")},
    )
    assert outcome == "APPROVED"


# --------------------------------------------- 4. interpretive adjudication + defenses


def test_typical_adjudication_records_full_verdict_vector(contract, direct_vm):
    build_policy(contract)
    direct_vm.mock_llm(r".*", llm_json(VERDICTS_TYPICAL))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    verdicts = {r["clause_id"]: r["verdict"] for r in ruling["rulings"]}

    assert verdicts == {
        "deliverable-shipped": "PASS",
        "budget-disclosed": "PASS",
        "no-unapproved-scope-change": "FAIL",
        "links-provided": "PASS",
        "length-cap": "PASS",  # mechanical, evaluated without the LLM
    }
    # One MAJOR failure against an allowance of zero.
    assert ruling["outcome"] == "REJECTED"
    assert ruling["attempts"] == 1
    assert ruling["decided_at"] != ""

    # The FAIL carries verbatim evidence from the pinned subject.
    scope = next(r for r in ruling["rulings"] if r["clause_id"] == "no-unapproved-scope-change")
    assert scope["evidence"] in SUBJECT


def test_clean_report_is_approved(contract, direct_vm):
    build_policy(contract)
    direct_vm.mock_llm(r".*", llm_json(VERDICTS_ALL_CLEAN))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)
    assert contract.get_outcome(case_id) == "APPROVED"


def test_fabricated_evidence_is_downgraded_not_stored_as_failure(contract, direct_vm):
    """
    A FAIL citing text that does not exist in the subject cannot become a rejection.

    This is the anti-hallucination floor: grounding is a string containment check
    against the on-chain subject, so it holds even before consensus runs.
    """
    build_policy(contract)
    forged = dict(VERDICTS_ALL_CLEAN)
    forged["no-unapproved-scope-change"] = (
        "FAIL",
        "the team admitted to falsifying the entire budget report",  # not in SUBJECT
    )
    direct_vm.mock_llm(r".*", llm_json(forged))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    scope = next(r for r in ruling["rulings"] if r["clause_id"] == "no-unapproved-scope-change")
    assert scope["verdict"] == "UNCLEAR"
    assert scope["evidence"] == ""
    # Downgraded to UNCLEAR on a MAJOR clause -> review, not rejection.
    assert ruling["outcome"] == "NEEDS_REVIEW"


def test_invented_clause_ids_are_discarded(contract, direct_vm):
    """The on-chain policy defines the clause set; the model cannot extend it."""
    build_policy(contract)
    payload = dict(VERDICTS_ALL_CLEAN)
    payload["ignore-previous-instructions"] = ("FAIL", "anything")
    direct_vm.mock_llm(r".*", llm_json(payload))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    stored = {r["clause_id"] for r in ruling["rulings"]}
    assert stored == {c[0] for c in CLAUSES}
    assert contract.get_outcome(case_id) == "APPROVED"


def test_omitted_clause_fails_closed_to_unclear(contract, direct_vm):
    build_policy(contract)
    partial = dict(VERDICTS_ALL_CLEAN)
    del partial["deliverable-shipped"]  # FATAL clause silently dropped by the model
    direct_vm.mock_llm(r".*", llm_json(partial))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    shipped = next(r for r in ruling["rulings"] if r["clause_id"] == "deliverable-shipped")
    assert shipped["verdict"] == "UNCLEAR"
    assert ruling["outcome"] == "NEEDS_REVIEW"  # never silently approved


def test_unparseable_llm_output_fails_closed(contract, direct_vm):
    build_policy(contract)
    direct_vm.mock_llm(r".*", "I'm sorry, I can't help with that.")

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    # Every clause collapses to UNCLEAR, which the leader treats as a model failure.
    with direct_vm.expect_revert("LLM_ERROR"):
        contract.adjudicate(case_id)


def test_garbage_verdict_values_become_unclear(contract, direct_vm):
    build_policy(contract)
    payload = dict(VERDICTS_ALL_CLEAN)
    payload["deliverable-shipped"] = ("DEFINITELY_YES", "")
    direct_vm.mock_llm(r".*", llm_json(payload))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    shipped = next(r for r in ruling["rulings"] if r["clause_id"] == "deliverable-shipped")
    assert shipped["verdict"] == "UNCLEAR"


def test_decided_case_cannot_be_readjudicated(contract, direct_vm):
    build_policy(contract)
    direct_vm.mock_llm(r".*", llm_json(VERDICTS_ALL_CLEAN))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)
    assert contract.get_outcome(case_id) == "APPROVED"

    with direct_vm.expect_revert("already decided"):
        contract.adjudicate(case_id)


def test_needs_review_case_can_be_readjudicated_and_replaces_rulings(contract, direct_vm):
    build_policy(contract)
    unclear = dict(VERDICTS_ALL_CLEAN)
    unclear["budget-disclosed"] = ("UNCLEAR", "")
    direct_vm.mock_llm(r".*", llm_json(unclear))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)
    assert contract.get_outcome(case_id) == "NEEDS_REVIEW"

    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(VERDICTS_ALL_CLEAN))
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    assert ruling["outcome"] == "APPROVED"
    assert ruling["attempts"] == 2
    # Rulings replaced, not appended.
    assert len(ruling["rulings"]) == len(CLAUSES)


def test_unknown_case_reverts(direct_vm, contract):
    with direct_vm.expect_revert("unknown case"):
        contract.adjudicate("nope#1")


# --------------------------------------------------------------------- 5. consensus


def adjudicated(contract, direct_vm, verdicts, max_major_failures=0):
    """Run one adjudication as leader, leaving a captured validator behind."""
    build_policy(contract, max_major_failures=max_major_failures)
    direct_vm.mock_llm(r".*", llm_json(verdicts))
    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)
    return case_id


def test_validator_agrees_when_it_derives_the_same_vector(contract, direct_vm):
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)
    assert direct_vm.run_validator() is True


def test_validator_rejects_pass_fail_contradiction(contract, direct_vm):
    """A direct contradiction is fatal at any severity — no tolerance band applies."""
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)

    flipped = dict(VERDICTS_TYPICAL)
    flipped["links-provided"] = ("FAIL", "Repository: https://example.org/ledger-recon")
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(flipped))

    assert direct_vm.run_validator() is False


def test_validator_rejects_any_drift_on_a_fatal_clause(contract, direct_vm):
    """FATAL clauses get zero tolerance, even for PASS<->UNCLEAR confidence drift."""
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)

    drifted = dict(VERDICTS_TYPICAL)
    drifted["deliverable-shipped"] = ("UNCLEAR", "")
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(drifted))

    assert direct_vm.run_validator() is False


def test_validator_tolerates_bounded_drift_on_an_advisory_clause(contract, direct_vm):
    """
    Confidence drift on a clause that cannot change the outcome is tolerated.

    Without this band, honest validators would reject each other constantly and every
    case would go undetermined. The band is deliberately narrow: one non-FATAL clause,
    UNCLEAR only, and the aggregate outcome must still match.
    """
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)

    drifted = dict(VERDICTS_TYPICAL)
    drifted["links-provided"] = ("UNCLEAR", "")
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(drifted))

    assert direct_vm.run_validator() is True


def test_validator_rejects_drift_beyond_the_allowance(contract, direct_vm):
    """Two drifting clauses exceed MAX_DRIFT_CLAUSES even though neither is FATAL."""
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL, max_major_failures=1)

    drifted = dict(VERDICTS_TYPICAL)
    drifted["links-provided"] = ("UNCLEAR", "")
    drifted["budget-disclosed"] = ("UNCLEAR", "")
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(drifted))

    assert direct_vm.run_validator() is False


def test_validator_rejects_drift_that_would_change_the_outcome(contract, direct_vm):
    """
    A single non-FATAL UNCLEAR drift is inside the band, but here it flips the case
    from REJECTED to NEEDS_REVIEW — so the aggregate check catches it.
    """
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)

    drifted = dict(VERDICTS_TYPICAL)
    drifted["no-unapproved-scope-change"] = ("UNCLEAR", "")
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(drifted))

    assert direct_vm.run_validator() is False


def test_validator_rejects_forged_leader_evidence(contract, direct_vm):
    """
    The malicious-leader case.

    The leader fabricates a FATAL failure out of nothing: it reports FAIL citing text
    that does not exist in the subject. The payload is perfectly well-formed — valid
    JSON, known clause IDs, legal enum values, non-empty evidence string — so a
    format-only validator accepts it. This one rejects it, because it derived PASS
    for that clause itself and a PASS<->FAIL contradiction is never tolerable.

    See `test_validator_rejects_forgery_it_cannot_detect_by_disagreement` for the
    harder case, where the verdicts agree and only the citation is fake.
    """
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)

    forged = {
        clause_id: {
            "verdict": verdict,
            "evidence": evidence,
            "rationale": "forged",
        }
        for clause_id, (verdict, evidence) in VERDICTS_TYPICAL.items()
    }
    forged["deliverable-shipped"] = {
        "verdict": "FAIL",
        "evidence": "the team confirmed nothing was ever delivered",  # not in SUBJECT
        "rationale": "forged",
    }

    assert direct_vm.run_validator(leader_result=forged) is False


def test_validator_rejects_forgery_it_cannot_detect_by_disagreement(contract, direct_vm):
    """
    Grounding in isolation — the case only check 3 can catch.

    Here the leader's verdict vector matches the validator's exactly: both find the
    scope-change clause FAILing. Verdict comparison is clean, drift is zero, and both
    vectors aggregate to the same REJECTED outcome. The only defect is the citation —
    the leader attached a quote that is nowhere in the pinned subject.

    Every other guard passes this payload through. If the evidence check were removed,
    a leader could attribute real failures to invented text, and the fabricated quote
    would be what reviewers and downstream contracts read out of `get_ruling`.
    """
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)

    forged = {
        clause_id: {
            "verdict": verdict,
            "evidence": evidence,
            "rationale": "same verdicts, fake citation",
        }
        for clause_id, (verdict, evidence) in VERDICTS_TYPICAL.items()
    }
    # Same FAIL the validator independently derives — but sourced to text that
    # does not exist in SUBJECT.
    forged["no-unapproved-scope-change"]["evidence"] = (
        "the team unilaterally rewrote the entire architecture in secret"
    )

    assert direct_vm.run_validator(leader_result=forged) is False


def test_validator_rejects_leader_that_drops_a_clause(contract, direct_vm):
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)

    truncated = {
        clause_id: {
            "verdict": verdict,
            "evidence": evidence,
            "rationale": "partial",
        }
        for clause_id, (verdict, evidence) in VERDICTS_TYPICAL.items()
    }
    del truncated["budget-disclosed"]

    assert direct_vm.run_validator(leader_result=truncated) is False


def test_validator_rejects_non_dict_leader_result(contract, direct_vm):
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)
    assert direct_vm.run_validator(leader_result="APPROVED") is False


def test_validator_disagrees_when_leader_errored_but_it_succeeded(contract, direct_vm):
    adjudicated(contract, direct_vm, VERDICTS_TYPICAL)
    assert direct_vm.run_validator(leader_error=RuntimeError("boom")) is False


# The drift allowance is a secondary guard. Whenever drift changes the outcome, the
# aggregate-equality check already catches it — so isolating the allowance needs a
# policy where drifting clauses are provably outcome-neutral: several ADVISORY
# interpretive clauses, where UNCLEAR neither fails nor blocks.

DRIFT_CLAUSES = [
    ("core", "INTERPRETIVE", "FATAL", "The report must state the deliverable shipped.", ""),
    ("style-a", "INTERPRETIVE", "ADVISORY", "The report should mention throughput.", ""),
    ("style-b", "INTERPRETIVE", "ADVISORY", "The report should mention infra spend.", ""),
    ("style-c", "INTERPRETIVE", "ADVISORY", "The report should link to a demo.", ""),
]

DRIFT_ALL_PASS = {c[0]: ("PASS", "") for c in DRIFT_CLAUSES}


def drift_scenario(contract, direct_vm, validator_view):
    build_policy(contract, "drift", clauses=DRIFT_CLAUSES)
    direct_vm.mock_llm(r".*", llm_json(DRIFT_ALL_PASS))
    case_id = contract.submit("drift", SUBJECT, "")
    contract.adjudicate(case_id)
    assert contract.get_outcome(case_id) == "APPROVED"

    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(validator_view))
    return direct_vm.run_validator()


def test_validator_tolerates_one_outcome_neutral_drift(contract, direct_vm):
    view = dict(DRIFT_ALL_PASS)
    view["style-a"] = ("UNCLEAR", "")
    assert drift_scenario(contract, direct_vm, view) is True


def test_validator_rejects_two_drifts_even_when_outcome_is_unchanged(contract, direct_vm):
    """
    Both sides still aggregate to APPROVED, so only MAX_DRIFT_CLAUSES can catch this.

    Drift that cannot change the outcome is still evidence the clause is worded too
    loosely for the model to answer stably. Past the allowance the validator disagrees,
    which forces a retry rather than quietly recording a coin-flip ruling.
    """
    view = dict(DRIFT_ALL_PASS)
    view["style-a"] = ("UNCLEAR", "")
    view["style-b"] = ("UNCLEAR", "")
    assert drift_scenario(contract, direct_vm, view) is False


def test_invented_clause_ids_do_not_count_toward_usability(contract, direct_vm):
    """
    Invented clause IDs are dropped at parse time, not merely at storage time.

    The model answers *only* a clause that does not exist. If the phantom survived
    parsing it would look like a real decision and make an otherwise empty response
    seem usable; because it is discarded, every real clause is a contract-supplied
    default and the leader correctly reports that nothing came back.
    """
    build_policy(contract)
    direct_vm.mock_llm(r".*", llm_json({"phantom-clause": ("PASS", "")}))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    with direct_vm.expect_revert("LLM_ERROR"):
        contract.adjudicate(case_id)


# --------------------------------------- 6. underdetermined cases vs. model failures
#
# An all-UNCLEAR verdict vector has two possible causes that look identical once
# parsed, and the contract must treat them oppositely:
#
#   - the model read the subject and could not decide  -> a real ruling, NEEDS_REVIEW
#   - the model returned nothing usable                -> [LLM_ERROR], retry
#
# These tests pin both directions, since collapsing them is what previously stranded
# a fully underdetermined case at PENDING until its attempts ran out.


VERDICTS_ALL_UNCLEAR = {clause_id: ("UNCLEAR", "") for clause_id in INTERPRETIVE_IDS}


def test_complete_unclear_vector_settles_into_needs_review(contract, direct_vm):
    """
    A subject that settles nothing is a reviewable outcome, not a failure.

    Every interpretive clause comes back explicitly UNCLEAR. That is a legitimate
    reading — the pinned text simply does not answer these questions — so the ruling is
    recorded and `_aggregate` routes the blocking UNCLEARs to NEEDS_REVIEW.
    """
    build_policy(contract)
    direct_vm.mock_llm(r".*", llm_json(VERDICTS_ALL_UNCLEAR))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    assert ruling["outcome"] == "NEEDS_REVIEW"
    assert contract.get_outcome(case_id) == "NEEDS_REVIEW"

    # The full vector is stored, not just the blocking clauses — a reviewer needs to
    # see that every clause was considered and none was decided.
    assert {r["clause_id"] for r in ruling["rulings"]} == {c[0] for c in CLAUSES}
    interpretive = [r for r in ruling["rulings"] if r["clause_id"] in INTERPRETIVE_IDS]
    assert all(r["verdict"] == "UNCLEAR" for r in interpretive)
    assert all(r["evidence"] == "" for r in interpretive)

    # It counted as a real attempt and is dated, unlike a retried model failure.
    assert ruling["attempts"] == 1
    assert ruling["decided_at"].startswith("2026-03-20")


def test_underdetermined_case_reaches_consensus_rather_than_retrying(contract, direct_vm):
    """
    The settling path has to survive the validator, not just the leader.

    Both sides independently derive an all-UNCLEAR vector and must agree: no verdict
    differs, so no drift is spent, and both aggregate to NEEDS_REVIEW.
    """
    adjudicated(contract, direct_vm, VERDICTS_ALL_UNCLEAR)
    assert direct_vm.run_validator() is True


def test_one_decided_clause_makes_a_partial_response_usable(contract, direct_vm):
    """
    Partial responses are already legitimate, so one real verdict is enough.

    The model answers a single clause and omits the rest. The omissions fail closed to
    UNCLEAR as always; the response still contains a decision, so it is recorded.
    """
    build_policy(contract)
    direct_vm.mock_llm(r".*", llm_json({"budget-disclosed": ("UNCLEAR", "")}))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    assert contract.get_outcome(case_id) == "NEEDS_REVIEW"


def test_illegal_verdict_values_everywhere_are_a_model_failure(contract, direct_vm):
    """
    UNCLEAR the contract substituted is not UNCLEAR the model chose.

    Every clause carries a value outside the enum. Each one still fails closed to
    UNCLEAR, so the stored vector would be indistinguishable from a genuine
    all-UNCLEAR reading — but nothing here was decided, so this must retry.
    """
    build_policy(contract)
    payload = {clause_id: ("DEFINITELY_YES", "") for clause_id in INTERPRETIVE_IDS}
    direct_vm.mock_llm(r".*", llm_json(payload))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    with direct_vm.expect_revert("LLM_ERROR"):
        contract.adjudicate(case_id)


def test_wholly_fabricated_failures_are_a_model_failure(contract, direct_vm):
    """
    A response whose every citation was invented has nothing the contract accepted.

    Each clause comes back FAIL quoting text absent from the subject, so grounding
    downgrades all of them to UNCLEAR. Recording that as NEEDS_REVIEW would let total
    fabrication settle as a routine outcome; a retry may yet produce a real answer.
    """
    build_policy(contract)
    payload = {
        clause_id: ("FAIL", "the team admitted to falsifying the entire budget report")
        for clause_id in INTERPRETIVE_IDS
    }
    direct_vm.mock_llm(r".*", llm_json(payload))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    with direct_vm.expect_revert("LLM_ERROR"):
        contract.adjudicate(case_id)


def test_one_grounded_failure_survives_amid_fabrications(contract, direct_vm):
    """
    The usability test asks whether *anything* was accepted, not whether all was.

    One clause cites real text; the others fabricate. The fabrications are downgraded
    and the grounded FAIL stands, so the case is decided rather than retried — and on a
    MAJOR clause with no allowance, that means REJECTED.
    """
    build_policy(contract)
    payload = {
        clause_id: ("FAIL", "the team admitted to falsifying the entire budget report")
        for clause_id in INTERPRETIVE_IDS
    }
    payload["no-unapproved-scope-change"] = (
        "FAIL",
        "replaced the originally agreed Postgres backend with ClickHouse without",
    )
    direct_vm.mock_llm(r".*", llm_json(payload))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    assert ruling["outcome"] == "REJECTED"
    scope = next(r for r in ruling["rulings"] if r["clause_id"] == "no-unapproved-scope-change")
    assert scope["verdict"] == "FAIL"


def test_empty_verdict_list_is_a_model_failure(contract, direct_vm):
    """A well-formed envelope carrying no verdicts decided nothing."""
    build_policy(contract)
    direct_vm.mock_llm(r".*", json.dumps({"verdicts": []}))

    case_id = contract.submit("grant-milestone", SUBJECT, "")
    with direct_vm.expect_revert("LLM_ERROR"):
        contract.adjudicate(case_id)


def test_underdetermined_case_can_be_readjudicated_once_clarified(contract, direct_vm):
    """
    Settling into NEEDS_REVIEW must not be a dead end.

    An underdetermined case stays open to re-adjudication, so the same pinned subject
    can be re-run against a better model without forking the policy or resubmitting.
    """
    build_policy(contract)
    direct_vm.mock_llm(r".*", llm_json(VERDICTS_ALL_UNCLEAR))
    case_id = contract.submit("grant-milestone", SUBJECT, "")
    contract.adjudicate(case_id)
    assert contract.get_outcome(case_id) == "NEEDS_REVIEW"

    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*", llm_json(VERDICTS_ALL_CLEAN))
    contract.adjudicate(case_id)

    ruling = contract.get_ruling(case_id)
    assert ruling["outcome"] == "APPROVED"
    assert ruling["attempts"] == 2
    # Rewritten wholesale: no UNCLEAR rows left over from the first pass.
    assert all(r["verdict"] != "UNCLEAR" for r in ruling["rulings"])
