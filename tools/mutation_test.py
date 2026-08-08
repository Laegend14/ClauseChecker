"""
Mutation test for the ClauseCheck consensus guards.

A passing test suite proves the code works on the cases you thought of. It does not
prove the tests would notice if a guard were removed. This script checks that directly:
it disables each consensus check in turn, re-runs the suite, and reports whether the
suite caught it.

A surviving mutant means the guard is either untested or redundant. Every mutant here
is expected to be KILLED.

Run from the repository root:

    python tools/mutation_test.py

The original contract is restored on exit, including on Ctrl-C or crash.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contracts" / "ClauseCheck.py"


# Each mutant is (name, find, replace). `find` must match the current contract source
# exactly once — the script refuses to run a mutant whose anchor has drifted, so a
# refactor cannot silently turn this into a no-op.
MUTANTS = [
    (
        "validator skips independent re-derivation",
        "            mine = leader_fn()\n"
        "            theirs = leader_result.calldata\n",
        "            theirs = leader_result.calldata\n"
        "            mine = theirs if isinstance(theirs, dict) else {}\n",
    ),
    (
        "PASS<->FAIL contradiction tolerated",
        "                if VERDICT_UNCLEAR not in (their_verdict, my_verdict):\n"
        "                    return False\n",
        "                if False:\n"
        "                    return False\n",
    ),
    (
        "FATAL clauses lose zero-tolerance",
        "                if severities.get(clause_id) == SEV_FATAL:\n"
        "                    return False\n",
        "                if False:\n"
        "                    return False\n",
    ),
    (
        "drift allowance removed (unbounded drift)",
        "                drift += 1\n"
        "                if drift > MAX_DRIFT_CLAUSES:\n"
        "                    return False\n",
        "                drift += 1\n",
    ),
    (
        "validator stops grounding leader evidence",
        "                if not _quote_is_grounded(subject, their_entry.get(\"evidence\", \"\")):\n"
        "                    return False\n",
        "                if False:\n"
        "                    return False\n",
    ),
    (
        "aggregate equality check removed",
        "            return _aggregate(their_flat, severities, max_major) == _aggregate(\n"
        "                my_flat, severities, max_major\n"
        "            )\n",
        "            return True\n",
    ),
    (
        "leader grounding removed (ungrounded FAIL reaches storage)",
        "        if verdict == VERDICT_FAIL and not _quote_is_grounded(subject, evidence):\n",
        "        if False:\n",
    ),
    (
        "omitted clauses no longer fail closed",
        "    for clause_id in clause_ids:\n"
        "        if clause_id not in parsed:\n",
        "    for clause_id in []:\n"
        "        if clause_id not in parsed:\n",
    ),
    (
        "unknown clause ids accepted from model",
        "        if not isinstance(clause_id, str) or clause_id not in known:\n",
        "        if not isinstance(clause_id, str):\n",
    ),
    (
        "ADVISORY failures block approval",
        "            elif severity == SEV_MAJOR:\n"
        "                major_failures += 1\n",
        "            else:\n"
        "                major_failures += 1\n",
    ),
]


def run_suite() -> tuple[bool, str]:
    """Run pytest; return (passed, one-line summary)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    tail = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    summary = tail[-1] if tail else "no output"
    return proc.returncode == 0, summary.strip()


def main() -> int:
    original = CONTRACT.read_text(encoding="utf-8")

    print("Baseline (unmutated contract):")
    passed, summary = run_suite()
    print(f"  {summary}")
    if not passed:
        print("\nBaseline suite is already failing. Fix that before mutation testing.")
        return 1

    survivors = []
    try:
        for name, find, replace in MUTANTS:
            occurrences = original.count(find)
            if occurrences != 1:
                print(f"\n[SKIP   ] {name}")
                print(f"           anchor matched {occurrences} times, expected 1 — update the mutant")
                survivors.append(name + " (anchor drifted)")
                continue

            CONTRACT.write_text(original.replace(find, replace), encoding="utf-8", newline="\n")
            passed, summary = run_suite()
            status = "SURVIVED" if passed else "KILLED  "
            print(f"\n[{status}] {name}")
            print(f"           {summary}")
            if passed:
                survivors.append(name)
    finally:
        CONTRACT.write_text(original, encoding="utf-8", newline="\n")

    print("\n" + "=" * 78)
    if survivors:
        print(f"{len(survivors)} of {len(MUTANTS)} mutants SURVIVED — these guards are untested:")
        for name in survivors:
            print(f"  - {name}")
        return 1

    print(f"All {len(MUTANTS)} mutants killed. Every consensus guard is load-bearing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
