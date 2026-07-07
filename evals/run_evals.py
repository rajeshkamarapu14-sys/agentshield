"""
run_evals.py — Run the security eval suite against the firewall.

Loads evals/test_cases.json, pushes every case through AgentShield, has the
JudgeAgent score each decision against its expectation, prints a pass/fail summary
table, and writes evals/results.json. All audit records land in
logs/audit_log.jsonl (the log is cleared first for a clean run).

Usage:
    python evals/run_evals.py            # deterministic, offline
    AGENTSHIELD_USE_LLM_JUDGE=true python evals/run_evals.py   # + Gemini judge

Exit code is non-zero if any case fails, so this doubles as a CI gate.
"""

from __future__ import annotations

import json
import os
import sys

# Make the project root importable when run as `python evals/run_evals.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import Case, Decision  # noqa: E402
from firewall import AgentShield  # noqa: E402
from agents import JudgeAgent  # noqa: E402
from audit import clear as clear_audit  # noqa: E402

try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
except Exception:  # pragma: no cover
    _RICH = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_PATH = os.path.join(ROOT, "evals", "test_cases.json")
RESULTS_PATH = os.path.join(ROOT, "evals", "results.json")


def load_cases():
    with open(CASES_PATH, "r", encoding="utf-8") as fh:
        return [Case.from_dict(d) for d in json.load(fh)]


def run(llm_judge: bool = False, llm_detector: bool = False, limit: int = 0):
    clear_audit()  # fresh audit trail for this run
    firewall = AgentShield(log=True, use_llm_detector=llm_detector or None)
    judge = JudgeAgent(use_llm=llm_judge or None)
    cases = load_cases()
    if limit and limit > 0:
        cases = cases[:limit]        # cap the run (e.g. a small live-Gemini test)

    rows = []
    passed = 0
    from collections import Counter
    from common import DECISION_SEVERITY, Decision
    total_score = 0
    unsafe_allow = 0      # firewall was TOO PERMISSIVE vs expected (dangerous)
    overblock = 0         # firewall was stricter than expected but safe
    decisions = Counter()
    reason_codes = set()
    review_queue = []
    for case in cases:
        result = firewall.inspect_case(case)
        j = judge.audit(result, expected=case.expected_decision)   # soundness + expected
        ok = result.decision.value == case.expected_decision
        passed += int(ok)
        total_score += j.score
        decisions[result.decision.value] += 1
        entry = result.audit_dict()
        reason_codes.update(entry.get("reason_codes", []))

        # over-permissive vs over-strict (vs expected)
        try:
            diff = DECISION_SEVERITY[result.decision] - DECISION_SEVERITY[Decision(case.expected_decision)]
            if diff < 0:
                unsafe_allow += 1
            elif diff > 0:
                overblock += 1
        except (ValueError, KeyError):
            pass

        needs_review = j.needs_review or (not ok)
        row = {
            "case_id": case.case_id, "title": case.title, "source": case.source,
            "expected": case.expected_decision, "actual": result.decision.value,
            "match": ok, "judge_score": j.score, "verdict": j.verdict,
            "judged_by": j.judged_by, "judge_reason": j.reason,
            "needs_review": needs_review, "issues": j.issues,
            "reason": "; ".join(result.reasons[:2]),
        }
        rows.append(row)
        if needs_review:
            review_queue.append({"case_id": case.case_id, "actual": result.decision.value,
                                 "expected": case.expected_decision, "score": j.score,
                                 "verdict": j.verdict, "judged_by": j.judged_by,
                                 "issues": j.issues, "judge_reason": j.reason})

    summary = {
        "total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
        "accuracy": round(passed / len(cases), 3) if cases else 0.0,
        "avg_judge_score": round(total_score / len(cases), 2) if cases else 0.0,
        "unsafe_allow_count": unsafe_allow,
        "overblock_count": overblock,
        "review_queue_count": len(review_queue),
        "reason_code_coverage": len(reason_codes),
        "decision_distribution": dict(decisions),
        "judge_backend": "gemini" if judge.use_llm else "rules",
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "review_queue": review_queue, "results": rows},
                  fh, indent=2)

    _print(rows, summary, review_queue)
    return summary


def _print(rows, summary, review_queue):
    if _RICH:
        console = Console()
        table = Table(title="AgentShield — Security Eval Results", show_lines=False)
        for c in ("Case", "Source", "Expected", "Actual", "✓", "Score", "Rev"):
            table.add_column(c, justify="center" if c in ("✓", "Score", "Rev") else "left",
                             style="cyan" if c == "Case" else ("dim" if c == "Source" else None),
                             no_wrap=(c == "Case"))
        for r in rows:
            mark = "[green]✓[/green]" if r["match"] else "[red]✗[/red]"
            st = "green" if r["match"] else "red"
            rev = "[yellow]![/yellow]" if r["needs_review"] else ""
            table.add_row(r["case_id"], r["source"], r["expected"],
                          f"[{st}]{r['actual']}[/{st}]", mark, str(r["judge_score"]), rev)
        console.print(table)
        color = "green" if summary["failed"] == 0 else "yellow"
        console.print(
            f"\n[bold {color}]Passed {summary['passed']}/{summary['total']} "
            f"({summary['accuracy']*100:.0f}%)  |  avg judge {summary['avg_judge_score']}/5  |  "
            f"judge={summary['judge_backend']}[/bold {color}]")
        console.print(
            f"[dim]unsafe_allow={summary['unsafe_allow_count']}  "
            f"overblock={summary['overblock_count']}  "
            f"review_queue={summary['review_queue_count']}  "
            f"reason_codes={summary['reason_code_coverage']}  "
            f"decisions={summary['decision_distribution']}[/dim]")
        if review_queue:
            console.print("[yellow]Review queue:[/yellow]")
            for q in review_queue:
                why = q.get("judge_reason") or (", ".join(q["issues"]) if q["issues"] else "")
                console.print(f"  [yellow]![/yellow] {q['case_id']}: {q['actual']} "
                              f"(exp {q['expected']}) score={q['score']} "
                              f"[{q.get('judged_by','rules')}] {why}")
    else:
        for r in rows:
            print(f"{r['case_id']:<24} {r['expected']:<22} {r['actual']:<22} "
                  f"{'Y' if r['match'] else 'N'}  {r['judge_score']}  "
                  f"{'REVIEW' if r['needs_review'] else ''}")
        print(f"\nPassed {summary['passed']}/{summary['total']} "
              f"({summary['accuracy']*100:.0f}%) | avg judge {summary['avg_judge_score']}/5 "
              f"| judge={summary['judge_backend']}")
        print(f"unsafe_allow={summary['unsafe_allow_count']} "
              f"overblock={summary['overblock_count']} "
              f"review_queue={summary['review_queue_count']} "
              f"reason_codes={summary['reason_code_coverage']}")


if __name__ == "__main__":
    # Flags let you flip on the live Gemini paths without env-var syntax:
    #   python evals/run_evals.py --llm-judge         (Gemini scores each case)
    #   python evals/run_evals.py --llm-judge --llm-detector
    #   python evals/run_evals.py --llm-judge --limit 5   (only 5 cases = 5 calls)
    argv = sys.argv[1:]
    limit = 0
    if "--limit" in argv:
        try:
            limit = int(argv[argv.index("--limit") + 1])
        except (IndexError, ValueError):
            print("--limit needs a number, e.g. --limit 5"); sys.exit(2)
    s = run(llm_judge="--llm-judge" in argv,
            llm_detector="--llm-detector" in argv,
            limit=limit)
    sys.exit(0 if s["failed"] == 0 else 1)
