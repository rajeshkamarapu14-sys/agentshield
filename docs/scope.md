# AgentShield — Project Scope

## One-line
A **prompt-injection firewall** that sits in front of a tool-using AI support
agent, inspecting everything it reads and every action it plans before any risky
operation runs.

## Goal
Let businesses safely deploy AI support agents by **detecting prompt injection,
blocking unsafe tool calls, enforcing policy, redacting secrets, logging every
decision, and self-evaluating** with synthetic red-team cases.

- **Competition:** AI Agents Intensive Vibe Coding Capstone (Google × Kaggle)
- **Track:** Agents for Business
- **Deadline:** 2026-07-06 11:59 PM PT

## Product story
> "AgentShield helps businesses safely deploy tool-using AI agents by detecting
> prompt injection, blocking unsafe tool calls, enforcing policy, logging
> decisions, and running security evals."

---

## In scope ✅

### Core capability
- 4-stage, **fail-closed** firewall inspecting: **input → retrieved content →
  planned tool call → final output** (most-restrictive decision wins).
- Five decisions: `allow` · `block` · `sanitize` · `require_human_approval` ·
  `ask_clarification`.
- Detection across the **five injection sources**: customer ticket, uploaded
  attachment, knowledge-base doc, email thread history, and tool/API response.

### Multi-agent system
- **SupportAgent** — the protected, tool-using agent (untrusted by design).
- **InjectionDetectorAgent** — direct & indirect injection detection.
- **ToolPolicyAgent** — external email / CRM / bulk / unknown-tool policy.
- **RedTeamAgent** — generates synthetic attack cases for evals.
- **JudgeAgent** — LLM-as-judge scoring (rubric 1–5, pass/fail/review).
- **AuditReporterAgent** — renders the JSONL audit trail as a report.

### Tools & guardrails
- **12 dry-run tools** (search/attachment/email-thread/customer-lookup/tickets/
  business-profile reads, plus draft-reply, dry-run email/CRM/refund, create-ticket,
  and security-policy) behind a **firewall-gated** tool layer,
  exposed both in-process and via a **real MCP stdio server** (official MCP SDK).
- **Real on-disk attachments** (`data/attachments/`) — `read_attachment` reads
  genuine files (path-traversal guarded); poisoned files exercise the firewall.
- Deterministic guardrails: injection rules, sensitive-data detection/redaction,
  policy engine, output guardrail.

### Evals, logs, tests
- **47 eval cases** (5 allow · 5 direct-block · 5 indirect · 3 approval · 2
  clarify + 20 obfuscation/disclosure/data-model/redaction cases) → **47/47 passing, avg judge 5.0/5**.
- **Append-only JSONL audit trail** (`logs/audit_log.jsonl`).
- **197 pytest tests** (guardrails, disclosure, tools, data model, full eval sweep).

### Google integration & deployability
- Real Google **ADK** `LlmAgent` (`adk_agent.py`) with firewall-gated tools.
- Optional **Gemini** judge/detector (`gemini_client.py`, `check_gemini.py`).
- **FastAPI** service (`app.py`), **Dockerfile**, **Cloud Run** deploy
  (`deploy/cloudrun.sh`).
- Concepts demonstrated: multi-agent (incl. ADK) · MCP (in-process registry + real stdio server) · security
  guardrails · deployability · LLM-as-judge · audit trail.

---

## Out of scope ❌
- **No real side effects** — no real emails, CRM writes, network calls, or
  customer data. Every risky tool is **dry-run**; all example data is synthetic.
- **No secrets in code** — `.env.example` holds variable names only; `.env` is
  gitignored.
- **Not a full cybersecurity platform** — detection is rule-based; optional Gemini
  detection can advise/escalate but never overrides the deterministic decision;
  a trained classifier is future work.
- **No defense against adversarially-optimized/novel phrasings** or multi-turn
  social engineering (documented as future work).
- **Relevance checking is heuristic**, not exhaustive.
- **Every Google/LLM path is optional** — the system runs 100% offline and
  deterministically with no API key.

---

## Deliverables & status

| Deliverable | Status |
|---|---|
| Deterministic firewall core (guardrails, policy engine) | ✅ Complete & verified |
| 6-agent multi-agent system | ✅ Complete |
| 12 dry-run tools + in-process registry | ✅ Complete |
| Real MCP stdio server (official SDK) + client smoke test | ✅ Complete & verified |
| Real on-disk attachments (path-traversal guarded) | ✅ Complete & verified |
| 47 eval cases + runner (47/47) | ✅ Complete |
| JSONL audit trail | ✅ Complete |
| 197 pytest tests | ✅ Passing |
| Terminal demo (`demo.py`) | ✅ Complete |
| FastAPI API (`app.py`) | ✅ Complete & tested |
| Real Google ADK agent | ✅ Complete (constructs offline) |
| Optional Gemini judge/detector | ✅ Wired (needs key to run) |
| Docker + Cloud Run deploy files | ✅ Complete |
| README + architecture + demo-script + scope docs | ✅ Complete |
| Public GitHub repo | ⏳ Pending (git setup with new email) |
| Kaggle writeup (≤2,500 words) | ⏳ To draft |
| ≤5-min YouTube video | ⏳ To record (script ready) |
| Cover image | ⏳ To create |
| Live Gemini key / Cloud Run deploy | ⏳ Optional (user credentials) |

---

## Definition of done
- A judge understands the project in ~30 seconds.
- Terminal demo works; eval runner works; ≥20 test cases; ≥5 injection sources.
- Logs generated; README strong; public GitHub repo clean; no secrets committed.
- Clear Kaggle writeup and video story.
