# AgentShield — Architecture

## Overview

AgentShield is a **fail-closed firewall** wrapped around a tool-using support
agent. The support agent may be manipulated by injected content; the firewall
inspects everything the agent reads and everything it wants to do, and returns a
single decision before any risky action executes.

## Request lifecycle

```
Case / API request
   │
   ├─ Stage 1  INPUT     evaluate_text(user_input, source=customer_ticket)
   │                     + optional Gemini detector
   ├─ Stage 2  CONTEXT   evaluate_text(retrieved_doc, source=attachment|kb|email|tool_response)
   │                     + optional Gemini detector
   ├─ Stage 3  TOOL      evaluate_tool_call(planned_call, user_input)
   ├─ Stage 4  OUTPUT    evaluate_output(drafted_reply)      (optional)
   │
   ▼
most_restrictive(stages)  ──►  final Decision
   │
   ├─►  audit.write_entry(...)          → logs/audit_log.jsonl
   └─►  JudgeAgent.score(...)           → rubric 1–5 / pass|fail|review
```

`most_restrictive` uses a severity ordering
(`allow < ask_clarification < sanitize < require_human_approval < block`) so a
single `block` anywhere overrides everything else.

## Components

| Layer | Files | Role |
|---|---|---|
| Data model | `common.py` | `Decision`, `Source`, `RiskFinding`, `FirewallDecision`, `ToolCall`, `Case` |
| Guardrails (deterministic) | `guardrails/injection_rules.py`, `sensitive_data.py`, `policy_engine.py`, `output_guardrail.py` | detection + the five-way decision |
| Tools | `tools/*.py`, `tools/mcp_server.py` | 12 dry-run tools + firewall-gated MCP-style dispatcher |
| Agents | `agents/*.py` | multi-agent system (support, detector, policy, red-team, judge, reporter) |
| Orchestration | `firewall.py` | runs the 4 stages, merges, logs |
| Optional LLM | `gemini_client.py`, `config.py` | Gemini second opinion, gated on `GEMINI_API_KEY` |
| Interfaces | `demo.py`, `app.py`, `evals/run_evals.py` | CLI demo, FastAPI service, eval runner |

## Design decision: deterministic guardrails for core security

AgentShield **separates reasoning from enforcement**. LLM agents are used for
planning, language understanding, judging, and advisory review; the
**deterministic firewall is the final security gatekeeper**. This is intentional:
the security boundary must be predictable, auditable, and resistant to prompt
injection. An LLM can help *understand* context, but it should not be the only
component deciding whether a risky tool call, data disclosure, refund, CRM
update, or outbound message is safe — especially because that context (retrieved
documents, email threads, tool outputs) can itself carry injected instructions.

### Why deterministic agents are best for core enforcement

Deterministic agents use explicit rules, signatures, allowlists, parameter
validation, redaction policies, and approval gates. They are well suited to being
the security boundary because they provide:

- **No policy hallucination** — they do not invent new security rules or
  reinterpret policy differently on each run.
- **Consistency** — the same input and policy configuration produce the same
  decision every time. This is also what makes the eval suite reproducible.
- **Auditability & compliance** — each decision can include reason codes, risk
  scores, and structured audit logs explaining exactly why an action was allowed,
  blocked, sanitized, or sent for human approval.
- **Fail-closed behavior** — when a request is risky, ambiguous, or outside
  policy, the firewall blocks, sanitizes, asks for clarification, or requires
  human approval instead of silently allowing the action.
- **Speed** — rule-based checks run quickly, *before* a tool executes, which is
  what allows unsafe actions to be blocked in real time.
- **Safe tool control** — allowlists, argument validation, refund thresholds,
  CRM-field restrictions, and sensitive-data redaction are naturally expressed as
  deterministic policy.

This mirrors how security is enforced elsewhere: firewall rules, IAM permission
checks, static scanners, vulnerability signatures, DLP rules, and policy-as-code.

### Where LLM agents add value

LLMs are genuinely useful in AgentShield — used where reasoning and language
understanding help, rather than as the final authority:

- **Support planning** — the SupportAgent (Google ADK / optional Gemini)
  understands a request and decides what support action may be needed.
- **Context interpretation** — summarizing KB articles, attachments, email
  threads, or tool results.
- **Advisory detection** — flagging suspicious language, indirect injection, or
  social-engineering patterns a simple signature might miss.
- **Incident explanation** — turning audit logs / red-team results into readable
  reports.
- **JudgeAgent review** — scoring firewall decisions and flagging cases for human
  review, while **never overriding the deterministic firewall**.

### The boundary

- The **SupportAgent** may use Google ADK and optional Gemini to understand and plan.
- The **JudgeAgent** (and optional Gemini) may score, explain, and flag decisions
  for review — but it can only hold or make a verdict *stricter*; it can never
  turn a deterministic `block` into an `allow`.
- The **deterministic firewall** makes the final allow / block / sanitize /
  approval / clarification decision, and risky tools never execute before its
  approval.

**Honest scope.** Deterministic rules are *predictable and auditable*, not
omniscient. They do not automatically catch every possible attack — real-world
coverage depends on the policy and the eval suite. Optional Gemini can help flag
novel phrasing, but it advises and escalates; it never overrides. The value of
this design is a firewall you can *reason about and audit*, combined with the
flexibility of LLM agents — without making an LLM the only line of defense.

## MCP-style tool layer

AgentShield ships the tool layer in **two forms**, both firewall-gated:

1. **In-process registry** (`tools/mcp_server.py`) — mirrors the MCP contract
   (each tool has a name, `inputSchema`, risk class, and manifest entry via
   `list_tools()` → `GET /tools`). Used by the demo/eval/API so they run with zero
   external processes. `call_tool()` asks the policy engine for a verdict and
   refuses to execute anything not cleared.
2. **Real MCP server** (`tools/mcp_stdio_server.py`) — a genuine Model Context
   Protocol server built on the official MCP Python SDK (`FastMCP`), speaking
   stdio transport. Any MCP client (an ADK `MCPToolset`, or
   `scripts/mcp_client_smoke.py`) can connect, list the 12 tools, and call them —
   and every call still routes through the same firewall. This is the same
   registry exposed over the wire; the tools are unchanged.

## Google integration (optional, documented)

- **Gemini**: `gemini_client.generate()` powers the optional LLM judge and the
  injection-detector second opinion. Enable with `GEMINI_API_KEY` +
  `AGENTSHIELD_USE_LLM_JUDGE=true` / `AGENTSHIELD_USE_LLM_DETECTOR=true`.
- **Google ADK** (`adk_agent.py`): a real ADK `LlmAgent` (Gemini-backed) exposing
  **13 `FunctionTool`s** — all **12** registry dry-run tools (each firewall-gated
  via `tools/mcp_server.call_tool`) plus a `check_content_for_injection` helper the
  model can call on untrusted content. The turn's user message is captured
  (contextvar) and threaded into every tool call, so the INPUT firewall runs at
  the ADK surface too. The agent constructs offline (no key); running it via
  `InMemoryRunner` needs Gemini/Vertex credentials. ADK wraps the deterministic
  core — it doesn't fork it.
- **Cloud Run** (`deploy/cloudrun.sh`, `.gcloudignore`): `Dockerfile` reads
  `$PORT`; deploy with `PROJECT_ID=... ./deploy/cloudrun.sh` (wraps
  `gcloud run deploy agentshield --source . --allow-unauthenticated`).

## Threat model & assumptions

- **In scope:** direct prompt injection, indirect injection via 5 sources,
  secret/PII exfiltration, unsafe/irrelevant/unknown tool calls, output leakage.
- **Out of scope (future work):** adversarially-optimized novel phrasings,
  multi-turn social engineering, model-level jailbreaks. Optional Gemini
  detection can help flag novel or ambiguous phrasing (it can only escalate to
  stricter, never loosen), but it does not override deterministic policy; a
  trained classifier is longer-term future work.
- **Assumption:** risky tools are dry-run; a production deployment would place
  real permissioned connectors behind the identical firewall interface.
