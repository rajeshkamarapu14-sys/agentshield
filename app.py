"""
app.py — Deployable FastAPI service for AgentShield.

Exposes the firewall over HTTP so it can be containerised and deployed (e.g. to
Google Cloud Run). Endpoints:

  GET  /            — health + one-line summary (HTML)
  GET  /tools       — MCP-style tool manifest
  POST /inspect     — run a request through the firewall, get the decision
  GET  /audit       — audit-trail summary
  GET  /healthz     — liveness probe

Run locally:  uvicorn app:app --reload --port 8080
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from common import ToolCall
from config import CONFIG
from firewall import AgentShield
from tools.mcp_server import list_tools
from agents import AuditReporterAgent, JudgeAgent

app = FastAPI(
    title="AgentShield",
    description="Prompt-Injection Firewall for Secure AI Support Agents",
    version="1.0.0",
)


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    """Reject over-large request bodies with 413 before parsing (fail-closed)."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > CONFIG.max_api_body_bytes:
        return JSONResponse(
            status_code=413,
            content={"decision": "block", "status": "blocked", "tool_executed": False,
                     "reason_codes": ["input_too_large", "resource_exhaustion_protection"],
                     "detail": f"request body exceeds {CONFIG.max_api_body_bytes} bytes"})
    return await call_next(request)

_firewall = AgentShield(log=True)
_judge = JudgeAgent()
_reporter = AuditReporterAgent()


class InspectRequest(BaseModel):
    user_input: str = ""
    context: str = ""
    context_source: str = "customer_ticket"
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = {}
    final_output: Optional[str] = None
    expected_decision: Optional[str] = None  # optional, enables judge scoring


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    summary = _reporter.summarize()
    return f"""
    <html><head><title>AgentShield</title></head>
    <body style="font-family:system-ui;max-width:720px;margin:40px auto;">
    <h1>🛡 AgentShield</h1>
    <p><b>Prompt-Injection Firewall for Secure AI Support Agents.</b>
    Inspects user input, retrieved documents, planned tool calls, and final output
    before any risky action runs.</p>
    <p>Decisions logged so far: <b>{summary['total']}</b> — {summary['by_decision']}</p>
    <ul>
      <li><code>GET /tools</code> — tool manifest</li>
      <li><code>POST /inspect</code> — inspect a request</li>
      <li><code>GET /audit</code> — audit summary</li>
      <li><code>GET /docs</code> — OpenAPI UI</li>
    </ul>
    </body></html>
    """


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/tools")
def tools() -> Dict[str, Any]:
    return {"tools": list_tools()}


@app.post("/inspect")
def inspect(req: InspectRequest) -> Dict[str, Any]:
    tool_call = ToolCall(req.tool_name, req.tool_args) if req.tool_name else None
    result = _firewall.inspect(
        user_input=req.user_input,
        context=req.context,
        context_source=req.context_source,
        tool_call=tool_call,
        final_output=req.final_output,
        session_id="api",
        user_request_summary=req.user_input[:80],
    )
    out: Dict[str, Any] = {
        "decision": result.decision.value,
        "reasons": result.reasons,
        "detected_risks": [r.to_dict() for r in result.detected_risks],
        "stages": [s.to_dict() for s in result.stages],
    }
    # JudgeAgent always runs its independent soundness audit; the expected
    # decision (if provided) additionally enables answer-key scoring.
    j = _judge.audit(result, expected=req.expected_decision)
    out["judge"] = j.to_dict()
    return out


@app.get("/audit")
def audit() -> Dict[str, Any]:
    return _reporter.summarize()
