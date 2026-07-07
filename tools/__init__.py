"""AgentShield dry-run tool suite (MCP-style).

All tools are safe: reads return synthetic data, and every "risky" tool
(send_email, update_crm) only simulates its action. No real emails, CRM writes,
network calls, or secrets. See tools/mcp_server.py for the registry/dispatcher.
"""
