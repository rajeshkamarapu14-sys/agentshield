"""Tests for the synthetic customer/ticket data model and the lookup tools."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.mcp_server import call_tool  # noqa: E402
from tools._synthetic_data import CUSTOMERS, TICKETS, KNOWLEDGE_BASE  # noqa: E402


def test_fixtures_loaded():
    assert len(CUSTOMERS) >= 2
    assert len(TICKETS) >= 2
    assert len(KNOWLEDGE_BASE) >= 3


def test_no_full_card_stored_anywhere():
    """The store must hold last-4 only — never a full PAN. You cannot leak what
    you do not store."""
    blob = json.dumps(CUSTOMERS)
    # No customer field should be a 13-16 digit card number.
    for c in CUSTOMERS:
        assert "card_full" not in c
        assert len(str(c.get("card_last4", ""))) <= 4
    assert "4111111111111111" not in blob


def test_lookup_customer_redacts_sensitive_fields():
    r = call_tool("lookup_customer_dry_run", {"customer_id": "CUST-001"})
    text = r["result"]["text"]
    # sensitive fields redacted / masked
    assert "[REDACTED_DOB]" in text
    assert "[REDACTED_PHONE]" in text
    assert "[REDACTED_ADDRESS]" in text
    assert "alice.fake@example.com" not in text   # email masked
    # safe partial stays
    assert "1111" in text
    # raw sensitive values absent
    assert "1992-04-10" not in text


def test_lookup_unknown_customer():
    r = call_tool("lookup_customer_dry_run", {"customer_id": "CUST-999"})
    assert r["result"].get("error")


def test_list_tickets_returns_customer_tickets():
    r = call_tool("list_tickets_dry_run", {"customer_id": "CUST-001"})
    assert "TICK-001" in r["result"]["text"]


def test_lookup_is_firewall_allowed():
    r = call_tool("lookup_customer_dry_run", {"customer_id": "CUST-001"})
    assert r["firewall"]["decision"] == "allow"
    assert r["executed"] is True


def test_business_profile_served_via_tool():
    r = call_tool("get_business_profile_dry_run", {})
    assert r["executed"] is True
    prof = r["result"]["profile"]
    assert prof["company_name"] == "NovaCart Support"
    assert prof["country_code"] == "SG"
    assert prof["currency"] == "SGD"
    assert prof["refund_policy"]["human_approval_above"] == 500
    assert prof["data_handling"]["stores_full_card"] is False


def test_customers_have_country():
    for c in CUSTOMERS:
        assert c.get("country") == "Singapore"
