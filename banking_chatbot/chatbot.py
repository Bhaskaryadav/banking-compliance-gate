"""
Module 3 — Banking Chatbot (lab stub)
Extended in Module 6 Project 3 with PCI DSS compliance guardrails.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_client import get_llm_client, resolve_model

load_dotenv()

FINANCIAL_KEYWORDS = frozenset({
    "balance", "transfer", "account", "statement", "loan",
    "credit", "debit", "transaction", "payment",
})

AUDIT_LOG_PATH = Path("audit_log/chatbot_tool_calls.jsonl")

# Per-session query counters (keyed by session_id)
_session_counters: dict[str, int] = {}

RATE_LIMIT_MAX = 20


def pre_response_pii_filter(response: str) -> str:
    """Redact card and account numbers from response text (PCI DSS Req 3)."""
    response = re.sub(r"\b\d{13,19}\b", "[REDACTED-CARD]", response)
    response = re.sub(r"\b\d{8,12}\b", "[REDACTED-ACCT]", response)
    return response


def rate_limit_check(session_id: str) -> None:
    """Raise RuntimeError after 20 financial queries for a given session (PCI DSS Req 6)."""
    count = _session_counters.get(session_id, 0) + 1
    _session_counters[session_id] = count
    if count > RATE_LIMIT_MAX:
        raise RuntimeError(
            f"Rate limit exceeded for session {session_id}: "
            f"{count} queries (max {RATE_LIMIT_MAX})"
        )


def write_audit_log_entry(event: dict) -> None:
    """Append a sanitised JSONL entry to the chatbot audit log (PCI DSS Req 10)."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Sanitise any PII values before writing
    safe_event = json.loads(
        re.sub(r"\b\d{13,19}\b", "[REDACTED-CARD]",
               re.sub(r"\b\d{8,12}\b", "[REDACTED-ACCT]", json.dumps(event)))
    )
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(safe_event) + "\n")


def run_with_guardrails(user_message: str, session_id: str) -> str:
    """Chain rate-limit check → LLM call → audit log → PII filter."""
    rate_limit_check(session_id)
    response = call_claude(user_message)
    write_audit_log_entry({
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "session_id": session_id,
        "user_message": user_message,
        "response_length": len(response),
        "schema_version": "1.0",
    })
    return pre_response_pii_filter(response)


def is_financial_query(user_message: str) -> bool:
    """Return True if the message looks like a financial query."""
    tokens = set(user_message.lower().split())
    return bool(tokens & FINANCIAL_KEYWORDS)


def call_claude(user_message: str, tools: list[dict[str, Any]] | None = None) -> str:
    """Send a user message to Claude and return the text response."""
    client = get_llm_client()
    response = client.messages.create(
        model=resolve_model("claude-sonnet-4-5"),
        max_tokens=1024,
        tools=tools or [],
        messages=[{"role": "user", "content": user_message}],
    )
    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


def handle_message(user_message: str) -> str:
    """Basic chatbot handler — guardrails added in Module 6 Project 3."""
    return call_claude(user_message)


if __name__ == "__main__":
    print(handle_message("What services does Heritage National Bank offer?"))
