"""
Unit tests for src/agent/orchestrator.py.

External dependencies mocked:
  - _run_discovery_query  (Neo4j discovery queries in Phase 1)
  - litellm.completion    (LLM calls in Phase 2)
  - _estimate_tokens      (tiktoken)
"""

import os

os.environ.setdefault("NAVIGATOR_MODEL", "gpt-4o")
os.environ.setdefault("NAVIGATOR_API_BASE", "http://localhost:8000")

from unittest.mock import MagicMock, patch

import pytest

from src.agent.orchestrator import (
    _build_system_prompt,
    _discover_candidates,
    _parse_llm_output,
    investigate_event,
    investigate_window,
)


def _make_llm_response(content: str, tool_calls=None):
    mock_message = MagicMock()
    mock_message.tool_calls = tool_calls
    mock_message.content = content
    mock_message.model_dump.return_value = {"role": "assistant", "content": content}
    mock_choice = MagicMock()
    mock_choice.message = mock_message
    mock_choice.finish_reason = "stop" if tool_calls is None else "tool_calls"
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    return mock_response


# ===========================================================================
# _parse_llm_output
# ===========================================================================

class TestParseLlmOutput:
    def test_high_severity_parsed(self):
        text = "SEVERITY: HIGH\nFLAGGED_USERS: U620@DOM1\nFLAGGED_HOSTS: C1003\nNARRATIVE: Attack."
        severity, users, hosts = _parse_llm_output(text)
        assert severity == "HIGH"
        assert "U620@DOM1" in users
        assert "C1003" in hosts

    def test_low_severity_with_none_produces_empty_lists(self):
        text = "SEVERITY: LOW\nFLAGGED_USERS: NONE\nFLAGGED_HOSTS: NONE\nNARRATIVE: Clean."
        severity, users, hosts = _parse_llm_output(text)
        assert severity == "LOW"
        assert users == []
        assert hosts == []

    def test_no_severity_match_defaults_to_low(self):
        severity, users, hosts = _parse_llm_output("No structured output here.")
        assert severity == "LOW"

    def test_multiple_flagged_users_split_correctly(self):
        text = "SEVERITY: HIGH\nFLAGGED_USERS: U1@DOM1, U2@DOM1, U3@DOM1\nFLAGGED_HOSTS: C1\nNARRATIVE: ..."
        _, users, _ = _parse_llm_output(text)
        assert len(users) == 3
        assert "U3@DOM1" in users


# ===========================================================================
# _build_system_prompt
# ===========================================================================

class TestBuildSystemPrompt:
    def test_contains_candidate_usernames(self):
        prompt = _build_system_prompt(["U620@DOM1", "U100@DOM1"], 763200, 770000)
        assert "U620@DOM1" in prompt
        assert "U100@DOM1" in prompt

    def test_contains_severity_output_format(self):
        prompt = _build_system_prompt(["U1@DOM1"], 763200, 770000)
        assert "SEVERITY" in prompt
        assert "FLAGGED_USERS" in prompt
        assert "FLAGGED_HOSTS" in prompt
        assert "NARRATIVE" in prompt


# ===========================================================================
# _discover_candidates
# ===========================================================================

class TestDiscoverCandidates:
    _PATCH = "src.agent.orchestrator._run_discovery_query"

    def test_returns_discovery_result_schema(self):
        with patch(self._PATCH, return_value=[]):
            result = _discover_candidates(763200, 764600)
        assert "auth_anomaly_users" in result
        assert "ranked_candidates" in result
        assert result["tool_calls_made"] == 3

    def test_candidate_in_multiple_queries_ranks_first(self):
        repeated_user = "U620@DOM1"
        unique_user   = "U100@DOM1"

        def fake_query(query, params):
            if "failure_rate_pct" in query or "failure_rate" in query.lower():
                return [{"username": repeated_user}, {"username": unique_user}]
            if "first_seen_in_window" in query or "new_host_count" in query:
                return [{"username": repeated_user}]
            return [{"username": repeated_user}]

        with patch(self._PATCH, side_effect=fake_query):
            result = _discover_candidates(763200, 764600)
        assert result["ranked_candidates"][0] == repeated_user

    def test_neo4j_error_in_one_query_still_returns_result(self):
        from neo4j import exceptions as neo4j_exceptions
        calls = [0]

        def flaky_query(query, params):
            n = calls[0]; calls[0] += 1
            if n == 1:
                raise neo4j_exceptions.Neo4jError("transient error")
            return [{"username": "U620@DOM1"}]

        with patch(self._PATCH, side_effect=flaky_query):
            result = _discover_candidates(763200, 764600)
        assert "ranked_candidates" in result
        assert result["tool_calls_made"] == 3


# ===========================================================================
# investigate_window
# ===========================================================================

class TestInvestigateWindow:
    _DISCOVER = "src.agent.orchestrator._discover_candidates"
    _LITELLM  = "src.agent.orchestrator.litellm.completion"
    _TOKENS   = "src.agent.orchestrator._estimate_tokens"

    def test_no_candidates_returns_low_severity_immediately(self):
        discovery = {
            "auth_anomaly_users": [], "first_time_auth_users": [],
            "process_anomaly_users": [], "ranked_candidates": [], "tool_calls_made": 3,
        }
        with patch(self._DISCOVER, return_value=discovery):
            result = investigate_window(763200, 764600)
        assert result["severity"] == "LOW"
        assert result["flagged_users"] == []
        assert result["tool_calls_made"] == 3

    def test_with_candidates_calls_llm_and_parses_verdict(self):
        discovery = {
            "auth_anomaly_users": ["U620@DOM1"], "first_time_auth_users": ["U620@DOM1"],
            "process_anomaly_users": [], "ranked_candidates": ["U620@DOM1"], "tool_calls_made": 3,
        }
        verdict_text = (
            "SEVERITY: HIGH\nFLAGGED_USERS: U620@DOM1\nFLAGGED_HOSTS: C1003\n"
            "NARRATIVE: Lateral movement detected."
        )
        with (
            patch(self._DISCOVER, return_value=discovery),
            patch(self._LITELLM, return_value=_make_llm_response(verdict_text)),
            patch(self._TOKENS, return_value=500),
        ):
            result = investigate_window(763200, 764600)
        assert result["severity"] == "HIGH"
        assert "U620@DOM1" in result["flagged_users"]
        assert "C1003" in result["flagged_hosts"]


# ===========================================================================
# investigate_event
# ===========================================================================

class TestInvestigateEvent:
    _LITELLM = "src.agent.orchestrator.litellm.completion"
    _TOKENS  = "src.agent.orchestrator._estimate_tokens"

    def test_result_schema_complete(self):
        verdict_text = (
            "SEVERITY: HIGH\nFLAGGED_USERS: U620@DOM1\nFLAGGED_HOSTS: C1003\n"
            "NARRATIVE: Compromise confirmed."
        )
        with (
            patch(self._LITELLM, return_value=_make_llm_response(verdict_text)),
            patch(self._TOKENS, return_value=500),
        ):
            result = investigate_event("U620@DOM1", "C1003", 150885)
        for key in ("event", "flagged_users", "flagged_hosts", "verdict", "severity", "tool_calls_made"):
            assert key in result, f"Missing key: {key}"

    def test_time_window_is_plus_minus_3600(self):
        """investigate_event must build [T-3600, T+3600] — verify via captured system prompt."""
        captured_messages = []

        def capture_completion(**kwargs):
            captured_messages.extend(kwargs.get("messages", []))
            return _make_llm_response(
                "SEVERITY: LOW\nFLAGGED_USERS: NONE\nFLAGGED_HOSTS: NONE\nNARRATIVE: Clean."
            )

        with (
            patch(self._LITELLM, side_effect=capture_completion),
            patch(self._TOKENS, return_value=500),
        ):
            investigate_event("U620@DOM1", "C1003", 150885)

        system_content = captured_messages[0]["content"]
        assert "147285" in system_content  # 150885 - 3600
        assert "154485" in system_content  # 150885 + 3600
