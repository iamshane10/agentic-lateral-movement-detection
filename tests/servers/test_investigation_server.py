"""
Unit tests for src/servers/investigation_server.py.

All Neo4j I/O is replaced with unittest.mock so no live database is needed.
"""

import json
from unittest.mock import patch

from neo4j import exceptions as neo4j_exceptions

from src.servers.investigation_server import (
    get_concurrent_sessions,
    get_host_activity_summary,
    get_user_timeline,
)

USERNAME   = "U620@DOM1"
COMPUTER   = "C1003"
START_TIME = 147285
END_TIME   = 154485
EVENT_TIME = 150885

_PATCH = "src.servers.investigation_server._run_query"


class TestGetUserTimeline:
    def test_returns_auth_and_process_events(self):
        fake_row = {
            "username": USERNAME,
            "auth_events": [{"event_type": "AUTH", "time": 148000, "computer": "C1003",
                              "success": "Success", "auth_type": "Kerberos", "detail": "Network"}],
            "process_events": [{"event_type": "PROCESS", "time": 148005, "computer": "C1003",
                                 "process_name": "P131", "event_type_detail": "start"}],
            "total_auth_events": 1, "total_process_events": 1,
        }
        with patch(_PATCH, return_value=[fake_row]):
            result = json.loads(get_user_timeline(USERNAME, START_TIME, END_TIME))
        assert result["total_auth_events"] == 1
        assert result["total_process_events"] == 1

    def test_neo4j_error_returns_error_field(self):
        with patch(_PATCH, side_effect=neo4j_exceptions.Neo4jError("session failed")):
            result = json.loads(get_user_timeline(USERNAME, START_TIME, END_TIME))
        assert "error" in result
        assert result["username"] == USERNAME


class TestGetHostActivitySummary:
    def test_returns_auth_and_process_summary(self):
        fake_row = {
            "computer": COMPUTER, "unique_auth_users": 3, "total_auths": 10,
            "failed_auths": 2, "auth_users": ["U620@DOM1"],
            "unique_exec_users": 2, "processes_executed": ["P131"], "total_executions": 7,
        }
        with patch(_PATCH, return_value=[fake_row]):
            result = json.loads(get_host_activity_summary(COMPUTER, START_TIME, END_TIME))
        assert result["computer"] == COMPUTER
        assert result["total_auths"] == 10
        assert "P131" in result["processes_executed"]

    def test_neo4j_error_returns_error_field(self):
        with patch(_PATCH, side_effect=neo4j_exceptions.Neo4jError("cypher error")):
            result = json.loads(get_host_activity_summary(COMPUTER, START_TIME, END_TIME))
        assert "error" in result
        assert result["computer"] == COMPUTER


class TestGetConcurrentSessions:
    def test_returns_concurrent_users(self):
        fake_rows = [
            {"username": "U1@DOM1", "auth_time": 150880, "auth_type": "Kerberos", "time_delta_from_event": 5},
        ]
        with patch(_PATCH, return_value=fake_rows):
            result = json.loads(get_concurrent_sessions(COMPUTER, EVENT_TIME, window=300))
        assert result["count"] == 1
        assert result["concurrent_sessions"][0]["username"] == "U1@DOM1"

    def test_default_window_is_300(self):
        """When window is omitted, the server must pass window=300 to the query."""
        captured = {}

        def capture_params(query, params):
            captured.update(params)
            return []

        with patch(_PATCH, side_effect=capture_params):
            get_concurrent_sessions(COMPUTER, EVENT_TIME)

        assert captured.get("window") == 300
