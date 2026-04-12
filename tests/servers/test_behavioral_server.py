"""
Unit tests for src/servers/behavioral_server.py.

All Neo4j I/O is replaced with unittest.mock so no live database is needed.
"""

import json
from unittest.mock import patch

from neo4j import exceptions as neo4j_exceptions

from src.servers.behavioral_server import (
    get_auth_anomalies,
    get_first_time_authentications,
    get_process_anomalies,
)

USERNAME   = "U620@DOM1"
COMPUTER   = "C1003"
START_TIME = 147285
END_TIME   = 154485

_PATCH = "src.servers.behavioral_server._run_query"


class TestGetAuthAnomalies:
    def test_returns_valid_json(self):
        fake_row = {
            "username": USERNAME, "total_attempts": 50, "failed_attempts": 20,
            "failure_rate_pct": 40.0, "unique_targets": 5,
            "target_computers": ["C1003"], "auth_types_used": ["Kerberos"],
        }
        with patch(_PATCH, return_value=[fake_row]):
            result = json.loads(get_auth_anomalies(USERNAME, START_TIME, END_TIME))
        assert result["username"] == USERNAME
        assert result["failure_rate_pct"] == 40.0

    def test_neo4j_error_returns_error_field(self):
        with patch(_PATCH, side_effect=neo4j_exceptions.Neo4jError("connection refused")):
            result = json.loads(get_auth_anomalies(USERNAME, START_TIME, END_TIME))
        assert "error" in result
        assert result["username"] == USERNAME


class TestGetFirstTimeAuthentications:
    def test_returns_list_of_new_auth_pairs(self):
        fake_rows = [
            {"username": USERNAME, "computer": "C1003", "first_auth_time": 148000},
            {"username": USERNAME, "computer": "C2004", "first_auth_time": 149000},
        ]
        with patch(_PATCH, return_value=fake_rows):
            result = json.loads(get_first_time_authentications(USERNAME, START_TIME, END_TIME))
        assert result["count"] == 2
        assert result["first_time_authentications"][0]["computer"] == "C1003"

    def test_empty_result_returns_zero_count(self):
        with patch(_PATCH, return_value=[]):
            result = json.loads(get_first_time_authentications(USERNAME, START_TIME, END_TIME))
        assert result["count"] == 0
        assert "message" in result


class TestGetProcessAnomalies:
    def test_returns_new_processes(self):
        fake_row = {
            "username": USERNAME, "computer": COMPUTER,
            "new_processes": ["P131", "P445"], "new_process_count": 2, "total_in_window": 5,
        }
        with patch(_PATCH, return_value=[fake_row]):
            result = json.loads(get_process_anomalies(USERNAME, COMPUTER, START_TIME, END_TIME))
        assert result["new_processes"] == ["P131", "P445"]
        assert result["new_process_count"] == 2

    def test_neo4j_error_returns_error_with_username_and_computer(self):
        with patch(_PATCH, side_effect=neo4j_exceptions.Neo4jError("query failed")):
            result = json.loads(get_process_anomalies(USERNAME, COMPUTER, START_TIME, END_TIME))
        assert "error" in result
        assert result["username"] == USERNAME
        assert result["computer"] == COMPUTER
