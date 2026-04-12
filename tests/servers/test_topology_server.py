"""
Unit tests for src/servers/topology_server.py.

All Neo4j I/O is replaced with unittest.mock so no live database is needed.
Note: get_host_neighbors is disabled in the server and is not tested.
"""

import json
from unittest.mock import patch

from neo4j import exceptions as neo4j_exceptions

from src.servers.topology_server import (
    get_host_centrality,
    get_lateral_movement_path,
)

USERNAME   = "U620@DOM1"
COMPUTER   = "C1003"
START_TIME = 147285
END_TIME   = 154485

_PATCH = "src.servers.topology_server._run_query"


class TestGetHostCentrality:
    def test_returns_centrality_metrics(self):
        fake_row = {
            "computer": COMPUTER, "unique_users": 12,
            "total_auth_events": 45, "failed_auths": 3,
            "users": ["U620@DOM1"],
        }
        with patch(_PATCH, return_value=[fake_row]):
            result = json.loads(get_host_centrality(COMPUTER, START_TIME, END_TIME))
        assert result["unique_users"] == 12
        assert "U620@DOM1" in result["users"]

    def test_neo4j_error_returns_error_field(self):
        with patch(_PATCH, side_effect=neo4j_exceptions.Neo4jError("bolt disconnect")):
            result = json.loads(get_host_centrality(COMPUTER, START_TIME, END_TIME))
        assert "error" in result
        assert result["computer"] == COMPUTER


class TestGetLateralMovementPath:
    def test_returns_ordered_chain(self):
        fake_rows = [
            {"username": USERNAME, "computer": "C100", "auth_time": 148000, "auth_type": "Kerberos"},
            {"username": USERNAME, "computer": "C200", "auth_time": 149000, "auth_type": "NTLM"},
        ]
        with patch(_PATCH, return_value=fake_rows):
            result = json.loads(get_lateral_movement_path(USERNAME, START_TIME, END_TIME))
        assert result["count"] == 2
        assert result["chain"][0]["computer"] == "C100"

    def test_neo4j_error_returns_error_field(self):
        with patch(_PATCH, side_effect=neo4j_exceptions.Neo4jError("auth failed")):
            result = json.loads(get_lateral_movement_path(USERNAME, START_TIME, END_TIME))
        assert "error" in result
        assert result["username"] == USERNAME

    def test_rapid_multi_hop_chain_is_lateral_movement_signal(self):
        """5-second gap between consecutive auth events is a strong LM indicator."""
        fake_rows = [
            {"username": USERNAME, "computer": "C1003", "auth_time": 763210, "auth_type": "Kerberos"},
            {"username": USERNAME, "computer": "C2048", "auth_time": 763215, "auth_type": "Kerberos"},
        ]
        with patch(_PATCH, return_value=fake_rows):
            result = json.loads(get_lateral_movement_path(USERNAME, 763200, 764600))
        assert result["count"] == 2
        delta = result["chain"][1]["auth_time"] - result["chain"][0]["auth_time"]
        assert delta == 5
