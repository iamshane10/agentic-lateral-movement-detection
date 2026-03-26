"""
Direct test for behavioral_server.py tools.

Bypasses the MCP framework — calls the query functions directly so you can
validate Cypher results against Neo4j before wiring up the orchestrator.

Sample redteam event used for all fixtures:
    150885, U620@DOM1, C17693, C1003

    T          = 150885
    start_time = T - 3600 = 147285
    end_time   = T + 3600 = 154485

    get_process_anomalies is run against both the source host (C17693) and
    the destination host (C1003) to show where new process execution landed.

Usage:
    uv run python tests/test_behavioral.py
"""

import json
import sys
import os

# Make sure the project root is on the path when running the script directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.servers.behavioral_server import (
    _get_driver,
    get_auth_anomalies,
    get_first_time_authentications,
    get_process_anomalies,
)

# ---------------------------------------------------------------------------
# Fixtures derived from the redteam sample event
# ---------------------------------------------------------------------------

T           = 150885
USERNAME    = "U620@DOM1"
SRC_HOST    = "C17693"
DST_HOST    = "C1003"
START_TIME  = T - 3600   # 147285
END_TIME    = T + 3600   # 154485


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_result(label: str, raw: str) -> None:
    parsed = json.loads(raw)
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print('=' * 60)
    print(json.dumps(parsed, indent=2))


def _check_neo4j_connectivity() -> None:
    """Fail fast with a clear message if Neo4j is unreachable."""
    print("Checking Neo4j connectivity...", end=" ")
    try:
        with _get_driver() as driver:
            driver.verify_connectivity()
        print("OK")
    except Exception as exc:
        print(f"FAILED\n\nCannot reach Neo4j: {exc}")
        print("\nMake sure Neo4j is running and .env credentials are correct.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_auth_anomalies() -> None:
    raw = get_auth_anomalies(
        username=USERNAME,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_auth_anomalies | {USERNAME} | T±3600 ({START_TIME}–{END_TIME})",
        raw,
    )


def test_first_time_authentications() -> None:
    raw = get_first_time_authentications(
        username=USERNAME,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_first_time_authentications | {USERNAME} | T±3600 ({START_TIME}–{END_TIME})",
        raw,
    )


def test_process_anomalies_src() -> None:
    """Check for novel processes on the source host (where the user originated)."""
    raw = get_process_anomalies(
        username=USERNAME,
        computer=SRC_HOST,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_process_anomalies | {USERNAME} on {SRC_HOST} (source) | T±3600",
        raw,
    )


def test_process_anomalies_dst() -> None:
    """Check for novel processes on the destination host (lateral movement target)."""
    raw = get_process_anomalies(
        username=USERNAME,
        computer=DST_HOST,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_process_anomalies | {USERNAME} on {DST_HOST} (destination) | T±3600",
        raw,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"\nBehavioral Server — Direct Tool Test")
    print(f"  Event  : T={T}, user={USERNAME}, {SRC_HOST} → {DST_HOST}")
    print(f"  Window : {START_TIME} – {END_TIME}")

    _check_neo4j_connectivity()

    test_auth_anomalies()
    test_first_time_authentications()
    test_process_anomalies_src()
    test_process_anomalies_dst()

    print(f"\n{'=' * 60}")
    print("  All tools executed successfully.")
    print('=' * 60)
