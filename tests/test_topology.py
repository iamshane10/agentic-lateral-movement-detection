"""
Direct test for topology_server.py tools.

Bypasses the MCP framework — calls the query functions directly so you can
validate Cypher results against Neo4j before wiring up the orchestrator.

Sample redteam event used for all fixtures:
    150885, U620@DOM1, C17693, C1003

    T          = 150885
    start_time = T - 3600 = 147285
    end_time   = T + 3600 = 154485

    get_lateral_movement_path uses C17693 as source and C1003 as destination.
    time_delta values under 300 seconds are a strong lateral movement signal.

Usage:
    uv run python tests/test_topology.py
"""

import json
import sys
import os

# Make sure the project root is on the path when running the script directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.servers.topology_server import (
    _get_driver,
    get_host_centrality,
    get_lateral_movement_path,
    get_host_neighbors,
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

def test_host_centrality_src() -> None:
    """Check pivot point significance of the source host."""
    raw = get_host_centrality(
        computer=SRC_HOST,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_host_centrality | {SRC_HOST} (source) | T±3600 ({START_TIME}–{END_TIME})",
        raw,
    )


def test_host_centrality_dst() -> None:
    """Check pivot point significance of the destination host."""
    raw = get_host_centrality(
        computer=DST_HOST,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_host_centrality | {DST_HOST} (destination) | T±3600 ({START_TIME}–{END_TIME})",
        raw,
    )


def test_lateral_movement_path() -> None:
    """Reconstruct the auth chain from C17693 → C1003. Watch time_delta closely."""
    raw = get_lateral_movement_path(
        source_computer=SRC_HOST,
        target_computer=DST_HOST,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    parsed = json.loads(raw)

    print(f"\n{'=' * 60}")
    print(f"  get_lateral_movement_path | {SRC_HOST} → {DST_HOST} | T±3600 ({START_TIME}–{END_TIME})")
    print('=' * 60)
    print(json.dumps(parsed, indent=2))

    # Highlight time_delta for each path — under 300s is a strong LM signal.
    paths = parsed.get("paths", [])
    if paths:
        print(f"\n  --- time_delta summary ({len(paths)} path(s) found) ---")
        for i, p in enumerate(paths):
            delta = p["time_delta"]
            flag = " *** UNDER 300s — STRONG LATERAL MOVEMENT SIGNAL ***" if delta < 300 else ""
            print(f"  [{i+1}] pivot={p['pivot_user']}  "
                  f"src_t={p['auth_from_source_time']}  "
                  f"dst_t={p['auth_to_target_time']}  "
                  f"time_delta={delta}{flag}")
    else:
        print("\n  No authentication chain found between these hosts.")


def test_host_neighbors_src() -> None:
    """Map blast radius outward from the source host."""
    raw = get_host_neighbors(
        computer=SRC_HOST,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_host_neighbors | {SRC_HOST} (source) | T±3600 ({START_TIME}–{END_TIME})",
        raw,
    )


def test_host_neighbors_dst() -> None:
    """Map blast radius outward from the destination host."""
    raw = get_host_neighbors(
        computer=DST_HOST,
        start_time=START_TIME,
        end_time=END_TIME,
    )
    _print_result(
        f"get_host_neighbors | {DST_HOST} (destination) | T±3600 ({START_TIME}–{END_TIME})",
        raw,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"\nTopology Server — Direct Tool Test")
    print(f"  Event  : T={T}, user={USERNAME}, {SRC_HOST} → {DST_HOST}")
    print(f"  Window : {START_TIME} – {END_TIME}")

    _check_neo4j_connectivity()

    test_host_centrality_src()
    test_host_centrality_dst()
    test_lateral_movement_path()
    test_host_neighbors_src()
    test_host_neighbors_dst()

    print(f"\n{'=' * 60}")
    print("  All tools executed successfully.")
    print('=' * 60)
