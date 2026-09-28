"""
Behavioral MCP Server — behavioral_server.py

Exposes three tools for detecting anomalous authentication and process
execution behavior. Always the first server called in an investigation.

Tools:
    get_auth_anomalies            — failure rates, unique targets, auth type changes
    get_first_time_authentications — new user-host relationships inside the window
    get_process_anomalies         — novel process execution on a host vs. baseline
"""

import json
import os

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from neo4j import GraphDatabase, exceptions as neo4j_exceptions

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

mcp = FastMCP("behavioral-server")


def _get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def _run_query(query: str, params: dict) -> list[dict]:
    """Execute a Cypher query and return rows as plain dicts."""
    with _get_driver() as driver:
        with driver.session() as session:
            result = session.run(query, params)
            return [dict(record) for record in result]


# ---------------------------------------------------------------------------
# Tool 1: get_auth_anomalies
# ---------------------------------------------------------------------------

AUTH_ANOMALIES_QUERY = """
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH u,
     count(a) as total_attempts,
     sum(CASE WHEN a.status = "Fail" THEN 1 ELSE 0 END) as failed_attempts,
     collect(DISTINCT c.name) as target_computers,
     collect(DISTINCT a.auth_type) as auth_types_used
RETURN u.username as username,
       total_attempts,
       failed_attempts,
       round(toFloat(failed_attempts)/total_attempts * 100, 2) as failure_rate_pct,
       size(target_computers) as unique_targets,
       target_computers,
       auth_types_used
"""


@mcp.tool()
def get_auth_anomalies(username: str, start_time: int, end_time: int) -> str:
    """
    Detect abnormal authentication patterns for a user within a time window.

    Returns failure rate, unique target count, and auth types used. High
    failure_rate_pct combined with many unique_targets is a strong lateral
    movement / credential stuffing signal. auth_types_used detects protocol
    downgrade attacks.

    Args:
        username:   LANL username (e.g. 'U456@DOM1')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string with authentication anomaly metrics or an empty-result message.
    """
    try:
        rows = _run_query(AUTH_ANOMALIES_QUERY, {
            "username": username,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "username": username})

    if not rows:
        return json.dumps({
            "username": username,
            "message": "No authentication events found in the specified window.",
            "total_attempts": 0,
            "failed_attempts": 0,
            "failure_rate_pct": 0.0,
            "unique_targets": 0,
            "target_computers": [],
            "auth_types_used": [],
        })

    row = rows[0]
    return json.dumps({
        "username": row["username"],
        "total_attempts": row["total_attempts"],
        "failed_attempts": row["failed_attempts"],
        "failure_rate_pct": row["failure_rate_pct"],
        "unique_targets": row["unique_targets"],
        "target_computers": row["target_computers"],
        "auth_types_used": row["auth_types_used"],
    })


# ---------------------------------------------------------------------------
# Tool 2: get_first_time_authentications
# ---------------------------------------------------------------------------

FIRST_TIME_AUTH_QUERY = """
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = "Success"
WITH u, c, min(a.time) as first_seen_in_window
WHERE NOT EXISTS {
    MATCH (u)-[a2:AUTHENTICATED_TO]->(c)
    WHERE a2.time < $start_time
    AND a2.status = "Success"
}
RETURN u.username as username,
       c.name as computer,
       first_seen_in_window as first_auth_time
ORDER BY first_auth_time ASC
"""


@mcp.tool()
def get_first_time_authentications(username: str, start_time: int, end_time: int) -> str:
    """
    Find user-computer pairs where no prior successful authentication existed
    before the investigation window.

    A red team actor using compromised credentials will almost always
    authenticate to machines that account has never touched before. This
    surfaces the structural fingerprint of lateral movement.

    Args:
        username:   LANL username (e.g. 'U456@DOM1')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string with a list of first-time authentication events, or an
        empty-result message if none are found.
    """
    try:
        rows = _run_query(FIRST_TIME_AUTH_QUERY, {
            "username": username,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "username": username})

    if not rows:
        return json.dumps({
            "username": username,
            "message": "No first-time authentications found in the specified window.",
            "first_time_authentications": [],
            "count": 0,
        })

    return json.dumps({
        "username": username,
        "first_time_authentications": [
            {
                "computer": row["computer"],
                "first_auth_time": row["first_auth_time"],
            }
            for row in rows
        ],
        "count": len(rows),
    })


# ---------------------------------------------------------------------------
# Tool 3: get_process_anomalies // doesn't return any values, may not be a relevant tool
# ---------------------------------------------------------------------------

PROCESS_ANOMALIES_QUERY = """
MATCH (u:User {username: $username})-[e:EXECUTED]->(c:Computer {name: $computer})
WHERE e.time >= $start_time AND e.time <= $end_time
WITH u, c, collect(DISTINCT e.process_name) as processes_in_window
MATCH (u)-[e2:EXECUTED]->(c)
WHERE e2.time < $start_time
WITH u, c, processes_in_window,
     collect(DISTINCT e2.process_name) as historical_processes
WITH u, c,
     [p IN processes_in_window WHERE NOT p IN historical_processes] as new_processes,
     size(processes_in_window) as total_in_window
RETURN u.username as username,
       c.name as computer,
       new_processes,
       size(new_processes) as new_process_count,
       total_in_window
"""


@mcp.tool()
def get_process_anomalies(
    username: str,
    computer: str,
    start_time: int,
    end_time: int,
) -> str:
    """
    Identify processes executed by a user on a specific host that they have
    never run there before the investigation window.

    Called after get_first_time_authentications confirms suspicious access.
    Novel process execution on a newly accessed host is a second-layer
    corroboration signal. Process names are anonymized (e.g. 'P131') but
    behavioral novelty is still meaningful.

    Args:
        username:   LANL username (e.g. 'U456@DOM1')
        computer:   Target computer name (e.g. 'C17')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string listing novel processes and counts, or an empty-result
        message if no process execution data is found.
    """
    try:
        rows = _run_query(PROCESS_ANOMALIES_QUERY, {
            "username": username,
            "computer": computer,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "username": username, "computer": computer})

    if not rows:
        return json.dumps({
            "username": username,
            "computer": computer,
            "message": "No process execution data found for this user-host pair in the window.",
            "new_processes": [],
            "new_process_count": 0,
            "total_in_window": 0,
        })

    row = rows[0]
    return json.dumps({
        "username": row["username"],
        "computer": row["computer"],
        "new_processes": row["new_processes"],
        "new_process_count": row["new_process_count"],
        "total_in_window": row["total_in_window"],
    })

if __name__ == "__main__":
    mcp.run()
