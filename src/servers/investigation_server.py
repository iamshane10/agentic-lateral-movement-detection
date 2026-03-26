"""
Investigation MCP Server — investigation_server.py

Aggregates evidence once suspicious activity is already identified. Always
called last in the investigation sequence. Outputs feed the Explainability
Score metric and the agent's natural language justification.

Tools:
    get_user_timeline          — full chronological auth + process event timeline
    get_host_activity_summary  — all users, processes, auth events on a host
    get_concurrent_sessions    — other users active on the same host near event time
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

mcp = FastMCP("investigation-server")


def _get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def _run_query(query: str, params: dict) -> list[dict]:
    """Execute a Cypher query and return rows as plain dicts."""
    with _get_driver() as driver:
        with driver.session() as session:
            result = session.run(query, params)
            return [dict(record) for record in result]


# ---------------------------------------------------------------------------
# Tool 7: get_user_timeline
# ---------------------------------------------------------------------------

USER_TIMELINE_QUERY = """
MATCH (u:User {username: $username})
OPTIONAL MATCH (u)-[a:AUTHENTICATED_TO]->(c1:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
OPTIONAL MATCH (u)-[e:EXECUTED]->(c2:Computer)
WHERE e.time >= $start_time AND e.time <= $end_time
WITH u,
     collect(DISTINCT {
         event_type: 'AUTH',
         time: a.time,
         computer: c1.name,
         success: a.status,
         auth_type: a.auth_type,
         detail: a.logon_type
     }) as auth_events,
     collect(DISTINCT {
         event_type: 'PROCESS',
         time: e.time,
         computer: c2.name,
         process_name: e.process_name,
         event_type_detail: e.event_type
     }) as process_events
RETURN u.username as username,
       auth_events,
       process_events,
       size(auth_events) as total_auth_events,
       size(process_events) as total_process_events
"""


@mcp.tool()
def get_user_timeline(username: str, start_time: int, end_time: int) -> str:
    """
    Return a full chronological event timeline for a user, interleaving
    authentication and process events within the investigation window.

    Gives the LLM a complete narrative of what a user did. Interleaving
    auth and process events enables sequence reasoning — e.g., authenticated
    to host C17 at T=5000, then executed new process P445 at T=5003 is a
    much stronger signal than either event alone.

    Args:
        username:   LANL username (e.g. 'U456@DOM1')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string with auth_events and process_events lists plus counts,
        or an empty-result message if the user is not found.
    """
    try:
        rows = _run_query(USER_TIMELINE_QUERY, {
            "username": username,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "username": username})

    if not rows:
        return json.dumps({
            "username": username,
            "message": "No timeline data found for this user in the specified window.",
            "auth_events": [],
            "process_events": [],
            "total_auth_events": 0,
            "total_process_events": 0,
        })

    row = rows[0]
    return json.dumps({
        "username": row["username"],
        "auth_events": row["auth_events"],
        "process_events": row["process_events"],
        "total_auth_events": row["total_auth_events"],
        "total_process_events": row["total_process_events"],
    })


# ---------------------------------------------------------------------------
# Tool 8: get_host_activity_summary
# ---------------------------------------------------------------------------

HOST_ACTIVITY_QUERY = """
MATCH (c:Computer {name: $computer})
OPTIONAL MATCH (u:User)-[a:AUTHENTICATED_TO]->(c)
WHERE a.time >= $start_time AND a.time <= $end_time
OPTIONAL MATCH (u2:User)-[e:EXECUTED]->(c)
WHERE e.time >= $start_time AND e.time <= $end_time
WITH c,
     count(DISTINCT u) as unique_auth_users,
     count(a) as total_auths,
     sum(CASE WHEN a.status = "Success" THEN 1 ELSE 0 END) as failed_auths,
     collect(DISTINCT u.username) as auth_users,
     count(DISTINCT u2) as unique_exec_users,
     collect(DISTINCT e.process_name) as processes_executed,
     count(e) as total_executions
RETURN c.name as computer,
       unique_auth_users,
       total_auths,
       failed_auths,
       auth_users,
       unique_exec_users,
       processes_executed,
       total_executions
"""


@mcp.tool()
def get_host_activity_summary(computer: str, start_time: int, end_time: int) -> str:
    """
    Return all activity on a given host within the investigation window —
    all users, all processes, all auth events.

    First tool called when investigating a suspicious destination host.
    Answers who else was on this machine and what was running — essential
    for blast radius assessment and scoping the full impact of a compromise.

    Args:
        computer:   Target computer name (e.g. 'C17')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string with auth and process execution summary for the host,
        or an empty-result message if the computer is not found.
    """
    try:
        rows = _run_query(HOST_ACTIVITY_QUERY, {
            "computer": computer,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "computer": computer})

    if not rows:
        return json.dumps({
            "computer": computer,
            "message": "No activity found for this host in the specified window.",
            "unique_auth_users": 0,
            "total_auths": 0,
            "failed_auths": 0,
            "auth_users": [],
            "unique_exec_users": 0,
            "processes_executed": [],
            "total_executions": 0,
        })

    row = rows[0]
    return json.dumps({
        "computer": row["computer"],
        "unique_auth_users": row["unique_auth_users"],
        "total_auths": row["total_auths"],
        "failed_auths": row["failed_auths"],
        "auth_users": row["auth_users"],
        "unique_exec_users": row["unique_exec_users"],
        "processes_executed": row["processes_executed"],
        "total_executions": row["total_executions"],
    })


# ---------------------------------------------------------------------------
# Tool 9: get_concurrent_sessions
# ---------------------------------------------------------------------------

CONCURRENT_SESSIONS_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer {name: $computer})
WHERE a.time >= ($time - $window)
AND a.time <= ($time + $window)
AND a.status = "Success"
RETURN u.username as username,
       a.time as auth_time,
       a.auth_type as auth_type,
       abs(a.time - $time) as time_delta_from_event
ORDER BY time_delta_from_event ASC
"""


@mcp.tool()
def get_concurrent_sessions(computer: str, time: int, window: int = 300) -> str:
    """
    Find users who successfully authenticated to the same host at approximately
    the same time as the suspicious event.

    Detects whether a compromise event coincided with other unusual access.
    Multiple users authenticating to the same host within seconds of a red
    team event indicates either a coordinated attack or a high-value shared
    resource. Default window is 300 seconds.

    Args:
        computer: Target computer name (e.g. 'C17')
        time:     Event time — LANL internal integer (elapsed seconds)
        window:   Time radius in seconds on either side of event (default 300)

    Returns:
        JSON string listing concurrent authenticated users ordered by proximity
        to the event time, or an empty-result message if none are found.
    """
    try:
        rows = _run_query(CONCURRENT_SESSIONS_QUERY, {
            "computer": computer,
            "time": time,
            "window": window,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "computer": computer})

    if not rows:
        return json.dumps({
            "computer": computer,
            "time": time,
            "window": window,
            "message": "No concurrent sessions found within the specified window.",
            "concurrent_sessions": [],
            "count": 0,
        })

    return json.dumps({
        "computer": computer,
        "time": time,
        "window": window,
        "concurrent_sessions": [
            {
                "username": row["username"],
                "auth_time": row["auth_time"],
                "auth_type": row["auth_type"],
                "time_delta_from_event": row["time_delta_from_event"],
            }
            for row in rows
        ],
        "count": len(rows),
    })

if __name__ == "__main__":
    mcp.run()
