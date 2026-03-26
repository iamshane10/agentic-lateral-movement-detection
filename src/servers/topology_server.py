"""
Topology MCP Server — topology_server.py

Exposes three tools for analyzing host connectivity and graph structure.
Called second in the investigation sequence, after behavioral analysis.

Tools:
    get_host_centrality        — pivot point approximation via distinct user counts
    get_lateral_movement_path  — auth chain reconstruction between source and target
    get_host_neighbors         — blast radius via one-hop reachable computers
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

mcp = FastMCP("topology-server")


def _get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def _run_query(query: str, params: dict) -> list[dict]:
    """Execute a Cypher query and return rows as plain dicts."""
    with _get_driver() as driver:
        with driver.session() as session:
            result = session.run(query, params)
            return [dict(record) for record in result]


# ---------------------------------------------------------------------------
# Tool 4: get_host_centrality
# ---------------------------------------------------------------------------

HOST_CENTRALITY_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer {name: $computer})
WHERE a.time >= $start_time AND a.time <= $end_time
WITH c,
     count(DISTINCT u) as unique_users,
     count(a) as total_auth_events,
     sum(CASE WHEN a.status = "Fail" THEN 1 ELSE 0 END) as failed_auths,
     collect(DISTINCT u.username) as users
RETURN c.name as computer,
       unique_users,
       total_auth_events,
       failed_auths,
       users
ORDER BY unique_users DESC
"""


@mcp.tool()
def get_host_centrality(computer: str, start_time: int, end_time: int) -> str:
    """
    Approximate betweenness centrality for a host by counting distinct users
    authenticating to it within the time window.

    High unique_users indicates a pivot point host. Compromising a high-centrality
    host grants access to many credentials. Used instead of full GDS Betweenness
    Centrality to avoid memory exhaustion on 54M+ edges.

    Args:
        computer:   Target computer name (e.g. 'C17')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string with centrality metrics or an empty-result message.
    """
    try:
        rows = _run_query(HOST_CENTRALITY_QUERY, {
            "computer": computer,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "computer": computer})

    if not rows:
        return json.dumps({
            "computer": computer,
            "message": "No authentication events found for this host in the specified window.",
            "unique_users": 0,
            "total_auth_events": 0,
            "failed_auths": 0,
            "users": [],
        })

    row = rows[0]
    return json.dumps({
        "computer": row["computer"],
        "unique_users": row["unique_users"],
        "total_auth_events": row["total_auth_events"],
        "failed_auths": row["failed_auths"],
        "users": row["users"],
    })


# ---------------------------------------------------------------------------
# Tool 5: get_lateral_movement_path
# ---------------------------------------------------------------------------

LATERAL_MOVEMENT_PATH_QUERY = """
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = "Success"
RETURN u.username as username,
       c.name as computer,
       a.time as auth_time,
       a.auth_type as auth_type
ORDER BY a.time ASC
"""


@mcp.tool()
def get_lateral_movement_path(
        username: str,
        start_time: int,
        end_time: int,
) -> str:
    """
    Reconstruct the lateral movement chain for a user by returning the
    sequence of hosts they authenticated to within the investigation window.

    The src_host in redteam.txt represents the attacker's originating machine
    and does not appear as an authentication destination in auth logs. Movement
    chains are therefore reconstructed from sequential authentication events to
    destination hosts, ordered chronologically. A rapid sequence of
    authentications to multiple hosts within a short time span is a strong
    lateral movement indicator.

    Args:
        username:   Username to investigate (e.g. 'U456@DOM1')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string with the ordered authentication chain for the user,
        or an empty-result message if no events are found in the window.
    """
    try:
        rows = _run_query(LATERAL_MOVEMENT_PATH_QUERY, {
            "username": username,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({
            "error": str(exc),
            "username": username,
        })

    if not rows:
        return json.dumps({
            "username": username,
            "message": "No authentication events found for this user in the specified window.",
            "chain": [],
            "count": 0,
        })

    return json.dumps({
        "username": username,
        "chain": [
            {
                "computer": row["computer"],
                "auth_time": row["auth_time"],
                "auth_type": row["auth_type"],
            }
            for row in rows
        ],
        "count": len(rows),
    })

# ---------------------------------------------------------------------------
# Tool 6: get_host_neighbors // slow - unresponsive
# ---------------------------------------------------------------------------

HOST_NEIGHBORS_QUERY = """
MATCH (src:Computer {name: $computer})<-[a1:AUTHENTICATED_TO]-(u:User)
      -[a2:AUTHENTICATED_TO]->(dst:Computer)
WHERE a1.time >= $start_time AND a1.time <= $end_time
AND a2.time >= $start_time AND a2.time <= $end_time
AND dst.name <> $computer
AND a1.status = "Success"
RETURN DISTINCT dst.name as reachable_computer,
       collect(DISTINCT u.username) as via_users,
       count(DISTINCT u) as user_count
ORDER BY user_count DESC
"""


@mcp.tool()
def get_host_neighbors(computer: str, start_time: int, end_time: int) -> str:
    """
    Return all computers reachable from a given host within one authentication
    hop. Defines the blast radius of a compromised host.

    Reachability is defined by authentication paths — users who authenticated
    to the given host and also authenticated to another host within the window.
    Does not require flows.txt.

    Args:
        computer:   Source computer name (e.g. 'C17')
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        JSON string with reachable computers and bridging users, or an
        empty-result message if no neighbors are found.
    """
    try:
        rows = _run_query(HOST_NEIGHBORS_QUERY, {
            "computer": computer,
            "start_time": start_time,
            "end_time": end_time,
        })
    except neo4j_exceptions.Neo4jError as exc:
        return json.dumps({"error": str(exc), "computer": computer})

    if not rows:
        return json.dumps({
            "computer": computer,
            "message": "No reachable neighbor computers found from this host in the specified window.",
            "neighbors": [],
            "count": 0,
        })

    return json.dumps({
        "computer": computer,
        "neighbors": [
            {
                "reachable_computer": row["reachable_computer"],
                "via_users": row["via_users"],
                "user_count": row["user_count"],
            }
            for row in rows
        ],
        "count": len(rows),
    })


if __name__ == "__main__":
    mcp.run()
