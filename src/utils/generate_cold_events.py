"""
generate_cold_events.py

One-time data preparation script. Queries Neo4j to produce a curated set of
clean control events and writes them to data/cold_events.txt in the same
format as redteam.txt (timestamp,username,src_host,dst_host — comma-separated,
no header).

This script is run once manually and its output is committed alongside
redteam.txt as a research artifact. It is NOT called by evaluator.py at runtime.

Filtering pipeline:
    Filter 1 — Exclude machine accounts ('$') and ANONYMOUS logons.
    Filter 2 — Exclude any username appearing anywhere in redteam.txt.
    Filter 3 — Low-centrality hosts only (< 50 distinct authenticating users
               in the cold window).
    Filter 4 — Exclude rapid multi-hop users (> 3 distinct hosts in any 300s
               sliding window). Bulk query; skipped with a warning on timeout.
    Filter 5 — Successful authentications only (a.status = 'Success').

For src_host: cold events have no origin concept, so dst_host is used for
both src_host and dst_host columns, consistent with how evaluator.py uses
only username, dst_host, and timestamp from each row.

Usage:
    uv run python -m src.evaluation.generate_cold_events
"""

import os
import random
import sys
from pathlib import Path

# Ensure project root is on sys.path when run directly as a script.
# Has no effect when invoked via `python -m src.evaluation.generate_cold_events`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

COLD_WINDOW_START = 635020
COLD_WINDOW_END   = 640800

_REDTEAM_PATH = Path(os.getenv("REDTEAM_PATH", "data/redteam.txt"))
_OUTPUT_PATH  = Path("data/cold_events.txt")

# Filter 3 — low-centrality hosts in the cold window (< 50 distinct users)
_LOW_CENTRALITY_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= 635020 AND a.time <= 640800
AND NOT u.username CONTAINS '$'
AND NOT u.username CONTAINS 'ANONYMOUS'
WITH c, count(DISTINCT u) AS unique_users
WHERE unique_users < 50
RETURN c.name AS computer, unique_users
ORDER BY unique_users ASC
"""

# Filter 4 — users who accessed > 3 distinct hosts within any 300s window
# (bulk query; skipped gracefully on timeout)
_HIGH_HOP_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= 635020 AND a.time <= 640800
AND a.status = 'Success'
AND NOT u.username CONTAINS '$'
AND NOT u.username CONTAINS 'ANONYMOUS'
WITH u, a.time AS t
MATCH (u)-[a2:AUTHENTICATED_TO]->(c2:Computer)
WHERE a2.time >= t AND a2.time <= t + 300
AND a2.status = 'Success'
WITH u, t, count(DISTINCT c2) AS hops_in_window
WITH u, max(hops_in_window) AS max_hops
WHERE max_hops > 3
RETURN DISTINCT u.username AS username
"""

# Candidate events on low-centrality hosts in the cold window
_CANDIDATE_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= 635020 AND a.time <= 640800
AND a.status = 'Success'
AND NOT u.username CONTAINS '$'
AND NOT u.username CONTAINS 'ANONYMOUS'
AND c.name IN $low_centrality_hosts
RETURN u.username AS username,
       c.name AS dst_host,
       a.time AS timestamp
ORDER BY rand()
LIMIT 1000
"""


def _load_redteam_usernames(path: Path) -> set[str]:
    """Return the set of all unique usernames from redteam.txt."""
    usernames: set[str] = set()
    if not path.exists():
        print(f"[cold_events] Warning: redteam path not found: {path}")
        return usernames
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                usernames.add(parts[1].strip())
    return usernames


def main() -> None:
    neo4j_uri      = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user_env = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "password")

    print(f"[cold_events] Cold window: {COLD_WINDOW_START} to {COLD_WINDOW_END}")

    # Filter 2: collect redteam usernames for exclusion
    redteam_usernames = _load_redteam_usernames(_REDTEAM_PATH)

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user_env, neo4j_password))
    try:
        # Filter 3: low-centrality hosts
        with driver.session() as session:
            result = session.run(_LOW_CENTRALITY_QUERY)
            low_centrality_hosts = {row["computer"] for row in result}
        print(f"[cold_events] Low-centrality hosts found:   {len(low_centrality_hosts)}")

        # Filter 4: high-hop users (bulk; skip on timeout or error)
        high_hop_users: set[str] = set()
        try:
            with driver.session() as session:
                result = session.run(_HIGH_HOP_QUERY)
                high_hop_users = {row["username"] for row in result}
        except Exception as exc:
            print(
                f"[cold_events] Warning: high-hop bulk query failed ({exc}) — "
                "Filter 4 skipped, high-hop users not excluded"
            )
        print(f"[cold_events] High-hop users excluded:       {len(high_hop_users)}")

        # Candidate query
        with driver.session() as session:
            result = session.run(
                _CANDIDATE_QUERY,
                {"low_centrality_hosts": list(low_centrality_hosts)},
            )
            candidates = [dict(r) for r in result]
    finally:
        driver.close()

    # Apply in-Python filters: high-hop and redteam exclusion
    candidates = [
        c for c in candidates
        if c["username"] not in high_hop_users
        and c["username"] not in redteam_usernames
    ]

    # Deduplicate by username — one event per unique user for a diverse control set
    random.shuffle(candidates)
    seen_users: set[str] = set()
    deduped: list[dict] = []
    for c in candidates:
        if c["username"] not in seen_users:
            seen_users.add(c["username"])
            deduped.append(c)

    # Take first 50 after deduplication
    final_events = deduped[:50]

    print(f"[cold_events] Redteam users excluded:        {len(redteam_usernames)}")
    print(f"[cold_events] Final cold events written:     {len(final_events)}")

    # Write output — src_host = dst_host (no origin concept for cold events)
    _OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_OUTPUT_PATH, "w") as fh:
        for ev in final_events:
            fh.write(f"{ev['timestamp']},{ev['username']},{ev['dst_host']},{ev['dst_host']}\n")

    print(f"[cold_events] Output: {_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
