"""
Agent Orchestrator — orchestrator.py

Two-phase blind lateral movement detection.

Phase 1 — Discovery (orchestrator-level, no entity inputs):
    Direct Neo4j queries scan all users in the time window for auth anomalies,
    first-time authentications, and process anomalies. The LLM never sees this
    phase — no usernames or hostnames are provided as inputs.

Phase 2 — Investigation (LLM-driven, entity-centric):
    Top-3 candidates from Phase 1 are passed to the LLM. The LLM selects
    relevant topology and investigation tools per candidate and produces a
    final structured verdict.

Entry point:
    investigate_window(start_time, end_time) -> dict

The evaluator (evaluator.py) imports investigate_window.
orchestrator.py never imports from evaluator.py.
"""

import json
import os
import re
from collections import Counter

import litellm
from dotenv import load_dotenv
from neo4j import GraphDatabase, exceptions as neo4j_exceptions

from src.servers import investigation_server, topology_server

load_dotenv()

_NAVIGATOR_BASE_URL = os.getenv("NAVIGATOR_API_BASE")
_NAVIGATOR_MODEL = os.getenv("NAVIGATOR_MODEL")
if not _NAVIGATOR_MODEL:
    raise RuntimeError(
        "NAVIGATOR_MODEL is not set in .env — set it to gpt-4o or your Navigator endpoint model"
    )

_NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

_MAX_ITERATIONS = 20  # max total LLM tool calls in Phase 2
MAX_RESULT_CHARS = 2000  # max chars per tool result before truncation

_PHASE2_TOOL_NAMES = {
    "get_user_timeline",
    "get_host_activity_summary",
    "get_concurrent_sessions",
    "get_lateral_movement_path",
    "get_host_centrality",
    "get_host_neighbors",
    "get_user_historical_baseline",
}

# ---------------------------------------------------------------------------
# Phase 2 tool dispatch and schemas — entity-centric tools only.
# Behavioral tools are Phase 1 (orchestrator-level Cypher, not LLM tools).
# get_host_neighbors excluded — implementation commented out in topology_server.
# get_lateral_movement_path takes `username` per actual server implementation.
# ---------------------------------------------------------------------------

_TOOL_DISPATCH: dict[str, callable] = {
    "get_lateral_movement_path": topology_server.get_lateral_movement_path,
    "get_host_centrality": topology_server.get_host_centrality,
    "get_user_timeline": investigation_server.get_user_timeline,
    "get_host_activity_summary": investigation_server.get_host_activity_summary,
    "get_concurrent_sessions": investigation_server.get_concurrent_sessions,
    "get_user_historical_baseline": investigation_server.get_user_historical_baseline,
}

_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_lateral_movement_path",
            "description": (
                "Reconstruct the authentication chain for a user within the window. "
                "Returns the ordered sequence of hosts the user authenticated to, "
                "sorted chronologically. A rapid multi-host sequence (many hosts in "
                "a short time span) is worth examining, but many legitimate users "
                "authenticate to several hosts — it is not sufficient on its own."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "LANL username (e.g. 'U456@DOM1')",
                    },
                    "start_time": {
                        "type": "integer",
                        "description": "Window start — LANL internal integer (elapsed seconds)",
                    },
                    "end_time": {
                        "type": "integer",
                        "description": "Window end — LANL internal integer (elapsed seconds)",
                    },
                },
                "required": ["username", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_host_centrality",
            "description": (
                "Approximate betweenness centrality for a host by counting distinct "
                "users authenticating to it within the window. High unique_users "
                "indicates a pivot point host — compromising it grants access to many "
                "credentials."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "computer": {
                        "type": "string",
                        "description": "Target computer name (e.g. 'C17')",
                    },
                    "start_time": {
                        "type": "integer",
                        "description": "Window start — LANL internal integer (elapsed seconds)",
                    },
                    "end_time": {
                        "type": "integer",
                        "description": "Window end — LANL internal integer (elapsed seconds)",
                    },
                },
                "required": ["computer", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_timeline",
            "description": (
                "Return a full chronological event timeline for a user, interleaving "
                "authentication and process events within the investigation window. "
                "Enables sequence reasoning — e.g., auth to host at T=5000 followed by "
                "novel process execution at T=5003 is a high-severity signal."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "LANL username (e.g. 'U456@DOM1')",
                    },
                    "start_time": {
                        "type": "integer",
                        "description": "Window start — LANL internal integer (elapsed seconds)",
                    },
                    "end_time": {
                        "type": "integer",
                        "description": "Window end — LANL internal integer (elapsed seconds)",
                    },
                },
                "required": ["username", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_host_activity_summary",
            "description": (
                "Return all activity on a given host within the investigation window — "
                "all users, all processes, all auth events. Use this to assess the "
                "blast radius of a potentially compromised host."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "computer": {
                        "type": "string",
                        "description": "Target computer name (e.g. 'C17')",
                    },
                    "start_time": {
                        "type": "integer",
                        "description": "Window start — LANL internal integer (elapsed seconds)",
                    },
                    "end_time": {
                        "type": "integer",
                        "description": "Window end — LANL internal integer (elapsed seconds)",
                    },
                },
                "required": ["computer", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_concurrent_sessions",
            "description": (
                "Find users who successfully authenticated to the same host at "
                "approximately the same time as a suspicious event. Use window=300 "
                "for a ±300 second radius around the event time."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "computer": {
                        "type": "string",
                        "description": "Target computer name (e.g. 'C17')",
                    },
                    "time": {
                        "type": "integer",
                        "description": "Event time — LANL internal integer (elapsed seconds)",
                    },
                    "window": {
                        "type": "integer",
                        "description": "Time radius in seconds on either side of event (default 300)",
                    },
                },
                "required": ["computer", "time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_historical_baseline",
            "description": (
                "Returns the user's historical authentication baseline from before "
                "the investigation window. Use this early in every investigation to "
                "establish what is normal for this user. If distinct_hosts_visited is "
                "high, multi-host activity in the window is not suspicious on its own. "
                "If total_prior_auths is 0, this user has no history — treat all "
                "activity as potentially anomalous. Pass dst_host (the host under "
                "review) to get dst_host_seen_before — an exact answer to whether "
                "the user authenticated to that host before the window "
                "(historical_hosts is capped at 50 and may omit it). History in the "
                "graph spans only a few hours, so avg_daily_auths is approximate."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "LANL username (e.g. 'U456@DOM1')",
                    },
                    "window_start": {
                        "type": "integer",
                        "description": (
                            "Investigation window start (use start_time) — LANL internal "
                            "integer. Only successful auths before this are counted."
                        ),
                    },
                    "dst_host": {
                        "type": "string",
                        "description": "Optional — the host under review (e.g. 'C17')",
                    },
                },
                "required": ["username", "window_start"],
            },
        },
    },
]

_PHASE2_TOOLS = [
    t for t in _TOOLS
    if t["function"]["name"] in _PHASE2_TOOL_NAMES
]

# ---------------------------------------------------------------------------
# Phase 1 — Discovery: direct Neo4j queries, no entity inputs required.
# These queries scan the full graph within the time window to surface
# candidate suspicious users by behavioral signal only.
# ---------------------------------------------------------------------------

# Users with high auth failure rate OR many distinct authentication targets.
_AUTH_ANOMALY_DISCOVERY_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH u,
     count(a) AS total_attempts,
     sum(CASE WHEN a.status = 'Fail' THEN 1 ELSE 0 END) AS failed_attempts,
     count(DISTINCT c) AS unique_targets
WITH u, total_attempts, failed_attempts, unique_targets,
     CASE WHEN total_attempts > 0
          THEN round(toFloat(failed_attempts) / toFloat(total_attempts) * 100, 2)
          ELSE 0.0 END AS failure_rate_pct
WHERE failure_rate_pct > 30.0 OR unique_targets >= 4
RETURN u.username AS username, total_attempts, failed_attempts,
       failure_rate_pct, unique_targets
ORDER BY failure_rate_pct DESC, unique_targets DESC
LIMIT 20
"""

# Users who successfully authenticated to hosts they had never accessed before.
_FIRST_TIME_AUTH_DISCOVERY_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time AND a.status = 'Success'
WITH u, c, min(a.time) AS first_seen_in_window
WHERE NOT EXISTS {
    MATCH (u)-[prev:AUTHENTICATED_TO]->(c)
    WHERE prev.time < $start_time AND prev.status = 'Success'
}
WITH u, count(c) AS new_host_count
WHERE new_host_count >= 1
RETURN u.username AS username, new_host_count
ORDER BY new_host_count DESC
LIMIT 20
"""

# Users who executed processes on hosts they had never run those processes on before.
_PROCESS_ANOMALY_DISCOVERY_QUERY = """
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time < 150000 AND a.status = 'Success'
WITH u, collect(DISTINCT c.name) AS historical_hosts
MATCH (u)-[b:AUTHENTICATED_TO]->(c2:Computer)
WHERE b.time >= 150000 AND b.time <= 157200 AND b.status = 'Success'
WITH u, historical_hosts, collect(DISTINCT c2.name) AS window_hosts
WITH u, 
     [h IN window_hosts WHERE NOT h IN historical_hosts] AS new_hosts
WHERE size(new_hosts) >= 1
RETURN u.username AS username, size(new_hosts) AS new_host_count
ORDER BY new_host_count DESC
LIMIT 20
"""


def _estimate_tokens(messages: list[dict], tools: list[dict]) -> int:
    import tiktoken
    enc = tiktoken.encoding_for_model("gpt-4o")
    text = json.dumps(messages) + json.dumps(tools)
    return len(enc.encode(text))


def _run_discovery_query(query: str, params: dict) -> list[dict]:
    """Execute a Cypher query directly against Neo4j, return rows as plain dicts."""
    driver = GraphDatabase.driver(_NEO4J_URI, auth=(_NEO4J_USER, _NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            result = session.run(query, params)
            return [dict(record) for record in result]
    finally:
        driver.close()


def _discover_candidates(start_time: int, end_time: int) -> dict:
    """
    Run three time-range-only discovery queries to surface suspicious users.

    No usernames or hostnames are provided as inputs — the queries scan the
    full graph within the window and return entities ranked by behavioral signal.

    Args:
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        {
            "auth_anomaly_users":    list[str],
            "first_time_auth_users": list[str],
            "process_anomaly_users": list[str],
            "ranked_candidates":     list[str],  # top 3 by cross-tool frequency
            "tool_calls_made":       int,         # always 3
        }
    """
    params = {"start_time": start_time, "end_time": end_time}

    try:
        auth_rows = _run_discovery_query(_AUTH_ANOMALY_DISCOVERY_QUERY, params)
    except neo4j_exceptions.Neo4jError:
        auth_rows = []

    try:
        first_time_rows = _run_discovery_query(_FIRST_TIME_AUTH_DISCOVERY_QUERY, params)
    except neo4j_exceptions.Neo4jError:
        first_time_rows = []

    try:
        proc_rows = _run_discovery_query(_PROCESS_ANOMALY_DISCOVERY_QUERY, params)
    except neo4j_exceptions.Neo4jError:
        proc_rows = []

    auth_users = [r["username"] for r in auth_rows]
    first_time_users = [r["username"] for r in first_time_rows]
    proc_users = [r["username"] for r in proc_rows]

    freq: Counter = Counter()
    for u in auth_users:
        freq[u] += 1
    for u in first_time_users:
        freq[u] += 1
    for u in proc_users:
        freq[u] += 1

    ranked = [u for u, _ in freq.most_common(3)]

    return {
        "auth_anomaly_users": auth_users,
        "first_time_auth_users": first_time_users,
        "process_anomaly_users": proc_users,
        "ranked_candidates": ranked,
        "tool_calls_made": 3,
    }


# ---------------------------------------------------------------------------
# System prompt — built dynamically with Phase 1 candidates injected.
# ---------------------------------------------------------------------------

def _build_system_prompt(
    candidates: list[str],
    start_time: int,
    end_time: int,
    event_mode: bool = False,
) -> str:
    """
    Build the Phase 2 system prompt.

    event_mode=False (investigate_window): candidates came from Phase 1 discovery.
    event_mode=True  (investigate_event):  a single case under review with no
    prior flagging — framed neutrally so the model is not primed to find guilt.
    """
    candidate_str = ", ".join(candidates)
    if event_mode:
        framing = f"""Each case is a (username, host, timestamp) tuple drawn from the active network window. Your job is to determine from the evidence whether this specific authentication event is consistent with legitimate user behavior or indicative of lateral movement.

USER UNDER REVIEW: {candidate_str}"""
    else:
        framing = f"""Phase 1 discovery is already complete. The following candidate users were identified from behavioral signals (high authentication failure rates, first-time authentications to new hosts, novel process executions):

CANDIDATES: {candidate_str}"""

    return f"""You are a security investigator. Never assume who is suspicious — let the data tell you.

{framing}

---

INVESTIGATION

Investigate using the available tools. Use start_time={start_time} and end_time={end_time} for all tool calls that require a time window.

Always call get_user_historical_baseline first (with window_start={start_time}, and dst_host set to the host under review when there is one) to establish what is normal for this user before interpreting activity in the investigation window.

RULES:
- Do not call all tools blindly — use judgment about which tools add signal.
- Do not repeat tool calls with identical parameters.
- Time values are LANL internal integers, not Unix timestamps.
- A rapid sequence of authentications to multiple hosts is worth examining, but on its own it is not evidence of lateral movement (see severity criteria below).
- If a tool returns empty results, note it and move on.
- You have a limited tool call budget. Prioritize the most informative tools.

---

FINAL OUTPUT FORMAT

Severity criteria:
- HIGH: Clear evidence of lateral movement in the investigation window — the user authenticated to multiple hosts in rapid succession AND this is corroborated by other signals in the tool results (authentication to hosts absent from the user's historical baseline, a high proportion of failed authentications, process execution on a destination host shortly after authenticating to it, or a burst that departs sharply from the rest of the user's activity in the window), OR the host shows failure spikes that cannot be explained by normal activity.
- MEDIUM: Ambiguous — some suspicious signals present but insufficient to confirm lateral movement. Requires analyst review.
- LOW: No meaningful evidence of lateral movement. Single-host activity, low event volume, or behavior consistent with normal operations.

Important: multi-host authentication alone is NOT sufficient for HIGH or MEDIUM. Many legitimate users authenticate to multiple hosts during normal operations. Elevation requires corroborating signals visible in the tool results, such as authentication to hosts absent from the user's historical baseline, a high proportion of failed authentications, process execution following an authentication, or an abrupt change in the user's activity within the window. Authenticating to a host the user has used before is weak evidence on its own. get_user_historical_baseline is the only tool that looks before the investigation window — all other tools cover the window only.

After investigation, produce exactly this structure — nothing before it:

SEVERITY: HIGH / MEDIUM / LOW
FLAGGED_USERS: comma-separated list of suspicious usernames (or NONE)
FLAGGED_HOSTS: comma-separated list of suspicious host names (or NONE)
NARRATIVE: [one to three paragraphs — summarize evidence, attack path if found, and reasoning]"""


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

_SEVERITY_RE = re.compile(r"SEVERITY\s*:\s*(HIGH|MEDIUM|LOW)", re.IGNORECASE)
_FLAGGED_USERS_RE = re.compile(r"FLAGGED_USERS\s*:\s*([^\n]+)", re.IGNORECASE)
_FLAGGED_HOSTS_RE = re.compile(r"FLAGGED_HOSTS\s*:\s*([^\n]+)", re.IGNORECASE)


def _parse_llm_output(text: str) -> tuple[str, list[str], list[str]]:
    """Parse severity, flagged_users, flagged_hosts from LLM verdict text."""
    print(f"[DBG][parse] Raw LLM output ({len(text)} chars):")
    print(f"[DBG][parse] ---\n{text}\n[DBG][parse] ---")

    severity_match = _SEVERITY_RE.search(text)
    severity = severity_match.group(1).upper() if severity_match else "LOW"

    users_match = _FLAGGED_USERS_RE.search(text)
    if users_match:
        raw = users_match.group(1).strip()
        flagged_users = (
            []
            if raw.upper() == "NONE"
            else [u.strip() for u in raw.split(",") if u.strip()]
        )
        print(f"[DBG][parse] FLAGGED_USERS raw: {raw!r} → {flagged_users}")
    else:
        flagged_users = []
        print(f"[DBG][parse] FLAGGED_USERS: NO MATCH")

    hosts_match = _FLAGGED_HOSTS_RE.search(text)
    if hosts_match:
        raw = hosts_match.group(1).strip()
        flagged_hosts = (
            []
            if raw.upper() == "NONE"
            else [h.strip() for h in raw.split(",") if h.strip()]
        )
        print(f"[DBG][parse] FLAGGED_HOSTS raw: {raw!r} → {flagged_hosts}")
    else:
        flagged_hosts = []
        print(f"[DBG][parse] FLAGGED_HOSTS: NO MATCH")

    print(f"[DBG][parse] Final → severity={severity}, users={flagged_users}, hosts={flagged_hosts}")
    return severity, flagged_users, flagged_hosts


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def investigate_window(start_time: int, end_time: int) -> dict:
    """
    Run a blind two-phase investigation over a time window.

    No entity identities (usernames, hostnames) are accepted as inputs.
    The agent discovers suspicious entities from behavioral signals alone.

    Phase 1 (Discovery):
        Orchestrator runs three time-range-only Cypher queries to surface
        candidate suspicious users without knowing who is suspicious.
        If zero candidates are found, returns early with severity=LOW.

    Phase 2 (Investigation):
        LLM investigates the top-3 candidates using entity-centric tools
        (topology + investigation). The LLM decides which tools to call
        per candidate. A hard cap of max_iterations=20 total tool calls
        is enforced.

    Args:
        start_time: Window start — LANL internal integer (elapsed seconds)
        end_time:   Window end   — LANL internal integer (elapsed seconds)

    Returns:
        {
            "window":          {"start": int, "end": int},
            "flagged_users":   list[str],
            "flagged_hosts":   list[str],
            "verdict":         str,   # FREE_TEXT — LLM narrative
            "severity":      str,   # HIGH / MEDIUM / LOW
            "tool_calls_made": int,   # Phase 1 (3) + Phase 2 LLM tool calls
        }

    Raises:
        RuntimeError: If Phase 2 LLM tool calls exceed max_iterations.
    """
    # --- Phase 1: Discovery (orchestrator-level, no LLM) ---
    print(f"Running Phase 1 (Discovery) across time window: {start_time}-{end_time}")
    discovery = _discover_candidates(start_time, end_time)
    candidates = discovery["ranked_candidates"]
    tool_calls_made = discovery["tool_calls_made"]  # 3 discovery queries

    # Primary cost-control gate: no candidates → no Phase 2
    if not candidates:
        return {
            "window": {"start": start_time, "end": end_time},
            "flagged_users": [],
            "flagged_hosts": [],
            "verdict": "No anomalies detected in window.",
            "severity": "LOW",
            "tool_calls_made": tool_calls_made,
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
    print(f"Potentially malicious users identified. Investigating...")
    # --- Phase 2: LLM Investigation ---
    system_prompt = _build_system_prompt(candidates, start_time, end_time)
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Investigate the candidate entities identified in Phase 1 "
                f"for time window [{start_time}, {end_time}]. "
                f"Produce your final output after investigation."
            ),
        },
    ]

    model = f"openai/{_NAVIGATOR_MODEL}"
    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    while True:
        estimated = _estimate_tokens(messages, _PHASE2_TOOLS)
        if estimated > 50000:
            raise RuntimeError(
                f"Context too large before LLM call: ~{estimated} tokens. "
                f"Window [{start_time}, {end_time}] aborted."
            )

        response = litellm.completion(
            base_url=_NAVIGATOR_BASE_URL,
            model=model,
            messages=messages,
            tools=_PHASE2_TOOLS,
            max_tokens=1000,
            temperature=0,
        )

        if response.usage:
            token_usage["prompt_tokens"] += response.usage.prompt_tokens or 0
            token_usage["completion_tokens"] += response.usage.completion_tokens or 0
            token_usage["total_tokens"] += response.usage.total_tokens or 0

        choice = response.choices[0]
        assistant_message = choice.message
        messages.append(assistant_message.model_dump(exclude_none=True))

        # No tool calls — LLM has produced its final verdict
        if not assistant_message.tool_calls:
            verdict_text = assistant_message.content or ""
            severity, flagged_users, flagged_hosts = _parse_llm_output(verdict_text)
            return {
                "window": {"start": start_time, "end": end_time},
                "flagged_users": flagged_users,
                "flagged_hosts": flagged_hosts,
                "verdict": verdict_text,
                "severity": severity,
                "tool_calls_made": tool_calls_made,
                "token_usage": token_usage,
            }

        # Execute each tool call and append results
        for tool_call in assistant_message.tool_calls:
            if tool_calls_made >= _MAX_ITERATIONS:
                raise RuntimeError(
                    f"Exceeded max_iterations={_MAX_ITERATIONS} tool calls "
                    f"in window [{start_time}, {end_time}]"
                )

            tool_name = tool_call.function.name
            tool_args = json.loads(tool_call.function.arguments)
            tool_calls_made += 1

            if tool_name not in _TOOL_DISPATCH:
                result = json.dumps({"error": f"Unknown tool: {tool_name}"})
            else:
                try:
                    result = _TOOL_DISPATCH[tool_name](**tool_args)
                except Exception as exc:
                    result = json.dumps({"error": str(exc), "tool": tool_name})

            result_str = result if isinstance(result, str) else json.dumps(result)
            if len(result_str) > MAX_RESULT_CHARS:
                result_str = result_str[:MAX_RESULT_CHARS] + "\n...[truncated]"
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result_str,
            })


def investigate_event(
    username: str,
    dst_host: str,
    timestamp: int,
) -> dict:
    """
    Entity-seeded investigation for a single red team event.

    Accepts a known username and destination host from a redteam.txt event,
    plus the event timestamp. Used for pilot evaluation where entity identity
    is known but the agent must still characterize the activity independently
    using graph tools.

    The agent receives no label — it does not know this is a confirmed
    red team event. It must determine severity from behavioral signals alone.

    Args:
        username:  LANL username, e.g. 'U620@DOM1'
        dst_host:  Destination computer, e.g. 'C1003'
        timestamp: LANL internal integer (elapsed seconds)

    Returns:
        {
            "event":           {"username": str, "dst_host": str, "timestamp": int},
            "flagged_users":   list[str],
            "flagged_hosts":   list[str],
            "verdict":         str,
            "severity":        str,   # HIGH / MEDIUM / LOW
            "tool_calls_made": int,
        }
    """
    start_time = timestamp - 3600
    end_time = timestamp + 3600

    print(f"[DBG][event] investigate_event: user={username!r} dst_host={dst_host!r} timestamp={timestamp}")
    print(f"[DBG][event] time window: [{start_time}, {end_time}]")
    print(f"[DBG][event] model={_NAVIGATOR_MODEL!r}  base_url={_NAVIGATOR_BASE_URL!r}")

    system_prompt = _build_system_prompt(
        candidates=[username],
        start_time=start_time,
        end_time=end_time,
        event_mode=True,
    )
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Investigate user {username} and host {dst_host} for potential "
                f"lateral movement around time {timestamp}. "
                f"Use start_time={start_time} and end_time={end_time} for all "
                f"tool calls. For get_concurrent_sessions use time={timestamp} "
                f"and window=300."
            ),
        },
    ]

    model = f"openai/{_NAVIGATOR_MODEL}"
    tool_calls_made = 0
    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    while True:
        estimated = _estimate_tokens(messages, _PHASE2_TOOLS)
        print(f"[DBG][event] LLM call #{tool_calls_made + 1} — estimated tokens: {estimated}")
        if estimated > 50000:
            raise RuntimeError(
                f"Context too large before LLM call: ~{estimated} tokens. "
                f"Event [{username}, {dst_host}, {timestamp}] aborted."
            )

        response = litellm.completion(
            base_url=_NAVIGATOR_BASE_URL,
            model=model,
            messages=messages,
            tools=_PHASE2_TOOLS,
            max_tokens=1000,
            temperature=0,
        )

        if response.usage:
            token_usage["prompt_tokens"] += response.usage.prompt_tokens or 0
            token_usage["completion_tokens"] += response.usage.completion_tokens or 0
            token_usage["total_tokens"] += response.usage.total_tokens or 0

        choice = response.choices[0]
        assistant_message = choice.message
        print(f"[DBG][event] finish_reason={choice.finish_reason!r}  tool_calls={len(assistant_message.tool_calls) if assistant_message.tool_calls else 0}")
        messages.append(assistant_message.model_dump(exclude_none=True))

        # No tool calls — LLM has produced its final verdict
        if not assistant_message.tool_calls:
            print(f"[DBG][event] LLM returned no tool calls — parsing verdict")
            verdict_text = assistant_message.content or ""
            severity, flagged_users, flagged_hosts = _parse_llm_output(verdict_text)
            print(f"[DBG][event] DONE — severity={severity} tool_calls_made={tool_calls_made} total_tokens={token_usage['total_tokens']}")
            return {
                "event": {"username": username, "dst_host": dst_host, "timestamp": timestamp},
                "flagged_users": flagged_users,
                "flagged_hosts": flagged_hosts,
                "verdict": verdict_text,
                "severity": severity,
                "tool_calls_made": tool_calls_made,
                "token_usage": token_usage,
            }

        # Execute each tool call and append results
        for tool_call in assistant_message.tool_calls:
            if tool_calls_made >= _MAX_ITERATIONS:
                raise RuntimeError(
                    f"Exceeded max_iterations={_MAX_ITERATIONS} tool calls "
                    f"for event [{username}, {dst_host}, {timestamp}]"
                )

            tool_name = tool_call.function.name
            tool_args = json.loads(tool_call.function.arguments)
            tool_calls_made += 1

            print(f"[DBG][event] tool call #{tool_calls_made}: {tool_name}({tool_args})")

            if tool_name not in _TOOL_DISPATCH:
                result = json.dumps({"error": f"Unknown tool: {tool_name}"})
                print(f"[DBG][event] UNKNOWN TOOL: {tool_name!r}")
            else:
                try:
                    result = _TOOL_DISPATCH[tool_name](**tool_args)
                except Exception as exc:
                    result = json.dumps({"error": str(exc), "tool": tool_name})
                    print(f"[DBG][event] tool EXCEPTION: {exc}")

            result_str = result if isinstance(result, str) else json.dumps(result)
            truncated = len(result_str) > MAX_RESULT_CHARS
            if truncated:
                result_str = result_str[:MAX_RESULT_CHARS] + "\n...[truncated]"
            print(f"[DBG][event] tool result ({len(result_str)} chars{', truncated' if truncated else ''}): {result_str[:300]!r}{'...' if len(result_str) > 300 else ''}")
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result_str,
            })


if __name__ == "__main__":
    import pprint

    result = investigate_window(start_time=763200, end_time=770000)
    pprint.pprint(result)
