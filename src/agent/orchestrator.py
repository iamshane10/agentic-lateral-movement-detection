"""
Agent Orchestrator — orchestrator.py

LiteLLM-based orchestrator that connects to Navigator AI (GPT-4o endpoint).
Registers all 9 MCP tool schemas, routes LLM tool_call requests to the
correct server function, and loops until the LLM produces a final verdict.

Usage:
    from src.agent.orchestrator import investigate

    verdict = investigate(
        username="U456@DOM1",
        source_host="C17",
        destination_host="C42",
        timestamp=500000,
    )
    print(verdict)
"""

import json
import os

import litellm
from dotenv import load_dotenv

from src.agent.system_prompt import SYSTEM_PROMPT
from src.servers import behavioral_server, investigation_server, topology_server

load_dotenv()

_NAVIGATOR_BASE_URL = os.getenv("NAVIGATOR_API_BASE")
_NAVIGATOR_MODEL = os.getenv("NAVIGATOR_MODEL", "gpt-oss-20b")

_TOOL_DISPATCH: dict[str, callable] = {
    "get_auth_anomalies": behavioral_server.get_auth_anomalies,
    "get_first_time_authentications": behavioral_server.get_first_time_authentications,
    "get_process_anomalies": behavioral_server.get_process_anomalies,
    "get_host_centrality": topology_server.get_host_centrality,
    "get_lateral_movement_path": topology_server.get_lateral_movement_path,
    "get_host_neighbors": topology_server.get_host_neighbors,
    "get_user_timeline": investigation_server.get_user_timeline,
    "get_host_activity_summary": investigation_server.get_host_activity_summary,
    "get_concurrent_sessions": investigation_server.get_concurrent_sessions,
}

_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_auth_anomalies",
            "description": (
                "Detect abnormal authentication patterns for a user within a time window. "
                "Returns failure rate, unique target count, and auth types used."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "LANL username (e.g. 'U456@DOM1')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
                },
                "required": ["username", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_first_time_authentications",
            "description": (
                "Find user-computer pairs where no prior successful authentication existed "
                "before the investigation window. Strong lateral movement indicator."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "LANL username (e.g. 'U456@DOM1')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
                },
                "required": ["username", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_process_anomalies",
            "description": (
                "Identify processes executed by a user on a specific host that they have "
                "never run there before the investigation window."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "LANL username (e.g. 'U456@DOM1')"},
                    "computer": {"type": "string", "description": "Target computer name (e.g. 'C17')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
                },
                "required": ["username", "computer", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_host_centrality",
            "description": (
                "Approximate betweenness centrality for a host by counting distinct users "
                "authenticating to it. High unique_users indicates a pivot point host."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "computer": {"type": "string", "description": "Target computer name (e.g. 'C17')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
                },
                "required": ["computer", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_lateral_movement_path",
            "description": (
                "Reconstruct the authentication chain between source and destination host "
                "via shared users. time_delta under 300 seconds is a strong lateral movement signal."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source_computer": {"type": "string", "description": "Source computer name (e.g. 'C17')"},
                    "target_computer": {"type": "string", "description": "Destination computer name (e.g. 'C42')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
                },
                "required": ["source_computer", "target_computer", "start_time", "end_time"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_host_neighbors",
            "description": (
                "Return all computers reachable from a given host within one authentication hop. "
                "Defines the blast radius of a compromised host."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "computer": {"type": "string", "description": "Source computer name (e.g. 'C17')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
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
                "authentication and process events within the investigation window."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "LANL username (e.g. 'U456@DOM1')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
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
                "all users, all processes, all auth events."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "computer": {"type": "string", "description": "Target computer name (e.g. 'C17')"},
                    "start_time": {"type": "integer", "description": "Window start — LANL internal integer"},
                    "end_time": {"type": "integer", "description": "Window end — LANL internal integer"},
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
                "Find users who successfully authenticated to the same host at approximately "
                "the same time as the suspicious event. Use window=300."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "computer": {"type": "string", "description": "Target computer name (e.g. 'C17')"},
                    "time": {"type": "integer", "description": "Event time — LANL internal integer"},
                    "window": {"type": "integer", "description": "Time radius in seconds (default 300)"},
                },
                "required": ["computer", "time"],
            },
        },
    },
]


# Core investigation function

def investigate(
    username: str,
    source_host: str,
    destination_host: str,
    timestamp: int,
) -> str:
    """
    Run a full 9-tool investigation for a suspicious event.

    Follows the fixed sequence from REFERENCE.md Section 4.4:
    Phase 1 (behavioral) → Phase 2 (topology) → Phase 3 (investigation).

    Args:
        username:         LANL username (e.g. 'U456@DOM1')
        source_host:      Source computer name (e.g. 'C17')
        destination_host: Destination computer name (e.g. 'C42')
        timestamp:        Event time — LANL internal integer (elapsed seconds)

    Returns:
        Full verdict text produced by the LLM, including VERDICT, EVIDENCE
        SUMMARY, ATTACK PATH, and CONFIDENCE REASONING sections.

    Raises:
        RuntimeError: If the LLM does not produce a final verdict after
                      exhausting the tool call loop.
    """
    start_time = timestamp - 3600
    end_time = timestamp + 3600

    investigation_prompt = (
        f"Investigate potential suspicious activity involving user {username} "
        f"between host {source_host} and host {destination_host} "
        f"around time {timestamp}."
    )

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"{investigation_prompt}\n\n"
                f"Use start_time={start_time} and end_time={end_time} for all tool calls. "
                f"For get_concurrent_sessions use time={timestamp} and window=300. "
                f"For get_process_anomalies use computer={destination_host}."
            ),
        },
    ]

    model = f"openai/{_NAVIGATOR_MODEL}"

    while True:
        response = litellm.completion(
            base_url=_NAVIGATOR_BASE_URL,
            model=model,
            messages=messages,
            tools=_TOOLS,
        )

        choice = response.choices[0]
        assistant_message = choice.message

        # Append assistant turn (may contain tool_calls or final text)
        messages.append(assistant_message.model_dump(exclude_none=True))

        # No tool calls — LLM has produced its final verdict
        if not assistant_message.tool_calls:
            return assistant_message.content or ""

        # Execute each tool call and append results
        for tool_call in assistant_message.tool_calls:
            tool_name = tool_call.function.name
            tool_args = json.loads(tool_call.function.arguments)

            if tool_name not in _TOOL_DISPATCH:
                result = json.dumps({"error": f"Unknown tool: {tool_name}"})
            else:
                try:
                    result = _TOOL_DISPATCH[tool_name](**tool_args)
                except Exception as exc:
                    result = json.dumps({"error": str(exc), "tool": tool_name})

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result,
            })

if __name__ == "__main__":
    verdict = investigate(
        username="U620@DOM1",
        source_host="C17693",
        destination_host="C1003",
        timestamp=150885,
    )
    print(verdict)