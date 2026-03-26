"""
Evaluator — evaluator.py

Iterates over data/redteam.txt, sends each event as a blind investigation
prompt to the agent, parses the VERDICT field, and writes structured results
to evaluation/results.json.

redteam.txt format (one event per line):
    timestamp,username,src_host,dst_host

Usage:
    uv run python -m src.evaluation.evaluator
"""

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from src.agent.orchestrator import investigate

load_dotenv()

_REDTEAM_PATH = Path(os.getenv("REDTEAM_PATH", "data/redteam.txt"))
_RESULTS_PATH = Path("evaluation/results.json")

_VERDICT_RE = re.compile(r"VERDICT\s*:\s*(HIGH|MEDIUM|LOW)", re.IGNORECASE)
_PATH_FOUND_RE = re.compile(
    r"(lateral movement path|auth.*chain|pivot_user|auth_from_source_time)",
    re.IGNORECASE,
)
_TOOL_CALL_RE = re.compile(
    r"\b(get_auth_anomalies|get_first_time_authentications|get_process_anomalies"
    r"|get_lateral_movement_path|get_host_centrality|get_host_neighbors"
    r"|get_user_timeline|get_host_activity_summary|get_concurrent_sessions)\b"
)


def _parse_redteam_line(line: str) -> dict | None:
    """Parse a single line from redteam.txt into event fields."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(",")
    if len(parts) < 4:
        return None
    return {
        "timestamp": int(parts[0]),
        "username": parts[1].strip(),
        "src_host": parts[2].strip(),
        "dst_host": parts[3].strip(),
    }


def _parse_verdict(agent_output: str) -> str:
    """Extract VERDICT level from agent output. Returns 'UNKNOWN' if not found."""
    match = _VERDICT_RE.search(agent_output)
    return match.group(1).upper() if match else "UNKNOWN"


def _extract_tool_sequence(agent_output: str) -> list[str]:
    """
    Extract the tool call sequence from the agent output text.
    The orchestrator does not surface the raw tool call list, so we infer
    which tools were invoked by scanning the verdict text for tool names.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for match in _TOOL_CALL_RE.finditer(agent_output):
        name = match.group(1)
        if name not in seen_set:
            seen.append(name)
            seen_set.add(name)
    return seen


def _lateral_path_found(agent_output: str) -> bool:
    """
    Return True if the agent output indicates a lateral movement path was
    reconstructed (i.e. get_lateral_movement_path returned non-empty results).
    Returns False when the output contains 'No direct authentication chain'.
    """
    if re.search(r"no direct auth", agent_output, re.IGNORECASE):
        return False
    return bool(_PATH_FOUND_RE.search(agent_output))


def run_evaluation(redteam_path: Path = _REDTEAM_PATH) -> list[dict]:
    """
    Main evaluation loop.

    Reads redteam.txt line by line, investigates each event, and returns
    a list of result records. Also writes results to evaluation/results.json.
    """
    _RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)

    events = []
    with open(redteam_path, "r") as fh:
        for line in fh:
            parsed = _parse_redteam_line(line)
            if parsed:
                events.append(parsed)

    total = len(events)
    print(f"[evaluator] Loaded {total} events from {redteam_path}")
    print(f"[evaluator] Results will be written to {_RESULTS_PATH}\n")

    results: list[dict] = []
    tp_count = 0
    unknown_count = 0

    for idx, event in enumerate(events, start=1):
        ts = event["timestamp"]
        user = event["username"]
        src = event["src_host"]
        dst = event["dst_host"]

        print(f"[{idx:>4}/{total}] Investigating {user} | {src} → {dst} | T={ts}")

        started_at = time.monotonic()
        try:
            agent_output = investigate(
                username=user,
                source_host=src,
                destination_host=dst,
                timestamp=ts,
            )
            elapsed = time.monotonic() - started_at
            error = None
        except Exception as exc:
            agent_output = ""
            elapsed = time.monotonic() - started_at
            error = str(exc)
            print(f"         ERROR: {error}")

        verdict = _parse_verdict(agent_output)
        is_tp = verdict == "HIGH"
        tool_sequence = _extract_tool_sequence(agent_output)
        path_found = _lateral_path_found(agent_output)

        if is_tp:
            tp_count += 1
        if verdict == "UNKNOWN":
            unknown_count += 1

        result = {
            "event_index": idx,
            "timestamp": ts,
            "username": user,
            "src_host": src,
            "dst_host": dst,
            "verdict": verdict,
            "true_positive": is_tp,
            "lateral_movement_path_found": path_found,
            "tool_call_sequence": tool_sequence,
            "elapsed_seconds": round(elapsed, 2),
            "raw_agent_output": agent_output,
            "error": error,
            "evaluated_at": datetime.utcnow().isoformat() + "Z",
        }
        results.append(result)

        # Running summary after each event
        precision_so_far = tp_count / idx
        print(
            f"         VERDICT={verdict:<7} TP={is_tp} | "
            f"path_found={path_found} | tools={len(tool_sequence)} | "
            f"elapsed={elapsed:.1f}s\n"
            f"         Running: {tp_count}/{idx} HIGH "
            f"({precision_so_far:.1%} of events so far)\n"
        )

        # Flush partial results after each event so progress is not lost
        with open(_RESULTS_PATH, "w") as fh:
            json.dump(
                {
                    "meta": {
                        "total_events": total,
                        "evaluated": idx,
                        "high_verdicts": tp_count,
                        "unknown_verdicts": unknown_count,
                        "run_started": results[0]["evaluated_at"] if results else None,
                    },
                    "results": results,
                },
                fh,
                indent=2,
            )

    # Final summary
    print("=" * 60)
    print(f"[evaluator] Done. {total} events processed.")
    print(f"            HIGH (True Positive): {tp_count}")
    print(f"            MEDIUM/LOW:           {total - tp_count - unknown_count}")
    print(f"            UNKNOWN (parse fail): {unknown_count}")
    print(f"            Results saved to:     {_RESULTS_PATH}")
    print("=" * 60)

    return results


if __name__ == "__main__":
    run_evaluation()
