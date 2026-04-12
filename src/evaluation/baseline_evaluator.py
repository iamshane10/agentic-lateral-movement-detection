"""
baseline_evaluator.py

Static Cypher baseline for lateral movement detection.
Deterministic, rule-based detector — no LLM, no tool calls.
Serves as a comparison baseline against the LLM-orchestrated agent.

Each event is scored by three independent signals drawn from the Phase 1
discovery queries in REFERENCE.md Section 4.2. Severity is escalated via
a lateral movement path check when the score threshold is met.

    Signal 1 — Auth anomaly        (+2 pts): failure_rate > 30% OR unique_targets >= 4
    Signal 2 — First-time auth     (+2 pts): any Success auth to a host never seen before window
    Signal 3 — Historical novelty  (+1 pt):  any window host absent from pre-window history

    Score >= 3  →  path check  →  HIGH (distinct hosts >= 3) or MEDIUM
    Score <  3  →  LOW, no flagging

Entry points:
    evaluate_baseline(username, dst_host, timestamp) -> dict
    run_baseline_evaluation(redteam_path, sample_size) -> None

Usage:
    uv run python -m src.evaluation.baseline_cypher
    uv run python -m src.evaluation.baseline_cypher --sample-size 20
"""

import argparse
import json
import os
import random
import sys
import time as time_module
from datetime import datetime
from pathlib import Path

# Ensure project root is on sys.path when run directly as a script.
# Has no effect when invoked via `python -m src.evaluation.baseline_cypher`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

_REDTEAM_PATH     = Path(os.getenv("REDTEAM_PATH", "data/redteam.txt"))
_COLD_EVENTS_PATH = Path("data/cold_events.txt")
_RESULTS_PATH     = Path("evaluation/baseline_results.json")

# Hot window for TP cases — matches run_entity_evaluation() in evaluator.py
_HOT_WINDOW_START = 763200
_HOT_WINDOW_END   = 770400


# ---------------------------------------------------------------------------
# Cypher — Signal 1: Auth anomaly (Phase 1 Query 1, scoped to one user)
# Flag if failure_rate_pct > 30.0 OR unique_targets >= 4
# ---------------------------------------------------------------------------
_SIGNAL1_QUERY = """
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH u,
     count(a) AS total_attempts,
     sum(CASE WHEN a.status = 'Fail' THEN 1 ELSE 0 END) AS failed_attempts,
     count(DISTINCT c) AS unique_targets
WITH u, total_attempts, failed_attempts, unique_targets,
     CASE WHEN total_attempts > 0
          THEN round(toFloat(failed_attempts) / toFloat(total_attempts) * 100, 2)
          ELSE 0.0 END AS failure_rate_pct
RETURN failure_rate_pct, unique_targets
"""

# ---------------------------------------------------------------------------
# Cypher — Signal 2: First-time authentication (Phase 1 Query 2, one user)
# Flag if any Success auth to a host with no pre-window Success auth exists.
# ---------------------------------------------------------------------------
_SIGNAL2_QUERY = """
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = 'Success'
WITH u, c, min(a.time) AS first_seen_in_window
WHERE NOT EXISTS {
    MATCH (u)-[prev:AUTHENTICATED_TO]->(c)
    WHERE prev.time < $start_time AND prev.status = 'Success'
}
RETURN count(c) AS new_host_count
"""

# ---------------------------------------------------------------------------
# Cypher — Signal 3: Historical host novelty (Phase 1 Query 3, parameterised)
# Starts from window hosts so a user with zero history is still flagged.
# Flag if any window host was absent from the user's pre-window baseline.
# ---------------------------------------------------------------------------
_SIGNAL3_QUERY = """
MATCH (u:User {username: $username})-[b:AUTHENTICATED_TO]->(c2:Computer)
WHERE b.time >= $start_time AND b.time <= $end_time
AND b.status = 'Success'
WITH u, collect(DISTINCT c2.name) AS window_hosts
OPTIONAL MATCH (u)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time < $start_time AND a.status = 'Success'
WITH u, window_hosts, collect(DISTINCT c.name) AS historical_hosts
WITH u, window_hosts, historical_hosts,
     [h IN window_hosts WHERE NOT h IN historical_hosts] AS new_hosts
RETURN size(new_hosts) AS new_host_count
"""

# ---------------------------------------------------------------------------
# Cypher — Severity escalation: count distinct hosts accessed in window.
# Derived from get_lateral_movement_path in REFERENCE.md Section 3.
# HIGH if distinct_hosts >= 3, MEDIUM otherwise.
# ---------------------------------------------------------------------------
_PATH_QUERY = """
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = 'Success'
RETURN count(DISTINCT c) AS distinct_hosts
"""


# ---------------------------------------------------------------------------
# Core evaluation function
# ---------------------------------------------------------------------------

def evaluate_baseline(username: str, dst_host: str, timestamp: int) -> dict:
    """
    Score a single entity with three deterministic Cypher signal checks.

    Time window: [timestamp - 3600, timestamp + 3600].

    Returns a dict matching the agent's output schema:
        {
            "flagged_users":   list[str],
            "flagged_hosts":   list[str],
            "severity":        "HIGH" | "MEDIUM" | "LOW",
            "tool_calls_made": 0,
            "verdict":         str,   # human-readable summary of fired rules
        }
    """
    start_time = timestamp - 3600
    end_time   = timestamp + 3600

    neo4j_uri      = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user     = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "password")

    params = {
        "username":   username,
        "start_time": start_time,
        "end_time":   end_time,
    }

    score = 0
    fired_signals: list[str] = []

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    try:
        # --- Signal 1: Auth anomaly ---
        with driver.session() as session:
            row = session.run(_SIGNAL1_QUERY, params).single()
        if row is not None:
            failure_rate   = row["failure_rate_pct"] or 0.0
            unique_targets = row["unique_targets"]   or 0
            if failure_rate > 30.0 or unique_targets >= 4:
                score += 2
                fired_signals.append(
                    f"Signal1(auth_anomaly: failure_rate={failure_rate:.1f}%, "
                    f"unique_targets={unique_targets})"
                )

        # --- Signal 2: First-time authentication ---
        with driver.session() as session:
            row = session.run(_SIGNAL2_QUERY, params).single()
        if row is not None:
            new_host_count = row["new_host_count"] or 0
            if new_host_count >= 1:
                score += 2
                fired_signals.append(
                    f"Signal2(first_time_auth: {new_host_count} new host(s))"
                )

        # --- Signal 3: Historical host novelty ---
        with driver.session() as session:
            row = session.run(_SIGNAL3_QUERY, params).single()
        if row is not None:
            new_host_count = row["new_host_count"] or 0
            if new_host_count >= 1:
                score += 1
                fired_signals.append(
                    f"Signal3(host_novelty: {new_host_count} host(s) not in history)"
                )

        # --- Severity escalation when score crosses threshold ---
        if score >= 3:
            with driver.session() as session:
                row = session.run(_PATH_QUERY, params).single()
            distinct_hosts = (row["distinct_hosts"] or 0) if row is not None else 0
            severity       = "HIGH" if distinct_hosts >= 3 else "MEDIUM"
            flagged_users  = [username]
            flagged_hosts  = [dst_host]
            verdict = (
                f"FLAGGED: score={score}/5. "
                f"Signals fired: {'; '.join(fired_signals)}. "
                f"Lateral path: {distinct_hosts} distinct host(s) in window → {severity}."
            )
        else:
            severity      = "LOW"
            flagged_users = []
            flagged_hosts = []
            verdict = (
                f"NOT FLAGGED: score={score}/5 (threshold 3). "
                + (
                    f"Signals fired: {'; '.join(fired_signals)}."
                    if fired_signals
                    else "No signals fired."
                )
            )
    finally:
        driver.close()

    return {
        "flagged_users":   flagged_users,
        "flagged_hosts":   flagged_hosts,
        "severity":        severity,
        "tool_calls_made": 0,
        "verdict":         verdict,
    }


# ---------------------------------------------------------------------------
# Parsing helper — standalone, no import from evaluator.py
# ---------------------------------------------------------------------------

def _parse_events(path: Path) -> list[dict]:
    """Parse a redteam.txt or cold_events.txt file into event dicts."""
    events = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            events.append({
                "timestamp": int(parts[0]),
                "username":  parts[1].strip(),
                "src_host":  parts[2].strip(),
                "dst_host":  parts[3].strip(),
            })
    return events


def _score_outcome(is_redteam: bool, severity: str) -> str:
    """Return TP / TN / FP / FN from ground-truth label and severity."""
    flagged = severity in {"HIGH", "MEDIUM"}
    if is_redteam and flagged:
        return "TP"
    if not is_redteam and not flagged:
        return "TN"
    if not is_redteam and flagged:
        return "FP"
    return "FN"  # is_redteam and not flagged


# ---------------------------------------------------------------------------
# Batch evaluation
# ---------------------------------------------------------------------------

def run_baseline_evaluation(
    redteam_path: str = str(_REDTEAM_PATH),
    sample_size: int = 12,
) -> None:
    """
    Run baseline evaluation over a balanced set of red team and control cases.

    Mirrors the structure of run_entity_evaluation() in evaluator.py:
        TP cases  ← hot window events [763200, 770400] from redteam.txt
        FP cases  ← data/cold_events.txt (generated by generate_cold_events.py)
        Balance   ← min(len(tp), len(controls))

    Scores each case as TP / TN / FP / FN, computes precision / recall / F1,
    and writes results to evaluation/baseline_results.json.

    Args:
        redteam_path: Path to redteam.txt
        sample_size:  Max number of red team TP cases (default: 12)
    """
    run_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    _RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)

    eval_wall_start = time_module.monotonic()

    # --- Step 1: TP cases from hot window ---
    all_rt_events = _parse_events(Path(redteam_path))
    hot_events = [
        e for e in all_rt_events
        if _HOT_WINDOW_START <= e["timestamp"] <= _HOT_WINDOW_END
    ]
    redteam_usernames: set[str] = {e["username"] for e in all_rt_events}

    random.shuffle(hot_events)
    tp_events = hot_events[:sample_size]
    n_redteam = len(tp_events)

    print(f"[baseline] redteam_path={redteam_path!r}")
    print(
        f"[baseline] hot window [{_HOT_WINDOW_START}, {_HOT_WINDOW_END}]: "
        f"{len(hot_events)} events → {n_redteam} TP cases selected"
    )

    # --- Step 2: Control cases from cold_events.txt ---
    if not _COLD_EVENTS_PATH.exists():
        raise FileNotFoundError(
            f"cold_events.txt not found at {_COLD_EVENTS_PATH}. "
            "Run: uv run python -m src.evaluation.generate_cold_events"
        )
    cold_all = _parse_events(_COLD_EVENTS_PATH)
    cold_all = [e for e in cold_all if e["username"] not in redteam_usernames]
    random.shuffle(cold_all)
    controls = cold_all[:sample_size]

    print(
        f"[baseline] cold_events.txt: {len(cold_all)} rows after redteam exclusion "
        f"→ {len(controls)} control cases selected"
    )
    if len(controls) < n_redteam:
        print(
            f"[baseline] Warning: only {len(controls)} control events available, "
            f"requested {n_redteam}"
        )

    # --- Step 3: Balance and shuffle ---
    n_cases = min(n_redteam, len(controls))
    cases: list[dict] = []
    for event in tp_events[:n_cases]:
        cases.append({
            "username":   event["username"],
            "dst_host":   event["dst_host"],
            "timestamp":  event["timestamp"],
            "src_host":   event["src_host"],
            "is_redteam": True,
        })
    for event in controls[:n_cases]:
        cases.append({
            "username":   event["username"],
            "dst_host":   event["dst_host"],
            "timestamp":  event["timestamp"],
            "src_host":   event["src_host"],
            "is_redteam": False,
        })
    random.shuffle(cases)

    total_cases = len(cases)
    print(f"[baseline] Total cases: {total_cases} ({n_cases} TP + {n_cases} control)")
    print(f"[baseline] Results → {_RESULTS_PATH}\n")

    # --- Step 4: Evaluate sequentially (no LLM — concurrency not needed) ---
    results: list[dict] = []
    tp_count = tn_count = fp_count = fn_count = 0

    for idx, case in enumerate(cases, start=1):
        username  = case["username"]
        dst_host  = case["dst_host"]
        timestamp = case["timestamp"]

        wall_start = time_module.monotonic()
        try:
            result = evaluate_baseline(username, dst_host, timestamp)
            error  = None
        except Exception as exc:
            result = {
                "flagged_users":   [],
                "flagged_hosts":   [],
                "severity":        "LOW",
                "tool_calls_made": 0,
                "verdict":         "",
            }
            error = str(exc)
            print(f"[baseline]   ERROR for {username!r}: {error}")

        elapsed = round(time_module.monotonic() - wall_start, 2)
        outcome = _score_outcome(case["is_redteam"], result["severity"])

        if outcome == "TP":
            tp_count += 1
        elif outcome == "TN":
            tn_count += 1
        elif outcome == "FP":
            fp_count += 1
        else:
            fn_count += 1

        entry = {
            "event": {
                "username":  username,
                "dst_host":  dst_host,
                "timestamp": timestamp,
            },
            "is_redteam":      case["is_redteam"],
            "flagged_users":   result["flagged_users"],
            "flagged_hosts":   result["flagged_hosts"],
            "severity":        result["severity"],
            "tool_calls_made": 0,
            "verdict":         result["verdict"],
            "outcome":         outcome,
            "error":           error,
            "elapsed_seconds": elapsed,
            "evaluated_at":    datetime.utcnow().isoformat() + "Z",
        }
        results.append(entry)

        # Flush incrementally so partial results survive a crash
        with open(_RESULTS_PATH, "w") as fh:
            json.dump({"results": results}, fh, indent=2)

        print(
            f"[{idx:>3}/{total_cases}] {username!r} → {dst_host!r}  "
            f"severity={result['severity']:<6}  outcome={outcome}  {elapsed:.2f}s"
        )

    total_elapsed = round(time_module.monotonic() - eval_wall_start, 2)

    # --- Step 5: Compute metrics and write final output ---
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall    = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    print("=" * 60)
    print("[baseline] Results:")
    print(f"  True Positives:   {tp_count}")
    print(f"  True Negatives:   {tn_count}")
    print(f"  False Positives:  {fp_count}")
    print(f"  False Negatives:  {fn_count}")
    print(f"  Precision:        {precision:.3f}")
    print(f"  Recall:           {recall:.3f}")
    print(f"  F1:               {f1:.3f}")
    print(f"  Total elapsed:    {total_elapsed}s")
    print(f"  Results saved to: {_RESULTS_PATH}")
    print("=" * 60)

    with open(_RESULTS_PATH, "w") as fh:
        json.dump(
            {
                "meta": {
                    "mode":                  "baseline",
                    "run_timestamp":         run_ts,
                    "hot_window_start":      _HOT_WINDOW_START,
                    "hot_window_end":        _HOT_WINDOW_END,
                    "total_cases":           total_cases,
                    "total_tool_calls":      0,
                    "true_positives":        tp_count,
                    "true_negatives":        tn_count,
                    "false_positives":       fp_count,
                    "false_negatives":       fn_count,
                    "precision":             round(precision, 4),
                    "recall":                round(recall, 4),
                    "f1":                    round(f1, 4),
                    "total_elapsed_seconds": total_elapsed,
                },
                "results": results,
            },
            fh,
            indent=2,
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Static Cypher baseline — lateral movement detection without LLM"
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=12,
        help="Max number of redteam TP cases to evaluate (default: 12)",
    )
    args = parser.parse_args()
    run_baseline_evaluation(sample_size=args.sample_size)
