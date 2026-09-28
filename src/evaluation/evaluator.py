"""
Evaluator — evaluator.py

Two-stage blind evaluation against redteam.txt ground truth.

Stage 1 — Investigation (timestamps only):
    Parse redteam.txt for timestamps only (user/host columns ignored).
    Deduplicate events into non-overlapping 2-hour windows.
    Call investigate_window(start_time, end_time) for each window.

Stage 2 — Scoring (entities used here only):
    Reload redteam.txt. For each window, collect redteam users and hosts
    whose timestamps fall within that window. Score each verdict:
        true_positive:  flagged_users or flagged_hosts intersects redteam entities
        false_positive: something flagged but nothing matches redteam
        false_negative: redteam entities present but nothing flagged
    Compute precision, recall, F1. Print summary.

redteam.txt format (one event per line):
    timestamp,username,src_host,dst_host

Usage:
    uv run python -m src.evaluation.evaluator
"""

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path when run directly as a script.
# Has no effect when invoked via `python -m src.evaluation.evaluator`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import json
import os
import time as time_module
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from dotenv import load_dotenv

from src.agent.orchestrator import investigate_event, investigate_window

load_dotenv()

_REDTEAM_PATH = Path(os.getenv("REDTEAM_PATH", "data/redteam.txt"))
_EVAL_CASES_PATH = Path("data/eval_cases.txt")
_WINDOW_SIZE = 7200  # 2 hours in LANL internal integer seconds
_FIXED_WINDOW_START = 763200
_FIXED_WINDOW_END = 764600

# Bounded concurrency for run_entity_evaluation().
# Each investigation makes 3–4 LLM calls; 3 concurrent = ~12 LLM calls/min peak,
# well within the 120 RPM Navigator gateway limit. Do not increase without
# verifying RPM headroom first.
MAX_CONCURRENT_INVESTIGATIONS = 3


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_redteam(path: Path) -> list[dict]:
    """
    Parse redteam.txt into a list of event dicts.

    Returns:
        list of {"timestamp": int, "username": str, "src_host": str, "dst_host": str}
    """
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
                "username": parts[1].strip(),
                "src_host": parts[2].strip(),
                "dst_host": parts[3].strip(),
            })
    return events


def _load_eval_cases(
    path: Path,
    sample_size: int | None,
    split: str | None = None,
) -> list[dict]:
    """
    Load the fixed evaluation case list (generate_eval_cases.py output).

    Every evaluator reads the same file, so all methods score identical cases.
    If split is given ('tune' or 'test'), keeps only that half of the file.
    If sample_size is given, keeps the first N redteam and first N control
    cases in file order (the file is pre-shuffled with a fixed seed).
    """
    if not path.exists():
        raise FileNotFoundError(
            f"eval_cases.txt not found at {path}. "
            "Run: uv run python -m src.utils.generate_eval_cases"
        )
    all_cases: list[dict] = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            ts, username, src_host, dst_host, label = parts[:5]
            all_cases.append({
                "timestamp":  int(ts),
                "username":   username,
                "src_host":   src_host,
                "dst_host":   dst_host,
                "is_redteam": label == "redteam",
                "split":      parts[5] if len(parts) > 5 else None,
            })

    if split is not None:
        all_cases = [c for c in all_cases if c["split"] == split]

    n_redteam = sum(c["is_redteam"] for c in all_cases)
    n_control = len(all_cases) - n_redteam
    n = min(n_redteam, n_control)
    if sample_size is not None:
        n = min(n, sample_size)

    cases: list[dict] = []
    taken = {True: 0, False: 0}
    for c in all_cases:
        if taken[c["is_redteam"]] < n:
            cases.append(c)
            taken[c["is_redteam"]] += 1
    return cases


# ---------------------------------------------------------------------------
# Window deduplication
# ---------------------------------------------------------------------------

def _make_windows(events: list[dict]) -> list[dict]:
    """
    Deduplicate events into non-overlapping 2-hour windows.

    Two events share the same bucket if floor(timestamp / 7200) is equal.
    Returns one window per bucket: start = bucket * 7200, end = (bucket+1) * 7200.

    Args:
        events: list of event dicts (only "timestamp" key is used here)

    Returns:
        list of {"start": int, "end": int, "timestamps": list[int]},
        sorted by start time.
    """
    buckets: dict[int, list[int]] = defaultdict(list)
    for event in events:
        bucket = event["timestamp"] // _WINDOW_SIZE
        buckets[bucket].append(event["timestamp"])

    windows = []
    for bucket in sorted(buckets.keys()):
        start = bucket * _WINDOW_SIZE
        end = (bucket + 1) * _WINDOW_SIZE
        windows.append({"start": start, "end": end, "timestamps": buckets[bucket]})
    return windows


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_window(result: dict, redteam_events: list[dict]) -> dict:
    """
    Score a single window investigation result against redteam ground truth.

    Redteam entities for a window are all usernames, src_hosts, and dst_hosts
    from events whose timestamp falls within [window.start, window.end].

    Args:
        result:          The dict returned by investigate_window().
        redteam_events:  Full parsed redteam event list (entity columns used here).

    Returns:
        {
            "true_positive":  bool,  # flagged entity intersects redteam entities
            "false_positive": bool,  # something flagged but no redteam match
            "false_negative": bool,  # redteam entity in window but nothing flagged
            "redteam_users":  list[str],
            "redteam_hosts":  list[str],
        }
    """
    w_start = result["window"]["start"]
    w_end = result["window"]["end"]

    redteam_users: set[str] = set()
    redteam_hosts: set[str] = set()
    for event in redteam_events:
        if w_start <= event["timestamp"] <= w_end:
            redteam_users.add(event["username"])
            redteam_hosts.add(event["src_host"])
            redteam_hosts.add(event["dst_host"])

    flagged_users = set(result["flagged_users"])
    flagged_hosts = set(result["flagged_hosts"])

    has_redteam = bool(redteam_users or redteam_hosts)
    has_flagged = bool(flagged_users or flagged_hosts)
    any_hit = bool((flagged_users & redteam_users) or (flagged_hosts & redteam_hosts))

    return {
        "true_positive": has_redteam and any_hit,
        "false_positive": has_flagged and not any_hit,
        "false_negative": has_redteam and not any_hit,
        "redteam_users": sorted(redteam_users),
        "redteam_hosts": sorted(redteam_hosts),
    }


# ---------------------------------------------------------------------------
# Entity evaluation helpers
# ---------------------------------------------------------------------------

def _flush_results(results: list[dict], output_path: Path, total_tokens: int = 0) -> None:
    """Write results list to disk incrementally (called after each completed case)."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"total_tokens": total_tokens, "results": results}, f, indent=2, default=str)


def _score_result(result: dict) -> str:
    """Return TP / TN / FP / FN outcome string based on is_redteam + severity."""
    is_redteam = result["is_redteam"]
    flagged = result["severity"] in {"HIGH", "MEDIUM"}
    if is_redteam and flagged:
        return "TP"
    if not is_redteam and not flagged:
        return "TN"
    if not is_redteam and flagged:
        return "FP"
    return "FN"


# ---------------------------------------------------------------------------
# Main evaluation loop
# ---------------------------------------------------------------------------

def run_evaluation(redteam_path: Path = _REDTEAM_PATH) -> list[dict]:
    """
    Run entity-seeded evaluation against every redteam.txt event within the
    fixed window [_FIXED_WINDOW_START, _FIXED_WINDOW_END].

    Each filtered event is investigated individually via investigate_event().
    All inputs are confirmed red team events, so the only outcomes are:
        true_positive:  severity in {HIGH, MEDIUM}
        false_negative: severity == LOW

    Results are written incrementally to a timestamped evaluation/results_*.json file.

    Args:
        redteam_path: Path to redteam.txt (default: data/redteam.txt via env var)

    Returns:
        List of per-event result dicts (also written to the results file).
    """
    run_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_path = Path(f"evaluation/results_{run_ts}.json")
    results_path.parent.mkdir(parents=True, exist_ok=True)

    eval_wall_start = time_module.monotonic()

    all_events = _parse_redteam(redteam_path)
    window_events = [
        e for e in all_events
        if _FIXED_WINDOW_START <= e["timestamp"] <= _FIXED_WINDOW_END
    ]

    print(f"[evaluator] redteam_path={redteam_path}")
    print(f"[evaluator] total events in file: {len(all_events)}")
    print(f"[evaluator] events in window [{_FIXED_WINDOW_START}, {_FIXED_WINDOW_END}]: {len(window_events)}")
    for e in window_events:
        print(f"[evaluator]   time={e['timestamp']} user={e['username']!r} src={e['src_host']!r} dst={e['dst_host']!r}")
    print(f"[evaluator] Results → {results_path}\n")

    if not window_events:
        print("[evaluator] No events found in window — nothing to evaluate.")
        return []

    total_events = len(window_events)
    event_results: list[dict] = []
    total_tool_calls = 0
    total_tokens = 0
    tp_count = 0
    fn_count = 0

    for idx, event in enumerate(window_events, start=1):
        username = event["username"]
        dst_host = event["dst_host"]
        timestamp = event["timestamp"]

        print(f"[{idx:>3}/{total_events}] user={username!r}  dst={dst_host!r}  time={timestamp}")

        wall_start = time_module.monotonic()
        try:
            result = investigate_event(username, dst_host, timestamp)
            elapsed = time_module.monotonic() - wall_start
            error = None
        except Exception as exc:
            elapsed = time_module.monotonic() - wall_start
            result = {
                "event": {"username": username, "dst_host": dst_host, "timestamp": timestamp},
                "flagged_users": [],
                "flagged_hosts": [],
                "verdict": "",
                "severity": "LOW",
                "tool_calls_made": 0,
                "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            }
            error = str(exc)
            print(f"           ERROR: {error}")

        severity = result["severity"]
        total_tool_calls += result["tool_calls_made"]
        event_tokens = result.get("token_usage", {}).get("total_tokens", 0)
        total_tokens += event_tokens

        flagged = severity in {"HIGH", "MEDIUM"}
        if flagged:
            tp_count += 1
            outcome = "TP"
        else:
            fn_count += 1
            outcome = "FN"

        print(
            f"           severity={severity:<6}  outcome={outcome}  "
            f"tool_calls={result['tool_calls_made']}  tokens={event_tokens}  elapsed={elapsed:.1f}s\n"
        )

        event_results.append({
            **result,
            "src_host": event["src_host"],
            "outcome": outcome,
            "error": error,
            "elapsed_seconds": round(elapsed, 2),
            "evaluated_at": datetime.utcnow().isoformat() + "Z",
        })

        # Flush after each event so partial results survive a crash
        with open(results_path, "w") as fh:
            json.dump(
                {
                    "total_tokens": total_tokens,
                    "meta": {
                        "total_events": total_events,
                        "evaluated": idx,
                        "total_tool_calls_so_far": total_tool_calls,
                        "total_tokens_so_far": total_tokens,
                    },
                    "results": event_results,
                },
                fh,
                indent=2,
            )

    recall = tp_count / total_events if total_events > 0 else 0.0
    total_elapsed = round(time_module.monotonic() - eval_wall_start, 2)

    print("=" * 60)
    print(f"[evaluator] Done. {total_events} events evaluated.")
    print(f"            True Positives:   {tp_count}")
    print(f"            False Negatives:  {fn_count}")
    print(f"            Recall:           {recall:.3f}")
    print(f"            Total tool calls: {total_tool_calls}")
    print(f"            Total tokens:     {total_tokens}")
    print(f"            Total elapsed:    {total_elapsed}s")
    print(f"            Results saved to: {results_path}")
    print("=" * 60)

    with open(results_path, "w") as fh:
        json.dump(
            {
                "total_tokens": total_tokens,
                "meta": {
                    "mode": "window",
                    "run_timestamp": run_ts,
                    "window_start": _FIXED_WINDOW_START,
                    "window_end": _FIXED_WINDOW_END,
                    "total_events": total_events,
                    "total_tool_calls": total_tool_calls,
                    "total_tokens": total_tokens,
                    "true_positives": tp_count,
                    "false_negatives": fn_count,
                    "recall": round(recall, 4),
                    "total_elapsed_seconds": total_elapsed,
                },
                "results": event_results,
            },
            fh,
            indent=2,
        )

    return event_results


def run_entity_evaluation(
    cases_path: str = str(_EVAL_CASES_PATH),
    sample_size: int | None = None,
    split: str | None = None,
) -> None:
    """
    Entity-seeded evaluation against ground truth.

    Loads the fixed balanced case list from data/eval_cases.txt
    (generate_eval_cases.py output) — the same file every baseline reads — runs
    investigate_event() on each case, and scores results. The agent receives
    only (username, dst_host, timestamp); labels are used for scoring only.
    Writes incrementally to a timestamped evaluation/entity_results_*.json file.

    Args:
        cases_path:  Path to eval_cases.txt
        sample_size: Use only the first N redteam and N control cases (default: all)
        split:       'tune' or 'test' to use only that half (default: all cases)
    """
    run_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    split_tag = f"{split}_" if split else ""
    _ENTITY_RESULTS_PATH = Path(f"evaluation/entity_results_{split_tag}{run_ts}.json")
    _ENTITY_RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)

    eval_wall_start = time_module.monotonic()

    HOT_WINDOW_START  = 763200
    HOT_WINDOW_END    = 770400
    COLD_WINDOW_START = 767000  # control sampling window — matches generate_cold_events.py; for meta logging only
    COLD_WINDOW_END   = 770400

    # --- Load the fixed, pre-shuffled case list (shared with all baselines) ---
    cases = _load_eval_cases(Path(cases_path), sample_size, split)
    n_cases = sum(c["is_redteam"] for c in cases)

    total_cases = len(cases)
    print(f"[entity_eval] cases_path={cases_path!r} split={split or 'all'}")
    print(f"[entity_eval] Red team cases:             {n_cases}")
    print(f"[entity_eval] Control cases:              {n_cases}")
    print(f"[entity_eval] Total cases to evaluate:    {total_cases}")
    print(f"[entity_eval] Results → {_ENTITY_RESULTS_PATH}\n")

    # --- Run investigations concurrently, score and flush after each completion ---

    def _timed_investigate(case: dict) -> dict:
        """Thin wrapper: calls investigate_event and records per-case wall time."""
        start = time_module.monotonic()
        result = investigate_event(case["username"], case["dst_host"], case["timestamp"])
        result["elapsed_seconds"] = round(time_module.monotonic() - start, 2)
        return result

    scored_results: list[dict] = []
    total_tool_calls = 0
    total_tokens = 0
    tp_count = 0
    tn_count = 0
    fp_count = 0
    fn_count = 0

    exec_wall_start = time_module.monotonic()

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_INVESTIGATIONS) as executor:
        future_to_case = {
            executor.submit(_timed_investigate, case): case
            for case in cases
        }

        for future in as_completed(future_to_case):
            case = future_to_case[future]
            try:
                result = future.result()
                error = None
            except Exception as exc:
                if "429" in str(exc):
                    time_module.sleep(10)
                error = str(exc)
                result = {
                    "event": {
                        "username": case["username"],
                        "dst_host": case["dst_host"],
                        "timestamp": case["timestamp"],
                    },
                    "flagged_users": [],
                    "flagged_hosts": [],
                    "verdict": "",
                    "severity": "LOW",
                    "tool_calls_made": 0,
                    "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                    "elapsed_seconds": 0.0,
                }
                print(f"           ERROR: {error}")

            result["is_redteam"] = case["is_redteam"]
            result["outcome"] = _score_result(result)
            result["error"] = error
            result["evaluated_at"] = datetime.utcnow().isoformat() + "Z"

            outcome = result["outcome"]
            total_tool_calls += result.get("tool_calls_made", 0)
            case_tokens = result.get("token_usage", {}).get("total_tokens", 0)
            total_tokens += case_tokens

            if outcome == "TP":
                tp_count += 1
            elif outcome == "TN":
                tn_count += 1
            elif outcome == "FP":
                fp_count += 1
            else:
                fn_count += 1

            scored_results.append(result)
            _flush_results(scored_results, _ENTITY_RESULTS_PATH, total_tokens)

            print(
                f"[entity_eval] Completed {len(scored_results)}/{total_cases} "
                f"— {case['username']} → {case['dst_host']} "
                f"({outcome}, tokens={case_tokens}, {result.get('elapsed_seconds', 0):.1f}s)"
            )

    total_elapsed = round(time_module.monotonic() - exec_wall_start, 2)

    # --- Final metrics ---
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    print("=" * 60)
    print(f"[entity_eval] Results:")
    print(f"  True Positives:   {tp_count}")
    print(f"  True Negatives:   {tn_count}")
    print(f"  False Positives:  {fp_count}")
    print(f"  False Negatives:  {fn_count}")
    print(f"  Precision:        {precision:.3f}")
    print(f"  Recall:           {recall:.3f}")
    print(f"  F1:               {f1:.3f}")
    print(f"  Total tool calls: {total_tool_calls}")
    print(f"  Total tokens:     {total_tokens}")
    print(f"  Total elapsed:    {total_elapsed}s")
    print(f"  Results saved to: {_ENTITY_RESULTS_PATH}")
    print("=" * 60)

    with open(_ENTITY_RESULTS_PATH, "w") as fh:
        json.dump(
            {
                "total_tokens": total_tokens,
                "meta": {
                    "mode": "entity",
                    "split": split or "all",
                    "run_timestamp": run_ts,
                    "hot_window_start": HOT_WINDOW_START,
                    "hot_window_end": HOT_WINDOW_END,
                    "cold_window_start": COLD_WINDOW_START,
                    "cold_window_end": COLD_WINDOW_END,
                    "max_concurrent": MAX_CONCURRENT_INVESTIGATIONS,
                    "total_cases": total_cases,
                    "total_tool_calls": total_tool_calls,
                    "total_tokens": total_tokens,
                    "true_positives": tp_count,
                    "true_negatives": tn_count,
                    "false_positives": fp_count,
                    "false_negatives": fn_count,
                    "precision": round(precision, 4),
                    "recall": round(recall, 4),
                    "f1": round(f1, 4),
                    "total_elapsed_seconds": total_elapsed,
                },
                "results": scored_results,
            },
            fh,
            indent=2,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Lateral movement evaluator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modes:
  window   Recall-only evaluation. Sends every confirmed redteam event in the
           fixed window to the agent. Measures True Positives and False Negatives.
           Output: evaluation/results_YYYYMMDD_HHMMSS.json

  entity   Precision + Recall + F1 evaluation. Sends a balanced mix of confirmed
           redteam events (TP cases) and normal control events (FP cases) to the
           agent. Measures TP, TN, FP, FN.
           Output: evaluation/entity_results_YYYYMMDD_HHMMSS.json
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["window", "entity"],
        default="window",
        help="Evaluation mode: 'window' (recall only) or 'entity' (precision + recall + F1). Default: window",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="[entity mode only] Use only the first N redteam and N control cases "
             "from data/eval_cases.txt (default: all)",
    )
    parser.add_argument(
        "--split",
        choices=["tune", "test"],
        default=None,
        help="[entity mode only] Use only the tune or test half of data/eval_cases.txt "
             "(default: all cases)",
    )
    args = parser.parse_args()

    if args.mode == "window":
        run_evaluation()
    else:
        run_entity_evaluation(sample_size=args.sample_size, split=args.split)
