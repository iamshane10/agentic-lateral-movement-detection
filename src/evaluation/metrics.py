"""
Metrics — metrics.py

Computes precision, recall, F1, and lateral-movement chain accuracy from
evaluation/results.json (agent) and evaluation/baseline_cypher_results.json
(Baseline B).  Prints a side-by-side comparison table.

Usage:
    uv run python -m src.evaluation.metrics
    uv run python -m src.evaluation.metrics --agent-only
    uv run python -m src.evaluation.metrics --baseline-only
"""

import argparse
import json
from pathlib import Path

_AGENT_RESULTS_PATH = Path("evaluation/results.json")
_BASELINE_RESULTS_PATH = Path("evaluation/baseline_cypher_results.json")


# ---------------------------------------------------------------------------
# Core metric computation
# ---------------------------------------------------------------------------

def compute_agent_metrics(results: list[dict]) -> dict:
    """
    Compute metrics from evaluator.py result records.

    Every event in redteam.txt is a ground-truth positive.
      TP = verdict == HIGH
      FN = verdict != HIGH  (MEDIUM, LOW, or UNKNOWN)
      FP = 0 (only redteam events are evaluated)

    Chain accuracy = fraction of TP events where a lateral movement path
    was reconstructed by get_lateral_movement_path.
    """
    total = len(results)
    tp = sum(1 for r in results if r.get("verdict") == "HIGH")
    fn = total - tp
    fp = 0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    # Chain accuracy: among TPs, how many had path reconstructed?
    tp_records = [r for r in results if r.get("verdict") == "HIGH"]
    paths_found = sum(1 for r in tp_records if r.get("lateral_movement_path_found"))
    chain_accuracy = paths_found / len(tp_records) if tp_records else 0.0

    # Tool sequence completeness: fraction of events where all 9 tools were called
    full_sequence = sum(
        1 for r in results if len(r.get("tool_call_sequence", [])) == 9
    )
    sequence_completeness = full_sequence / total if total > 0 else 0.0

    unknown = sum(1 for r in results if r.get("verdict") == "UNKNOWN")

    total_tokens = sum(
        r.get("token_usage", {}).get("total_tokens", 0) for r in results
    )

    return {
        "total_events": total,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "unknown_verdicts": unknown,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "chain_accuracy": round(chain_accuracy, 4),
        "sequence_completeness": round(sequence_completeness, 4),
        "total_tokens": total_tokens,
    }


def compute_baseline_metrics(results: list[dict]) -> dict:
    """
    Compute metrics from baseline_evaluator.py result records.

    Same ground-truth assumption: every redteam event is a positive.
    Baseline B has no chain reconstruction or tool sequence concept.
    """
    total = len(results)
    tp = sum(1 for r in results if r.get("flagged"))
    fn = total - tp
    fp = 0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "total_events": total,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "chain_accuracy": None,       # not applicable for static baseline
        "sequence_completeness": None,
    }


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _fmt(value, pct: bool = False) -> str:
    if value is None:
        return "N/A"
    if pct:
        return f"{value:.2%}"
    return f"{value:.4f}"


def print_comparison(agent: dict | None, baseline: dict | None) -> None:
    col_w = 28

    rows = [
        ("Metric",               "Agent (LLM+KG)",    "Baseline B (Cypher)"),
        ("-" * col_w,            "-" * 18,             "-" * 20),
        ("Total events",
            str(agent["total_events"]) if agent else "—",
            str(baseline["total_events"]) if baseline else "—"),
        ("True Positives (TP)",
            str(agent["true_positives"]) if agent else "—",
            str(baseline["true_positives"]) if baseline else "—"),
        ("False Negatives (FN)",
            str(agent["false_negatives"]) if agent else "—",
            str(baseline["false_negatives"]) if baseline else "—"),
        ("False Positives (FP)",
            str(agent["false_positives"]) if agent else "—",
            str(baseline["false_positives"]) if baseline else "—"),
        ("Precision",
            _fmt(agent["precision"]) if agent else "—",
            _fmt(baseline["precision"]) if baseline else "—"),
        ("Recall",
            _fmt(agent["recall"]) if agent else "—",
            _fmt(baseline["recall"]) if baseline else "—"),
        ("F1 Score",
            _fmt(agent["f1_score"]) if agent else "—",
            _fmt(baseline["f1_score"]) if baseline else "—"),
        ("Chain Accuracy",
            _fmt(agent.get("chain_accuracy"), pct=True) if agent else "—",
            "N/A"),
        ("Sequence Completeness",
            _fmt(agent.get("sequence_completeness"), pct=True) if agent else "—",
            "N/A"),
    ]
    if agent:
        rows.append((
            "Unknown Verdicts",
            str(agent.get("unknown_verdicts", 0)),
            "N/A",
        ))
    rows.append((
        "Total Tokens",
        str(agent.get("total_tokens", 0)) if agent else "—",
        "N/A",
    ))

    print()
    print("=" * 72)
    print("  EVALUATION RESULTS — Lateral Movement Detection")
    print("=" * 72)
    for label, a_val, b_val in rows:
        print(f"  {label:<{col_w}}  {a_val:<20}  {b_val}")
    print("=" * 72)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Compute and compare evaluation metrics")
    parser.add_argument("--agent-only",    action="store_true", help="Only show agent metrics")
    parser.add_argument("--baseline-only", action="store_true", help="Only show baseline metrics")
    args = parser.parse_args()

    agent_metrics = None
    baseline_metrics = None

    if not args.baseline_only:
        if not _AGENT_RESULTS_PATH.exists():
            print(f"[metrics] Agent results not found: {_AGENT_RESULTS_PATH}")
            print("         Run evaluator.py first.")
        else:
            with open(_AGENT_RESULTS_PATH) as fh:
                data = json.load(fh)
            agent_metrics = compute_agent_metrics(data["results"])
            print(f"[metrics] Loaded {agent_metrics['total_events']} agent results "
                  f"from {_AGENT_RESULTS_PATH}")

    if not args.agent_only:
        if not _BASELINE_RESULTS_PATH.exists():
            print(f"[metrics] Baseline results not found: {_BASELINE_RESULTS_PATH}")
            print("         Run baseline_evaluator.py first.")
        else:
            with open(_BASELINE_RESULTS_PATH) as fh:
                data = json.load(fh)
            baseline_metrics = compute_baseline_metrics(data["results"])
            print(f"[metrics] Loaded {baseline_metrics['total_events']} baseline results "
                  f"from {_BASELINE_RESULTS_PATH}")

    print_comparison(agent_metrics, baseline_metrics)


if __name__ == "__main__":
    main()
