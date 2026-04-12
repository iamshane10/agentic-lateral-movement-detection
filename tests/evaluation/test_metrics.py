"""
Unit tests for src/evaluation/metrics.py.

Tests cover:
  - compute_agent_metrics    : precision / recall / F1 / chain accuracy
  - compute_baseline_metrics : precision / recall / F1 for static baseline
  - _fmt                     : float formatter used in print_comparison
"""

import pytest

from src.evaluation.metrics import (
    _fmt,
    compute_agent_metrics,
    compute_baseline_metrics,
)


def _agent(verdict: str, lateral_found: bool = False, tool_seq_len: int = 0) -> dict:
    return {"verdict": verdict, "lateral_movement_path_found": lateral_found,
            "tool_call_sequence": list(range(tool_seq_len))}


def _baseline(flagged: bool) -> dict:
    return {"flagged": flagged}


# ===========================================================================
# compute_agent_metrics
# ===========================================================================

class TestComputeAgentMetrics:
    def test_perfect_recall_when_all_high(self):
        metrics = compute_agent_metrics([_agent("HIGH") for _ in range(4)])
        assert metrics["recall"] == 1.0
        assert metrics["precision"] == 1.0
        assert metrics["f1_score"] == 1.0

    def test_mixed_recall_calculation(self):
        # 3 TP, 1 FN → recall = 0.75
        results = [_agent("HIGH"), _agent("HIGH"), _agent("HIGH"), _agent("LOW")]
        metrics = compute_agent_metrics(results)
        assert metrics["recall"] == pytest.approx(0.75, abs=1e-4)

    def test_chain_accuracy_partial(self):
        results = [_agent("HIGH", lateral_found=True), _agent("HIGH", lateral_found=False)]
        assert compute_agent_metrics(results)["chain_accuracy"] == pytest.approx(0.5, abs=1e-4)

    def test_result_contains_required_keys(self):
        metrics = compute_agent_metrics([_agent("HIGH")])
        for key in ("total_events", "true_positives", "false_negatives", "false_positives",
                    "precision", "recall", "f1_score", "chain_accuracy", "sequence_completeness"):
            assert key in metrics, f"Missing key: {key}"


# ===========================================================================
# compute_baseline_metrics
# ===========================================================================

class TestComputeBaselineMetrics:
    def test_mixed_recall_calculation(self):
        # 2 flagged, 2 not → recall = 0.5
        results = [_baseline(True), _baseline(True), _baseline(False), _baseline(False)]
        assert compute_baseline_metrics(results)["recall"] == pytest.approx(0.5, abs=1e-4)

    def test_chain_accuracy_and_sequence_completeness_are_none(self):
        metrics = compute_baseline_metrics([_baseline(True)])
        assert metrics["chain_accuracy"] is None
        assert metrics["sequence_completeness"] is None

    def test_result_contains_required_keys(self):
        metrics = compute_baseline_metrics([_baseline(True)])
        for key in ("total_events", "true_positives", "false_negatives", "false_positives",
                    "precision", "recall", "f1_score", "chain_accuracy", "sequence_completeness"):
            assert key in metrics, f"Missing key: {key}"


# ===========================================================================
# _fmt
# ===========================================================================

class TestFmt:
    def test_none_returns_na(self):
        assert _fmt(None) == "N/A"

    def test_pct_formats_as_percentage(self):
        result = _fmt(0.75, pct=True)
        assert "%" in result
        assert "75" in result
