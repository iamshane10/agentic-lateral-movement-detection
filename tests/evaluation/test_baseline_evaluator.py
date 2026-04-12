"""
Unit tests for src/evaluation/baseline_evaluator.py.

Tests cover pure Python helpers that require no live services:
  - _parse_events  : file parsing into event dicts
  - _score_outcome : TP / TN / FP / FN outcome string
"""

import textwrap
from pathlib import Path

from src.evaluation.baseline_evaluator import (
    _parse_events,
    _score_outcome,
)


def _write_events_file(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "events.txt"
    p.write_text(textwrap.dedent(content))
    return p


# ===========================================================================
# _parse_events
# ===========================================================================

class TestParseEvents:
    def test_parses_valid_lines(self, tmp_path):
        content = "763210,U620@DOM1,C17693,C1003\n763300,U100@DOM1,C500,C600\n"
        events = _parse_events(_write_events_file(tmp_path, content))
        assert len(events) == 2
        assert events[0]["timestamp"] == 763210
        assert events[0]["username"] == "U620@DOM1"
        assert events[0]["dst_host"] == "C1003"

    def test_skips_comment_and_blank_lines(self, tmp_path):
        content = "# comment\n\n763210,U620@DOM1,C17693,C1003\n"
        events = _parse_events(_write_events_file(tmp_path, content))
        assert len(events) == 1

    def test_timestamp_is_integer(self, tmp_path):
        content = "763210,U620@DOM1,C17693,C1003\n"
        events = _parse_events(_write_events_file(tmp_path, content))
        assert isinstance(events[0]["timestamp"], int)


# ===========================================================================
# _score_outcome
# ===========================================================================

class TestScoreOutcome:
    def test_true_positive_high(self):
        assert _score_outcome(True, "HIGH") == "TP"

    def test_false_negative_low(self):
        assert _score_outcome(True, "LOW") == "FN"

    def test_false_positive_high(self):
        assert _score_outcome(False, "HIGH") == "FP"

    def test_true_negative_low(self):
        assert _score_outcome(False, "LOW") == "TN"
