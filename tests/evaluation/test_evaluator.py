"""
Unit tests for src/evaluation/evaluator.py.

Tests cover pure Python functions that require no live services:
  - _parse_redteam : file parsing into event dicts
  - _make_windows  : timestamp bucketing into 2-hour windows
  - _score_window  : TP / FP / FN logic against redteam ground truth
  - _score_result  : entity-mode TP / TN / FP / FN outcome string
  - _flush_results : incremental JSON flush to disk
"""

import json
import textwrap
from pathlib import Path

from src.evaluation.evaluator import (
    _flush_results,
    _make_windows,
    _parse_redteam,
    _score_result,
    _score_window,
)


def _write_temp_redteam(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "redteam.txt"
    p.write_text(textwrap.dedent(content))
    return p


# ===========================================================================
# _parse_redteam
# ===========================================================================

class TestParseRedteam:
    def test_parses_valid_lines(self, tmp_path):
        content = "763210,U620@DOM1,C17693,C1003\n763300,U100@DOM1,C500,C600\n"
        events = _parse_redteam(_write_temp_redteam(tmp_path, content))
        assert len(events) == 2
        assert events[0]["timestamp"] == 763210
        assert events[0]["username"] == "U620@DOM1"
        assert events[0]["dst_host"] == "C1003"

    def test_skips_comment_and_blank_lines(self, tmp_path):
        content = "# comment\n\n763210,U620@DOM1,C17693,C1003\n"
        events = _parse_redteam(_write_temp_redteam(tmp_path, content))
        assert len(events) == 1

    def test_timestamp_is_integer(self, tmp_path):
        events = _parse_redteam(_write_temp_redteam(tmp_path, "763210,U620@DOM1,C17693,C1003\n"))
        assert isinstance(events[0]["timestamp"], int)


# ===========================================================================
# _make_windows  (_WINDOW_SIZE = 7200 seconds)
# ===========================================================================

class TestMakeWindows:
    def test_two_events_in_same_bucket_produce_one_window(self):
        events = [{"timestamp": 763200}, {"timestamp": 763300}]
        windows = _make_windows(events)
        assert len(windows) == 1
        assert 763200 in windows[0]["timestamps"]

    def test_two_events_in_different_buckets_produce_two_windows(self):
        events = [{"timestamp": 763200}, {"timestamp": 770401}]
        windows = _make_windows(events)
        assert len(windows) == 2

    def test_window_end_equals_start_plus_7200(self):
        windows = _make_windows([{"timestamp": 763210}])
        assert windows[0]["end"] - windows[0]["start"] == 7200


# ===========================================================================
# _score_window
# ===========================================================================

class TestScoreWindow:
    def _result(self, flagged_users, flagged_hosts):
        return {"window": {"start": 763200, "end": 770400},
                "flagged_users": flagged_users, "flagged_hosts": flagged_hosts}

    def _event(self, ts=763210, user="U620@DOM1", src="C17693", dst="C1003"):
        return {"timestamp": ts, "username": user, "src_host": src, "dst_host": dst}

    def test_tp_on_flagged_user_match(self):
        score = _score_window(self._result(["U620@DOM1"], []), [self._event()])
        assert score["true_positive"] is True
        assert score["false_positive"] is False

    def test_fn_when_nothing_flagged(self):
        score = _score_window(self._result([], []), [self._event()])
        assert score["false_negative"] is True
        assert score["true_positive"] is False

    def test_fp_when_flagged_but_no_redteam_match(self):
        score = _score_window(self._result(["U999@DOM1"], []), [self._event()])
        assert score["false_positive"] is True
        assert score["true_positive"] is False


# ===========================================================================
# _score_result  (entity-mode)
# ===========================================================================

class TestScoreResult:
    def test_tp(self):
        assert _score_result({"is_redteam": True, "severity": "HIGH"}) == "TP"

    def test_fn(self):
        assert _score_result({"is_redteam": True, "severity": "LOW"}) == "FN"

    def test_fp(self):
        assert _score_result({"is_redteam": False, "severity": "HIGH"}) == "FP"

    def test_tn(self):
        assert _score_result({"is_redteam": False, "severity": "LOW"}) == "TN"


# ===========================================================================
# _flush_results
# ===========================================================================

class TestFlushResults:
    def test_written_results_match_input(self, tmp_path):
        path = tmp_path / "results.json"
        rows = [{"severity": "HIGH", "outcome": "TP"}, {"severity": "LOW", "outcome": "FN"}]
        _flush_results(rows, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["results"]) == 2
        assert data["results"][0]["outcome"] == "TP"
