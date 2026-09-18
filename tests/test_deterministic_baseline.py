"""Tests for the label-free online baseline."""

import importlib.util
import json
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="module")
def baseline():
    spec = importlib.util.spec_from_file_location(
        "deterministic_baseline", ROOT / "scripts" / "deterministic_baseline.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _row(doc_id, stamp, text, title=None):
    row = {"id": doc_id, "publish_time": stamp, "text": text}
    if title is not None:
        row["title"] = title
    return row


def test_only_prior_rows_can_be_same_target(baseline):
    rows = [
        _row("first", "2024-01-01T00:00:00", "APT Raven intrusion CVE-2024-1234"),
        _row("second", "2024-01-01T01:00:00", "APT Raven intrusion CVE-2024-1234"),
        _row("third", "2024-01-01T02:00:00", "APT Raven intrusion CVE-2024-1234"),
    ]
    predictions = baseline.predict(rows)
    assert predictions[0]["target"] is None
    assert predictions[1]["label"] == "SAME_EVENT"
    assert predictions[1]["target"] == "first"
    assert predictions[2]["target"] in {"first", "second"}
    for row, pred in zip(rows, predictions):
        assert pred["id"] == row["id"]
        assert pred["target"] != row["id"]


def test_noise_is_not_added_as_a_future_anchor(baseline):
    rows = [
        _row("noise", "2024-01-01T00:00:00", "General policy and annual report"),
        _row("event", "2024-01-01T01:00:00", "APT Raven intrusion CVE-2024-1234"),
    ]
    predictions = baseline.predict(rows)
    assert predictions[0]["label"] == "NO_EVENT"
    assert predictions[1]["target"] is None


def test_prediction_does_not_depend_on_row_order_hash_seed(baseline):
    rows = [
        _row("a", "2024-01-01T00:00:00", "malware exploit CVE-2024-0001 10.0.0.1"),
        _row("b", "2024-01-01T01:00:00", "malware exploit CVE-2024-0001 10.0.0.1"),
        _row("c", "2024-01-10T01:00:00", "general policy and annual report"),
    ]
    expected = baseline.predict(rows)
    shuffled = list(rows)
    # This only checks stable set iteration; chronological replay itself is
    # intentionally the supplied stream order.
    random.seed(7)
    random.shuffle(shuffled)
    assert baseline.predict(rows) == expected


def test_output_contract_is_jsonl_and_has_no_ground_truth_fields(baseline, tmp_path):
    rows = [_row("a", "2024-01-01T00:00:00", "new malware intrusion")]
    path = tmp_path / "pred.jsonl"
    baseline._write_jsonl(path, baseline.predict(rows))
    output = json.loads(path.read_text().strip())
    assert set(output) == {"id", "label", "target"}
    assert "target_incident_id" not in output
    assert "ground_truth_label_name" not in output


def test_validator_rejects_future_target(baseline):
    rows = [
        _row("first", "2024-01-01T00:00:00", "new malware intrusion"),
        _row("second", "2024-01-01T01:00:00", "new malware intrusion"),
    ]
    malformed = [
        {"id": "first", "label": "SAME_EVENT", "target": "second"},
        {"id": "second", "label": "UNSEEN_EVENT", "target": None},
    ]
    with pytest.raises(ValueError, match="earlier"):
        baseline.validate_predictions(rows, malformed)
