"""Smoke and leakage tests for the minimal MDL runner."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="module")
def mdl():
    spec = importlib.util.spec_from_file_location("run_mdl_experiment", ROOT / "scripts" / "run_mdl_experiment.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _row(doc_id, hour, text):
    return {"id": doc_id, "publish_time": f"2024-01-01T{hour:02d}:00:00", "text": text}


def test_mock_mdl_smoke_and_historical_targets(mdl):
    rows = [
        _row("a", 0, "APT Raven malware intrusion CVE-2024-1234"),
        _row("b", 1, "APT Raven malware intrusion CVE-2024-1234"),
        _row("c", 2, "new ransomware campaign CVE-2024-9999"),
    ]
    predictions, diagnostics = mdl.run_stream(rows, mdl.MockScorer(), top_k=2)
    assert [item["id"] for item in predictions] == ["a", "b", "c"]
    assert predictions[0]["target"] is None
    assert predictions[1]["target"] == "a"
    assert all(item["n_candidates"] <= 2 for item in diagnostics)
    assert all("ground_truth" not in json.dumps(item) for item in predictions)


def test_model_input_rejects_ground_truth_fields(mdl):
    rows = [_row("a", 0, "malware intrusion")]
    rows[0]["target_incident_id"] = "secret"
    with pytest.raises(ValueError, match="forbidden"):
        mdl.run_stream(rows, mdl.MockScorer())


def test_mock_runner_cli_on_frozen_synthetic_prefix(mdl, tmp_path):
    source = ROOT / "data" / "model_input" / "synthetic_input_1000.jsonl"
    rows = mdl.read_jsonl(source)[:100]
    output = tmp_path / "pred.jsonl"
    predictions, _ = mdl.run_stream(rows, mdl.MockScorer(), top_k=3)
    mdl._write_jsonl(output, predictions)
    assert output.read_text(encoding="utf-8").count("\n") == 100
    assert all(set(item) == {"id", "label", "target"} for item in predictions)
