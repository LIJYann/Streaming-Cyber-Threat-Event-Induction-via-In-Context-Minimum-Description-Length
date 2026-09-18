"""Integration checks for complete predictions and warm-up state replay."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_eval(tmp_path, predictions):
    rows = [{"id": str(i), "publish_time": f"2020-01-0{i+1}", "text": "intrusion"} for i in range(4)]
    gold = [dict(row, ground_truth_label_name="UNSEEN_EVENT" if i == 0 else "SAME_EVENT", target_incident_id="event") for i, row in enumerate(rows)]
    for name, data in [("input", rows), ("gold", gold), ("pred", predictions)]:
        (tmp_path / name).write_text("".join(json.dumps(row) + "\n" for row in data))
    return subprocess.run([sys.executable, str(ROOT / "scripts/evaluate.py"), "--stream", str(tmp_path / "input"), "--benchmark", str(tmp_path / "gold"), "--pred", str(tmp_path / "pred"), "--warmup", "2"], capture_output=True, text=True)


def predictions():
    return [{"id": str(i), "label": "UNSEEN_EVENT" if i == 0 else "SAME_EVENT", "target": [None, "0", "0", "1"][i]} for i in range(4)]


def test_warmup_links_preserved(tmp_path):
    result = run_eval(tmp_path, predictions())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["b_cubed_f1"] == 1.0


def test_incomplete_predictions_rejected(tmp_path):
    result = run_eval(tmp_path, predictions()[:2])
    assert result.returncode != 0
    assert "count" in result.stderr


def test_future_target_rejected(tmp_path):
    rows = predictions()
    rows[1]["target"] = "3"
    result = run_eval(tmp_path, rows)
    assert result.returncode != 0
    assert "earlier" in result.stderr
