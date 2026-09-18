"""Anti-shortcut gate: the benchmark must not be solvable by a one-line rule.

背景: `SAME_EVENT` 的增量切片来自同一个 MISP Event，MISP 沿用同一条 headline，
所以同一事件的不同切片标题**逐字相同**。这里把"一行规则"的收益固化下来：

  * 4-way 任务不得被朴素规则刷满（macro-F1 上限）；
  * 标题消融后的 SAME 检测必须真的变难（否则 `title == seen` 就是伪任务）。
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_baselines():
    spec = importlib.util.spec_from_file_location(
        "baselines_mod", ROOT / "scripts" / "baselines.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def baselines():
    module = _load_baselines()
    return module


def _inputs(baselines, asset: str, with_title: bool):
    files = baselines.ASSETS[asset]
    name = files["input" if with_title else "input_notitle"]
    path = baselines.DATA / "model_input" / name
    if not path.exists():
        pytest.skip("model_input 未生成（先运行 scripts/build_all.py build）")
    rows = baselines.read_jsonl(path)
    labels = {
        row["id"]: row["ground_truth_label_name"]
        for row in baselines.read_jsonl(baselines.DATA / files["benchmark"])
    }
    for row in rows:
        row["_label"] = labels[row["id"]]
    return rows, [row["_label"] for row in rows]


def test_no_naive_rule_saturates_the_four_way_task(baselines):
    """任何朴素规则都不该拿到高 macro-F1（4-way 才是论文的主任务）。"""
    for asset in ("real-wild", "real-augmented", "real-augmented-attributed"):
        rows, gold = _inputs(baselines, asset, with_title=True)
        for name, rule in (("title_seen", baselines._seen_rule), ("title_jaccard", baselines._jaccard_rule)):
            scores = baselines._score(gold, rule(rows, "title"))
            assert scores["macro_f1"] < 0.60, (
                f"{asset}/{name} 的 macro-F1={scores['macro_f1']:.3f} 过高，任务被捷径解掉"
            )


def test_title_ablation_removes_the_same_event_shortcut(baselines):
    """标题消融后，纯文本相似度不得再轻松命中 SAME。"""
    rows, gold = _inputs(baselines, "real-augmented", with_title=False)
    scores = baselines._score(gold, baselines._jaccard_rule(rows, "text"))
    assert scores["SAME_EVENT_f1"] < 0.20, (
        f"无标题口径下 text_jaccard 的 SAME-F1={scores['SAME_EVENT_f1']:.3f}，捷径仍存在"
    )


def test_title_shortcut_is_documented_not_hidden(baselines):
    """标题投影保留为上界参考，不能成为 SAME 的逐字捷径。"""
    rows, gold = _inputs(baselines, "real-augmented-attributed", with_title=True)
    scores = baselines._score(gold, baselines._seen_rule(rows, "title"))
    assert scores["SAME_EVENT_f1"] < 0.20
    assert scores["macro_f1"] < 0.60
