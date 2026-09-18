#!/usr/bin/env python3
"""
baselines.py — 在**模型真正看得到的输入**上跑朴素基线，含"一行规则"捷径。

为什么必须有这个脚本：
  `SAME_EVENT` 的增量切片来自同一个 MISP Event，而 MISP 沿用同一条 event
  headline，因此同一事件的不同切片**标题逐字相同**（实测 112 个多切片事件中 111 个）。
  审稿人一定会问："写一行 `if title in seen: return SAME` 不就刷满了？"

这里把该疑问量化成表格。基线都跑在 `data/model_input/*.jsonl` 上（即真正喂给模型的
字段），标签用 `id` 回连 `*_benchmark.jsonl`：

  majority        : 全预测多数类
  title_seen      : `标题此前出现过 => SAME`（最小的一行规则）
  title_jaccard   : `标题 Jaccard >= 0.7 且 Δt <= 14 天 => SAME`
  text_jaccard    : `正文 Jaccard >= 0.7 且 Δt <= 14 天 => SAME`（无标题口径的强基线）

用法:
  python3 scripts/baselines.py [--asset real-augmented]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cti_streaming_benchmark_builder import EventLabel, read_jsonl, tokenize  # noqa: E402

DATA = ROOT / "data"
LABELS = [label.name for label in EventLabel]
ASSETS = {
    "real-wild": {
        "benchmark": "misp_osint_benchmark.jsonl",
        "input": "misp_osint_input.jsonl",
        "input_notitle": "misp_osint_input_notitle.jsonl",
    },
    "real-augmented": {
        "benchmark": "misp_sliced_benchmark.jsonl",
        "input": "misp_sliced_input.jsonl",
        "input_notitle": "misp_sliced_input_notitle.jsonl",
    },
    "real-augmented-attributed": {
        "benchmark": "misp_sliced_attributed_benchmark.jsonl",
        "input": "misp_sliced_attributed_input.jsonl",
        "input_notitle": "misp_sliced_attributed_input_notitle.jsonl",
    },
    "synthetic": {
        "benchmark": "synthetic_benchmark_1000.jsonl",
        "input": "synthetic_input_1000.jsonl",
        "input_notitle": "synthetic_input_notitle_1000.jsonl",
    },
}


def _score(gold: Sequence[str], predictions: Sequence[str]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    f1s: List[float] = []
    for label in LABELS:
        tp = sum(1 for g, p in zip(gold, predictions) if g == label and p == label)
        fp = sum(1 for g, p in zip(gold, predictions) if g != label and p == label)
        fn = sum(1 for g, p in zip(gold, predictions) if g == label and p != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        out[f"{label}_p"], out[f"{label}_r"], out[f"{label}_f1"] = precision, recall, f1
        f1s.append(f1)
    out["macro_f1"] = sum(f1s) / len(f1s)
    out["accuracy"] = sum(1 for g, p in zip(gold, predictions) if g == p) / len(gold)
    return out


def _majority(gold: Sequence[str]) -> List[str]:
    return [Counter(gold).most_common(1)[0][0]] * len(gold)


def _seen_rule(rows: Sequence[Dict], field: str) -> List[str]:
    """`field 此前出现过 => SAME`，其余落到多数类（不含 SAME）。"""
    counts = Counter(row["_label"] for row in rows)
    counts.pop(EventLabel.SAME_EVENT.name, None)
    fallback = counts.most_common(1)[0][0]
    seen: set = set()
    predictions: List[str] = []
    for row in rows:
        value = row.get(field) or ""
        predictions.append(EventLabel.SAME_EVENT.name if value in seen else fallback)
        seen.add(value)
    return predictions


def _jaccard_rule(rows: Sequence[Dict], field: str, threshold: float = 0.7,
                  window_days: float = 14.0) -> List[str]:
    counts = Counter(row["_label"] for row in rows)
    counts.pop(EventLabel.SAME_EVENT.name, None)
    fallback = counts.most_common(1)[0][0]
    seen: List[Tuple[datetime, frozenset]] = []
    predictions: List[str] = []
    for row in rows:
        tokens = tokenize(row.get(field) or "")
        moment = datetime.fromisoformat(row["publish_time"])
        hit = False
        if tokens:
            for stamp, other in seen:
                if abs((moment - stamp).total_seconds()) > window_days * 86400:
                    continue
                union = len(tokens | other)
                if union and len(tokens & other) / union >= threshold:
                    hit = True
                    break
        predictions.append(EventLabel.SAME_EVENT.name if hit else fallback)
        seen.append((moment, tokens))
    return predictions


def evaluate(name: str, files: Dict[str, str]) -> None:
    benchmark = DATA / files["benchmark"]
    if not benchmark.exists():
        return
    labels = {row["id"]: row["ground_truth_label_name"] for row in read_jsonl(benchmark)}

    for variant, field, rules in (
        ("with title", "title", [("title_seen", _seen_rule), ("title_jaccard", _jaccard_rule)]),
        ("no title", "text", [("text_jaccard", _jaccard_rule)]),
    ):
        path = DATA / "model_input" / files["input" if field == "title" else "input_notitle"]
        if not path.exists():
            continue
        rows = read_jsonl(path)
        for row in rows:
            row["_label"] = labels[row["id"]]
        gold = [row["_label"] for row in rows]
        print(f"\n### {name} — {variant}  n={len(rows)}  {dict(Counter(gold))}")
        print("  baseline         acc    macro-F1   SAME(P/R/F1)   UNSEEN-F1  RELATED-F1  NO-F1")
        scores = _score(gold, _majority(gold))
        print(
            f"  {'majority':15s} {scores['accuracy']:.3f}  {scores['macro_f1']:.3f}      "
            f"{scores['SAME_EVENT_p']:.3f}/{scores['SAME_EVENT_r']:.3f}/{scores['SAME_EVENT_f1']:.3f}"
            f"      {scores['UNSEEN_EVENT_f1']:.3f}      {scores['RELATED_EVENT_f1']:.3f}"
            f"      {scores['NO_EVENT_f1']:.3f}"
        )
        for label, rule in rules:
            scores = _score(gold, rule(rows, field) if rule is _seen_rule else rule(rows, field))
            print(
                f"  {label:15s} {scores['accuracy']:.3f}  {scores['macro_f1']:.3f}      "
                f"{scores['SAME_EVENT_p']:.3f}/{scores['SAME_EVENT_r']:.3f}/{scores['SAME_EVENT_f1']:.3f}"
                f"      {scores['UNSEEN_EVENT_f1']:.3f}      {scores['RELATED_EVENT_f1']:.3f}"
                f"      {scores['NO_EVENT_f1']:.3f}"
            )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Naive baselines on the model-facing inputs.")
    parser.add_argument("--asset", choices=sorted(ASSETS), help="只跑某个资产")
    args = parser.parse_args(argv)
    for name, files in ASSETS.items():
        if args.asset and args.asset != name:
            continue
        evaluate(name, files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
