#!/usr/bin/env python3
"""
evaluate.py — 标准化的"流式在线评估协议"入口。

所有 baseline / 模型都用同一个接口，避免"评测口径不一致"被审稿人挑刺：

  python3 scripts/evaluate.py \\
      --stream data/model_input/misp_sliced_input.jsonl \\
      --benchmark data/misp_sliced_benchmark.jsonl \\
      --warmup 200 \\
      --metrics macro_f1,b_cubed,ari \\
      --pred predictions.jsonl

协议要点（写进 README，作为论文里的评测设定）：

1. **冷启动预热窗 (burn-in)**：流式记忆库在 t=0 是空的，前若干篇必然判不出 SAME。
   系统仍从第 1 篇开始运行（状态正常累积），但**指标只统计预热窗之后的文档**。
   `--warmup` 接受文档数（如 200）或比例（如 0.1）。

2. **簇级指标**：4-way macro-F1 只说明"每一步动作类型对不对"，不能说明"流结束后
   记忆图里的事件簇对不对"。因此同时报告 B-cubed F1 与 ARI（见 streaming_metrics）。
   GT 簇来自 benchmark 的 `target_incident_id`；`NO_EVENT` 文档按 TDT 惯例不进入
   事件图；预测簇由 (label, target) 并查集得到。

3. **预测文件格式**（每行一个 JSON）:
      {"id": "<样本 id>", "label": "SAME_EVENT", "target": "<被并入的样本 id>"}
   `target` 仅在 `label == SAME_EVENT` 时需要（指向更早的文档）。

   也可以不必自己实现 baseline，用内置的 `--baseline`:
      majority | title_seen | title_jaccard | text_jaccard | metadata_oracle
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cti_streaming_benchmark_builder import EventLabel, read_jsonl, tokenize  # noqa: E402
from streaming_metrics import (  # noqa: E402
    clusters_from_predictions,
    clustering_scores,
    macro_f1,
)

LABELS = [label.name for label in EventLabel]


def gold_clusters(benchmark_rows: Sequence[Dict]) -> Dict[str, str]:
    """GT 事件簇: 同一 `target_incident_id` 即同一事件实例；NO_EVENT 不入图。"""
    clusters: Dict[str, str] = {}
    for row in benchmark_rows:
        if row["ground_truth_label_name"] == EventLabel.NO_EVENT.name:
            continue
        anchor = row.get("target_incident_id") or row["id"]
        clusters[row["id"]] = anchor
    return clusters


def _fallback(rows: Sequence[Dict], labels: Sequence[str]) -> str:
    counts = {}
    for label in labels:
        counts[label] = counts.get(label, 0) + 1
    counts.pop(EventLabel.SAME_EVENT.name, None)
    return max(counts.items(), key=lambda kv: kv[1])[0]


def builtin_baseline(name: str, rows: Sequence[Dict], gold: Sequence[str]) -> List[Dict]:
    """内置基线：返回与 `--pred` 相同格式的预测。"""
    if name == "metadata_oracle":
        # oracle 用"事件的首篇文档 id"作为合并目标，与系统实际持有的记忆节点一致
        first_doc: Dict[str, str] = {}
        predictions: List[Dict] = []
        for row in rows:
            anchor = row.get("_oracle_target")
            label = row.get("_oracle_label")
            if label == EventLabel.NO_EVENT.name:
                predictions.append({"id": row["id"], "label": label, "target": None})
                continue
            if anchor and anchor in first_doc:
                predictions.append(
                    {"id": row["id"], "label": label, "target": first_doc[anchor]}
                )
            else:
                if anchor:
                    first_doc[anchor] = row["id"]
                predictions.append({"id": row["id"], "label": label, "target": None})
        return predictions
    fallback = _fallback(rows, gold)
    predictions: List[Dict] = []
    if name == "majority":
        return [{"id": row["id"], "label": fallback, "target": None} for row in rows]

    seen_titles: Dict[str, str] = {}
    seen: List[Tuple[datetime, frozenset, str]] = []
    for row in rows:
        title = row.get("title") or ""
        text = row.get("text") or ""
        moment = datetime.fromisoformat(row["publish_time"])
        label, target = fallback, None
        if name == "title_seen":
            if title in seen_titles:
                label, target = EventLabel.SAME_EVENT.name, seen_titles[title]
        else:
            field = title if name == "title_jaccard" else text
            tokens = tokenize(field)
            if tokens:
                best, best_score = None, 0.0
                for stamp, other, other_id in seen:
                    if abs((moment - stamp).total_seconds()) > 14 * 86400:
                        continue
                    union = len(tokens | other)
                    if not union:
                        continue
                    score = len(tokens & other) / union
                    if score > best_score:
                        best, best_score = other_id, score
                if best and best_score >= 0.7:
                    label, target = EventLabel.SAME_EVENT.name, best
        predictions.append({"id": row["id"], "label": label, "target": target})
        seen_titles.setdefault(title, row["id"])
        seen.append((moment, tokenize(title if name == "title_jaccard" else text), row["id"]))
    return predictions


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Standardised streaming evaluation protocol.")
    parser.add_argument("--stream", required=True, type=Path, help="模型输入 JSONL")
    parser.add_argument("--benchmark", required=True, type=Path, help="GT JSONL（含标签与 target_incident_id）")
    parser.add_argument(
        "--warmup",
        default="0",
        help="预热窗: 文档数 (200) 或比例 (0.1)；只有预热窗之后的文档计入指标",
    )
    parser.add_argument("--metrics", default="macro_f1,b_cubed,ari")
    parser.add_argument("--pred", type=Path, help="预测文件 JSONL")
    parser.add_argument(
        "--baseline",
        choices=["majority", "title_seen", "title_jaccard", "text_jaccard", "metadata_oracle"],
        help="内置基线（可选，替代 --pred）",
    )
    args = parser.parse_args(argv)

    benchmark_rows = read_jsonl(args.benchmark)
    by_id = {row["id"]: row for row in benchmark_rows}
    stream_rows = read_jsonl(args.stream)
    for row in stream_rows:
        row["_oracle_label"] = by_id[row["id"]]["ground_truth_label_name"]
        row["_oracle_target"] = by_id[row["id"]].get("target_incident_id")
    if not stream_rows:
        print("[error] empty stream", file=sys.stderr)
        return 2

    if args.pred:
        predictions = read_jsonl(args.pred)
        pred_by_id = {row["id"]: row for row in predictions}
    elif args.baseline:
        predictions = builtin_baseline(
            args.baseline, stream_rows, [row["_oracle_label"] for row in stream_rows]
        )
        pred_by_id = {row["id"]: row for row in predictions}
    else:
        print("[error] 需要 --pred 或 --baseline", file=sys.stderr)
        return 2

    warmup_raw = str(args.warmup)
    if warmup_raw.endswith("%"):
        cut = int(len(stream_rows) * float(warmup_raw.rstrip("%")) / 100)
    elif "." in warmup_raw:
        cut = int(len(stream_rows) * float(warmup_raw))
    else:
        cut = int(warmup_raw)
    cut = max(0, min(cut, len(stream_rows)))
    scored_rows = stream_rows[cut:]

    doc_ids = [row["id"] for row in scored_rows]
    gold = [row["_oracle_label"] for row in scored_rows]
    predicted = [pred_by_id.get(row["id"], {}).get("label", "NO_EVENT") for row in scored_rows]
    targets = [pred_by_id.get(row["id"], {}).get("target") for row in scored_rows]

    requested = {m.strip() for m in args.metrics.split(",") if m.strip()}
    summary: Dict[str, object] = {
        "stream": str(args.stream.name),
        "benchmark": str(args.benchmark.name),
        "n_documents": len(stream_rows),
        "warmup": cut,
        "n_scored": len(scored_rows),
        "predictor": args.pred.name if args.pred else args.baseline,
    }
    if "macro_f1" in requested:
        scores = macro_f1(gold, predicted, LABELS)
        summary["macro_f1"] = round(scores["macro_f1"], 4)
        summary["accuracy"] = round(scores["accuracy"], 4)
        summary["per_class_f1"] = {
            label: round(scores[f"{label}_f1"], 4) for label in LABELS
        }
    if "b_cubed" in requested or "ari" in requested:
        gold_map = gold_clusters(scored_rows and [by_id[i] for i in doc_ids] or [])
        gold_map = {row["id"]: gold_map[row["id"]] for row in scored_rows if row["id"] in gold_map}
        pred_map = clusters_from_predictions(doc_ids, predicted, targets)
        # 预测成 NO_EVENT 的文档不进入事件图
        pred_map = {
            doc_id: cluster
            for doc_id, cluster in pred_map.items()
            if doc_id in gold_map
            and pred_by_id.get(doc_id, {}).get("label", "NO_EVENT")
            != EventLabel.NO_EVENT.name
        }
        cluster_scores = clustering_scores(doc_ids, gold_map, pred_map)
        if "b_cubed" in requested:
            summary["b_cubed_precision"] = round(cluster_scores["precision"], 4)
            summary["b_cubed_recall"] = round(cluster_scores["recall"], 4)
            summary["b_cubed_f1"] = round(cluster_scores["f1"], 4)
        if "ari" in requested:
            summary["ari"] = round(cluster_scores["ari"], 4)
        summary["n_gold_clusters"] = int(cluster_scores["n_gold_clusters"])
        summary["n_pred_clusters"] = int(cluster_scores["n_pred_clusters"])

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
