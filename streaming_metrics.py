"""
streaming_metrics.py — 流式事件归纳的标准指标。

与逐文档的 4-way 分类不同，流式系统的最终产物是一张**事件记忆图**（哪些文档被归到
同一个事件实例）。因此除 macro-F1 之外，还必须报告聚类层面的指标：

  * B-cubed Precision / Recall / F1 —— 事件发现领域（TDT）的金标准：
    对任意两篇文档，若 GT 属于同一事件，系统是否也把它们放在同一个节点；
  * Adjusted Rand Index (ARI) —— 整个流结束后划分的拓扑一致性（对簇数量不敏感）。

聚类由 (label, target) 决定：
  * `SAME`    -> 并入 `target` 所指向的已存在事件节点；
  * `UNSEEN`  -> 新建事件节点；
  * `RELATED` -> 新建事件节点（同 actor/campaign 下的独立事件实例）；
  * `NO_EVENT`-> 不进入事件图（不是事件，聚类指标里剔除，与 TDT 惯例一致）。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from itertools import combinations
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


def macro_f1(gold: Sequence[str], predicted: Sequence[str], labels: Iterable[str]) -> Dict[str, float]:
    """逐类 P/R/F1 + macro-F1 + accuracy。"""
    labels = list(labels)
    stats: Dict[str, float] = {}
    f1s: List[float] = []
    for label in labels:
        tp = sum(1 for g, p in zip(gold, predicted) if g == label and p == label)
        fp = sum(1 for g, p in zip(gold, predicted) if g != label and p == label)
        fn = sum(1 for g, p in zip(gold, predicted) if g == label and p != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        stats[f"{label}_p"], stats[f"{label}_r"], stats[f"{label}_f1"] = precision, recall, f1
        f1s.append(f1)
    stats["macro_f1"] = sum(f1s) / len(f1s) if f1s else 0.0
    stats["accuracy"] = (
        sum(1 for g, p in zip(gold, predicted) if g == p) / len(gold) if gold else 0.0
    )
    return stats


def clusters_from_predictions(
    doc_ids: Sequence[str],
    labels: Sequence[str],
    targets: Sequence[Optional[str]],
) -> Dict[str, str]:
    """把 (label, target) 解析成"文档 -> 事件簇"的划分（并查集）。

    `target` 允许两种写法，两种都支持：
      * 更早某篇**文档的 id**（"我把这篇并入那篇所在的事件"）；
      * 事件**锚点字符串**（如 `misp-event:<uuid>`），即系统自己命名的事件节点。
    """
    parent: Dict[str, str] = {doc_id: doc_id for doc_id in doc_ids}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for doc_id, label, target in zip(doc_ids, labels, targets):
        if label == "NO_EVENT":
            continue
        if label == "SAME_EVENT" and target:
            if target not in parent:  # 事件锚点（系统自命名节点）
                parent[target] = target
            union(target, doc_id)
    return {doc_id: find(doc_id) for doc_id in doc_ids if doc_id in parent}


def b_cubed(
    gold: Dict[str, str], predicted: Dict[str, str]
) -> Dict[str, float]:
    """B-cubed Precision / Recall / F1（按文档平均，两两假设下的闭式实现）。"""
    shared = [doc_id for doc_id in gold if doc_id in predicted]
    if not shared:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    gold_members: Dict[str, int] = Counter(gold[doc_id] for doc_id in shared)
    pred_members: Dict[str, int] = Counter(predicted[doc_id] for doc_id in shared)
    pairs: Dict[Tuple[str, str], int] = Counter(
        (gold[doc_id], predicted[doc_id]) for doc_id in shared
    )
    precision_total = 0.0
    recall_total = 0.0
    for doc_id in shared:
        key = (gold[doc_id], predicted[doc_id])
        precision_total += pairs[key] / pred_members[predicted[doc_id]]
        recall_total += pairs[key] / gold_members[gold[doc_id]]
    precision = precision_total / len(shared)
    recall = recall_total / len(shared)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def adjusted_rand_index(gold: Dict[str, str], predicted: Dict[str, str]) -> float:
    """ARI：按文档对统计一致性，并对随机划分做期望校正。"""
    shared = [doc_id for doc_id in gold if doc_id in predicted]
    n = len(shared)
    if n < 2:
        return 0.0
    gold_members: Dict[str, int] = Counter(gold[doc_id] for doc_id in shared)
    pred_members: Dict[str, int] = Counter(predicted[doc_id] for doc_id in shared)
    contingency: Dict[Tuple[str, str], int] = Counter(
        (gold[doc_id], predicted[doc_id]) for doc_id in shared
    )

    def comb2(value: int) -> float:
        return value * (value - 1) / 2

    sum_cells = sum(comb2(count) for count in contingency.values())
    sum_gold = sum(comb2(count) for count in gold_members.values())
    sum_pred = sum(comb2(count) for count in pred_members.values())
    total = comb2(n)
    expected = sum_gold * sum_pred / total if total else 0.0
    maximum = (sum_gold + sum_pred) / 2
    denominator = maximum - expected
    if denominator == 0:
        return 1.0 if sum_cells == expected else 0.0
    return (sum_cells - expected) / denominator


def clustering_scores(
    doc_ids: Sequence[str],
    gold_clusters: Dict[str, str],
    predicted_clusters: Dict[str, str],
) -> Dict[str, float]:
    scored = [doc_id for doc_id in doc_ids if doc_id in gold_clusters and doc_id in predicted_clusters]
    gold = {doc_id: gold_clusters[doc_id] for doc_id in scored}
    pred = {doc_id: predicted_clusters[doc_id] for doc_id in scored}
    scores = b_cubed(gold, pred)
    scores["ari"] = adjusted_rand_index(gold, pred)
    scores["n_clustered_docs"] = float(len(scored))
    scores["n_gold_clusters"] = float(len(set(gold.values())))
    scores["n_pred_clusters"] = float(len(set(pred.values())))
    return scores
