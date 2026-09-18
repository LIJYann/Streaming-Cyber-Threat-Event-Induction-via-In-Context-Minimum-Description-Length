#!/usr/bin/env python3
"""
solvability_audit.py — 检查"去标题后是否变成不可解的天书"。

动机（可解性佯谬）: 去掉 `title` 之后，如果一篇增量切片只剩一串新生成的哈希，
那么**任何**模型都无法从虚空推断它属于哪起事件 —— 此时 SAME-F1 从 0.99 跌到 0.04
并不是"任务变难了"，而是"任务在信息论上不可解"。

本脚本统计每个类别的文档里，正文是否含至少一个**可解锚点**：
  * CVE 编号
  * 分析师批注 / 正文类属性（MalwareBlog 常把家族名写在 comment 里）
  * 内容级身份字段（malware-type / campaign-name / threat-actor / target-org / target-location）
  * 描述性链接（URL 里有可读 slug，而非纯哈希/ID）
  * 文件名 / 附件名
并报告"完全无锚点"的比例（这些文档在无标题口径下不可解）。

用法:
  python3 scripts/solvability_audit.py                       # 无标题口径
  python3 scripts/solvability_audit.py --variant with_title
  python3 scripts/solvability_audit.py --variant title_only   # 只看标题本身
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cti_streaming_benchmark_builder import read_jsonl  # noqa: E402

DATA = ROOT / "data"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# 16 进制串（含截断形式）不携带语义
HEX_RE = re.compile(r"^[0-9a-fA-F]{12,}\.*$")
SLUG_RE = re.compile(r"https?://[^\s;]+/[A-Za-z0-9_\-]{6,}")


def anchors_in(text: str) -> List[str]:
    """返回正文里出现的可解锚点类型。"""
    found: List[str] = []
    lowered = text.lower()
    if CVE_RE.search(text):
        found.append("cve")
    if "analyst notes" in lowered:
        found.append("analyst_note")
    if SLUG_RE.search(text):
        found.append("descriptive_link")
    for field in ("malware-type", "campaign-name", "threat-actor", "target-org",
                  "target-location", "target-user"):
        if field in lowered:
            found.append("content_identity")
            break
    for field in ("filename", "attachment", "malware-sample"):
        if field in lowered:
            found.append("file_artifact")
            break
    return found


def tokens_of(text: str) -> List[str]:
    return re.findall(r"\S+", text)


def hex_share(text: str) -> float:
    tokens = tokens_of(text)
    if not tokens:
        return 0.0
    return sum(1 for token in tokens if HEX_RE.match(token.rstrip(";,"))) / len(tokens)


def audit(variant: str) -> None:
    pairs = [
        ("real-wild", "misp_osint_benchmark.jsonl", "misp_osint_input.jsonl",
         "misp_osint_input_notitle.jsonl"),
        ("real-augmented", "misp_sliced_benchmark.jsonl", "misp_sliced_input.jsonl",
         "misp_sliced_input_notitle.jsonl"),
        ("synthetic", "synthetic_benchmark_1000.jsonl", "synthetic_input_1000.jsonl",
         "synthetic_input_notitle_1000.jsonl"),
    ]
    for name, benchmark_name, with_title_name, notitle_name in pairs:
        benchmark = DATA / benchmark_name
        if not benchmark.exists():
            continue
        labels = {row["id"]: row["ground_truth_label_name"] for row in read_jsonl(benchmark)}
        if variant == "with_title":
            path = DATA / "model_input" / with_title_name

            def text_of(row):
                return f"{row.get('title') or ''}\n{row['text']}"
        elif variant == "title_only":
            path = DATA / "model_input" / with_title_name

            def text_of(row):
                return row.get("title") or ""
        else:
            path = DATA / "model_input" / notitle_name

            def text_of(row):
                return row["text"]
        if not path.exists():
            continue

        per_class: Dict[str, Counter] = defaultdict(Counter)
        shares: Dict[str, List[float]] = defaultdict(list)
        for row in read_jsonl(path):
            label = labels[row["id"]]
            content = text_of(row)
            found = anchors_in(content)
            per_class[label]["n"] += 1
            per_class[label]["with_anchor"] += bool(found)
            per_class[label]["no_anchor"] += not found
            for anchor in found:
                per_class[label][anchor] += 1
            shares[label].append(hex_share(content))

        print(f"\n### {name} — 口径: {variant}")
        print("  label            n   有锚点   无锚点(不可解)  含CVE  分析师批注  描述性链接  文件样本  十六进制占比中位")
        for label in ("NO_EVENT", "SAME_EVENT", "RELATED_EVENT", "UNSEEN_EVENT"):
            stats = per_class.get(label)
            if not stats or not stats["n"]:
                continue
            n = stats["n"]
            median_hex = sorted(shares[label])[len(shares[label]) // 2]
            print(
                f"  {label:14s} {n:5d}  {stats['with_anchor']/n:6.1%}  "
                f"{stats['no_anchor']/n:11.1%}  {stats['cve']/n:5.1%}  "
                f"{stats['analyst_note']/n:9.1%}  {stats['descriptive_link']/n:10.1%}  "
                f"{stats['file_artifact']/n:7.1%}  {median_hex:12.1%}"
            )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check whether a projection stays solvable.")
    parser.add_argument(
        "--variant",
        choices=["notitle", "with_title", "title_only"],
        default="notitle",
        help="要审计的输入口径（默认 notitle）",
    )
    args = parser.parse_args(argv)
    audit(args.variant)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
