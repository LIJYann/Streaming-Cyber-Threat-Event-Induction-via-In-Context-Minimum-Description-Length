#!/usr/bin/env python3
"""
cti_streaming_benchmark_builder.py

用于自动从 STIX 2.1 / MISP 元数据流中构建"在线事件实例发现"四分类 Benchmark。

标签类型:
  0: NO_EVENT        (噪声/无有效因果事件)
  1: SAME_EVENT      (已知事件的平行报道/增量更新)
  2: RELATED_EVENT   (同一组织/战役下的相关但独立事件)
  3: UNSEEN_EVENT    (首次出现的新组织/新战役全新事件)

设计要点:
  * 纯标准库实现 (Python >= 3.8)，不需要 `stix2`，可直接解析 STIX 2.1 Bundle JSON。
  * 标注是**流式**的: 状态机只允许看到 `t <= now` 的文档，因此标签不是对
    全量语料做一次聚类的结果，而是"该文档到达时系统已知世界"的判定。
  * 严格时间保序; 时间戳统一归一化为 naive-UTC，避免 aware/naive 混排崩溃。

用法:
  python3 cti_streaming_benchmark_builder.py --demo
  python3 cti_streaming_benchmark_builder.py --stix data/sample_stix_bundle.json \
      --out data/benchmark.jsonl --stats
  python3 cti_streaming_benchmark_builder.py --input my_documents.json --out out.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# --------------------------------------------------------------------------- #
# 数据模型
# --------------------------------------------------------------------------- #
class EventLabel(IntEnum):
    NO_EVENT = 0
    SAME_EVENT = 1
    RELATED_EVENT = 2
    UNSEEN_EVENT = 3


@dataclass
class CTIDocument:
    doc_id: str
    publish_time: datetime
    content: str
    # Ground Truth 元数据（来自 STIX / MISP 或规则注入）
    is_threat_report: bool
    incident_id: Optional[str] = None  # 具体安全事件实例 ID (Same 判定依据)
    campaign_id: Optional[str] = None  # 战役归属 (Related 判定依据)
    actor_id: Optional[str] = None     # 威胁团伙归属 (Related 判定依据)
    cves: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # 不同来源 (STIX "Z" / MISP / 手工构造) 的时区表示方式不一致，
        # 统一归一化为 naive UTC，避免 aware/naive 混排时排序崩溃。
        if self.publish_time.tzinfo is not None:
            self.publish_time = (
                self.publish_time.astimezone(timezone.utc).replace(tzinfo=None)
            )
        self.cves = set(self.cves or ())


@dataclass
class StreamingSample:
    doc_id: str
    publish_time: str
    content: str
    ground_truth_label: EventLabel
    target_incident_id: Optional[str]
    rationale: str

    @property
    def label_name(self) -> str:
        return self.ground_truth_label.name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "publish_time": self.publish_time,
            "content": self.content,
            "ground_truth_label": int(self.ground_truth_label),
            "ground_truth_label_name": self.label_name,
            "target_incident_id": self.target_incident_id,
            "rationale": self.rationale,
        }


# --------------------------------------------------------------------------- #
# 流式标注状态机
# --------------------------------------------------------------------------- #
class CTIStreamingBenchmarkGenerator:
    """按时间戳推进的 4-way 在线标注器。

    状态 (`seen_*`) 就是"系统已知世界"，只由**已经到达**的文档更新。
    """

    def __init__(self) -> None:
        # 模拟在线环境的 Oracle 历史记忆库
        self.seen_incidents: Set[str] = set()
        self.seen_campaigns: Set[str] = set()
        self.seen_actors: Set[str] = set()

    # -- 内部: 把文档中的锚点登记进已知世界 -------------------------------- #
    def _register(self, doc: CTIDocument) -> None:
        # 只登记非空锚点，避免 None 污染已知世界（否则 `None in seen` 会恒为真）
        if doc.incident_id:
            self.seen_incidents.add(doc.incident_id)
        if doc.campaign_id:
            self.seen_campaigns.add(doc.campaign_id)
        if doc.actor_id:
            self.seen_actors.add(doc.actor_id)

    def determine_ground_truth(self, doc: CTIDocument) -> StreamingSample:
        """核心流式标注状态机：依据因果溯源拓扑与已到达的历史动态判定标签"""
        publish_time = doc.publish_time.isoformat()

        # 1. 门控：无事件级威胁证据 (Noise)
        has_event_anchor = doc.incident_id is not None or doc.campaign_id is not None
        if (not doc.is_threat_report) or (not has_event_anchor):
            return StreamingSample(
                doc_id=doc.doc_id,
                publish_time=publish_time,
                content=doc.content,
                ground_truth_label=EventLabel.NO_EVENT,
                target_incident_id=None,
                rationale="Document lacks concrete causal incident anchors or threat actors.",
            )

        # 2. 已知事件的后续报道 (Same Event)
        if doc.incident_id is not None and doc.incident_id in self.seen_incidents:
            return StreamingSample(
                doc_id=doc.doc_id,
                publish_time=publish_time,
                content=doc.content,
                ground_truth_label=EventLabel.SAME_EVENT,
                target_incident_id=doc.incident_id,
                rationale=(
                    f"Incident {doc.incident_id} has been instantiated previously "
                    "in the stream."
                ),
            )

        # 3. 相关但独立的事件 (Related-Distinct Event)
        # 条件：该 Incident 是全新的，但其所属的 Campaign 或 Threat Actor 已存在于记忆中
        is_related_campaign = (
            doc.campaign_id is not None and doc.campaign_id in self.seen_campaigns
        )
        is_related_actor = (
            doc.actor_id is not None and doc.actor_id in self.seen_actors
        )

        if is_related_campaign or is_related_actor:
            self._register(doc)
            return StreamingSample(
                doc_id=doc.doc_id,
                publish_time=publish_time,
                content=doc.content,
                ground_truth_label=EventLabel.RELATED_EVENT,
                target_incident_id=doc.incident_id,
                rationale=(
                    "New incident instance under existing cluster "
                    f"(Actor: {doc.actor_id} / Campaign: {doc.campaign_id})."
                ),
            )

        # 4. 全新独立事件 (Previously Unseen Event)
        # 条件：完全未知的 Actor/Campaign/Incident
        self._register(doc)
        return StreamingSample(
            doc_id=doc.doc_id,
            publish_time=publish_time,
            content=doc.content,
            ground_truth_label=EventLabel.UNSEEN_EVENT,
            target_incident_id=doc.incident_id,
            rationale=(
                "Novel incident with novel attribution "
                f"(Actor: {doc.actor_id}, Campaign: {doc.campaign_id})."
            ),
        )

    def process_stream(self, raw_documents: Iterable[CTIDocument]) -> List[StreamingSample]:
        """严格按照时间戳先后顺序处理文档流。

        对同一时间戳的文档使用 `doc_id` 作为次级排序键，保证结果可复现。
        时间戳统一归一化为 naive UTC（同时覆盖构造后被就地修改的文档）。
        """
        normalised = [
            CTIDocument(
                doc_id=doc.doc_id,
                publish_time=doc.publish_time,
                content=doc.content,
                is_threat_report=doc.is_threat_report,
                incident_id=doc.incident_id,
                campaign_id=doc.campaign_id,
                actor_id=doc.actor_id,
                cves=doc.cves,
            )
            for doc in raw_documents
        ]
        sorted_docs = sorted(normalised, key=lambda d: (d.publish_time, d.doc_id))
        return [self.determine_ground_truth(doc) for doc in sorted_docs]


# --------------------------------------------------------------------------- #
# STIX 2.1 输入
# --------------------------------------------------------------------------- #
def _parse_time(value: str) -> datetime:
    """解析 STIX 时间戳并归一化为 naive UTC（便于跨来源混排与排序）。"""
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed

def load_stix_bundle(source: Any) -> List[CTIDocument]:
    """把 STIX 2.1 Bundle 映射为 CTIDocument 列表。

    映射规则 (SDO -> 文档 / 锚点):
      report     -> 一篇文档; `published`(缺省 `created`) 为发布时间
      incident   -> incident_id  (Same 判定锚点)
      campaign   -> campaign_id  (Related 判定锚点)
      threat-actor -> actor_id   (Related 判定锚点)
      vulnerability -> cves      (特征补充)

    关系解析: 文档的锚点由其 `object_refs` 出发，沿 `relationship` 对象做
    闭包遍历得到，因此 `campaign -attributed-to-> threat-actor` 这类间接
    归属也会被正确识别。

    只有 `report` 会变成文档（`incident` 是事件实例本身，只作为 `Same`
    判定锚点，不重复生成文档）；没有事件锚点（或带 `x_no_event: true`
    扩展）的文档会在状态机第 1 步被判为 NO_EVENT。
    """
    payload = source
    if isinstance(source, (str, Path)):
        payload = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "objects" not in payload:
        raise ValueError("Not a STIX 2.1 bundle: top level must be an object with 'objects'.")

    objects: Dict[str, Dict[str, Any]] = {
        obj["id"]: obj for obj in payload["objects"] if isinstance(obj, dict) and "id" in obj
    }

    # 邻接表: source_ref -> [target_ref, ...]
    edges: Dict[str, List[str]] = {}
    for obj in objects.values():
        if obj.get("type") == "relationship":
            edges.setdefault(obj["source_ref"], []).append(obj["target_ref"])
        for ref in obj.get("object_refs", []) or []:
            edges.setdefault(obj["id"], []).append(ref)

    def closure(start_refs: Sequence[str]) -> List[Dict[str, Any]]:
        """从若干 ref 出发，做去重后的可达闭包遍历。"""
        seen: Set[str] = set()
        queue: List[str] = [r for r in start_refs if r in objects]
        out: List[Dict[str, Any]] = []
        while queue:
            ref = queue.pop(0)
            if ref in seen:
                continue
            seen.add(ref)
            obj = objects[ref]
            out.append(obj)
            queue.extend(edges.get(ref, []))
        return out

    def pick(objs: Iterable[Dict[str, Any]], stix_type: str) -> Optional[str]:
        for obj in objs:
            if obj.get("type") == stix_type:
                return obj["id"]
        return None

    documents: List[CTIDocument] = []
    for obj in payload["objects"]:
        if not isinstance(obj, dict):
            continue
        stix_type = obj.get("type")
        if stix_type != "report":
            continue

        reachable = closure(obj.get("object_refs") or [obj["id"]])
        incident_id = pick(reachable, "incident")
        campaign_id = pick(reachable, "campaign")
        actor_id = pick(reachable, "threat-actor")
        cves = {
            o["name"]
            for o in reachable
            if o.get("type") == "vulnerability" and o.get("name")
        }

        raw_time = obj.get("published") or obj.get("created")
        if not raw_time:
            raise ValueError(f"Object {obj['id']} has neither 'published' nor 'created'.")

        # 没有 incident SDO 时，以文档自身 id 作为事件实例锚点：
        # 未被 incident 串联的 report 本身就是独立事件实例。
        incident_anchor = incident_id or obj["id"]

        # `x_no_event: true` 允许显式把通用安全科普稿注入为 NO_EVENT 噪声。
        is_threat_report = not obj.get("x_no_event", False)

        title = obj.get("name") or ""
        body = obj.get("description") or ""
        content = (title + "\n\n" + body).strip()

        documents.append(
            CTIDocument(
                doc_id=obj["id"],
                publish_time=_parse_time(raw_time),
                content=content,
                is_threat_report=is_threat_report,
                incident_id=incident_anchor,
                campaign_id=campaign_id,
                actor_id=actor_id,
                cves=cves,
            )
        )

    return documents


def load_documents(source: Any) -> List[CTIDocument]:
    """加载 JSON / JSONL 形式的原始文档流（`CTIDocument` 字段子集）。"""
    path = Path(source)
    text = path.read_text(encoding="utf-8")
    records: List[Dict[str, Any]] = []
    if path.suffix.lower() in (".jsonl", ".ndjson"):
        for line in text.splitlines():
            if line.strip():
                records.append(json.loads(line))
    else:
        loaded = json.loads(text)
        records = loaded["documents"] if isinstance(loaded, dict) else loaded

    documents = []
    for rec in records:
        documents.append(
            CTIDocument(
                doc_id=rec["doc_id"],
                publish_time=_parse_time(rec["publish_time"]),
                content=rec.get("content", ""),
                is_threat_report=rec.get("is_threat_report", True),
                incident_id=rec.get("incident_id"),
                campaign_id=rec.get("campaign_id"),
                actor_id=rec.get("actor_id"),
                cves=set(rec.get("cves") or []),
            )
        )
    return documents


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def write_jsonl(samples: Sequence[StreamingSample], out_path: Path) -> Path:
    """导出为带绝对时间戳的 JSON Lines（标准流式 Benchmark 格式）。"""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(sample.to_dict(), ensure_ascii=False) + "\n")
    return out_path


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def summarize(samples: Sequence[StreamingSample]) -> Dict[str, Any]:
    distribution = Counter(s.ground_truth_label.name for s in samples)
    present = {label.name for label in EventLabel if distribution.get(label.name, 0) > 0}
    return {
        "n_samples": len(samples),
        "label_distribution": {label.name: distribution.get(label.name, 0) for label in EventLabel},
        "all_four_labels_present": len(present) == len(EventLabel),
        "missing_labels": sorted({label.name for label in EventLabel} - present),
        "time_range": [
            min((s.publish_time for s in samples), default=None),
            max((s.publish_time for s in samples), default=None),
        ],
    }


# --------------------------------------------------------------------------- #
# 演示数据（与线上脚本中 __main__ 的 5 篇文档一致）
# --------------------------------------------------------------------------- #
def demo_stream() -> List[CTIDocument]:
    return [
        # t0: 噪声 - 一篇通用网络安全培训教程
        CTIDocument(
            doc_id="doc_001",
            publish_time=datetime(2026, 1, 1, 10, 0),
            content="Tips for setting up strong corporate passwords and MFA...",
            is_threat_report=False,
        ),
        # t1: APT29 针对外交机构发起攻击 A (首次出现 -> UNSEEN)
        CTIDocument(
            doc_id="doc_002",
            publish_time=datetime(2026, 1, 2, 14, 0),
            content="APT29 targeted Ministry of Foreign Affairs using CVE-2025-1111...",
            is_threat_report=True,
            incident_id="incident_apt29_embassy_2026",
            campaign_id="campaign_nobelium_2026",
            actor_id="APT29",
            cves={"CVE-2025-1111"},
        ),
        # t2: 另一家安全厂商对攻击 A 的平行分析 (同一 incident -> SAME)
        CTIDocument(
            doc_id="doc_003",
            publish_time=datetime(2026, 1, 3, 9, 30),
            content="Technical breakdown of the backdoor used in the Ministry breach (CVE-2025-1111)...",
            is_threat_report=True,
            incident_id="incident_apt29_embassy_2026",
            campaign_id="campaign_nobelium_2026",
            actor_id="APT29",
            cves={"CVE-2025-1111"},
        ),
        # t3: APT29 发起了另一场针对能源企业的攻击 B (同组织不同事件 -> RELATED)
        CTIDocument(
            doc_id="doc_004",
            publish_time=datetime(2026, 1, 5, 11, 0),
            content="APT29 breached a power grid operator leveraging novel wiper...",
            is_threat_report=True,
            incident_id="incident_apt29_powergrid_2026",
            campaign_id="campaign_nobelium_2026",
            actor_id="APT29",
            cves={"CVE-2025-9999"},
        ),
        # t4: LockBit 勒索软件新变种横空出世 (全新未知团伙 -> UNSEEN)
        CTIDocument(
            doc_id="doc_005",
            publish_time=datetime(2026, 1, 6, 16, 0),
            content="LockBit 4.0 detected encrypting municipal health systems...",
            is_threat_report=True,
            incident_id="incident_lockbit_hospital_2026",
            campaign_id="campaign_lockbit_wave",
            actor_id="LockBit_Gang",
        ),
    ]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a 4-way streaming ground-truth benchmark from STIX 2.1 CTI metadata."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo", action="store_true", help="运行内置的 5 篇文档演示流")
    group.add_argument("--stix", metavar="BUNDLE.json", help="STIX 2.1 Bundle 路径")
    group.add_argument("--input", metavar="DOCS.json", help="原始文档流 (JSON / JSONL)")
    parser.add_argument("--out", metavar="OUT.jsonl", help="导出 JSON Lines 路径")
    parser.add_argument("--stats", action="store_true", help="打印标签分布与校验信息")
    parser.add_argument("--quiet", action="store_true", help="只输出导出路径/统计，不逐条打印")
    args = parser.parse_args(argv)

    if args.stix:
        documents = load_stix_bundle(args.stix)
    elif args.input:
        documents = load_documents(args.input)
    else:
        documents = demo_stream()
        args.demo = True

    builder = CTIStreamingBenchmarkGenerator()
    benchmark_stream = builder.process_stream(documents)

    if not args.quiet:
        print("=== 流式 4-Way 自动标注流水线输出 ===")
        for item in benchmark_stream:
            print(f"[{item.publish_time}] Doc: {item.doc_id}")
            print(f"  -> Label   : {item.ground_truth_label.name}")
            print(f"  -> Reason  : {item.rationale}\n")

    if args.out:
        path = write_jsonl(benchmark_stream, Path(args.out))
        print(f"[ok] wrote {len(benchmark_stream)} samples -> {path}")

    if args.stats:
        stats = summarize(benchmark_stream)
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        if not stats["all_four_labels_present"]:
            print(f"[warn] missing labels: {stats['missing_labels']}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
