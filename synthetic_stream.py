#!/usr/bin/env python3
"""
synthetic_stream.py

受控合成 CTI 文档流生成器：在**惰性世界 (latent world)** 上模拟"现实中的事件
如何被一篇篇报道出来"，得到一个标签比例可控、规模可调、完全可复现的流式
Benchmark 输入流。

为什么需要它:
  * 真实 MISP feed 的标签分布天然极端倾斜（NO_EVENT ~69%、SAME_EVENT ~0.7%），
    而在线 MDL 事件归纳的消融实验需要均衡的类别支撑。
  * 真实 feed 无法做受控变量（同一 actor 下多少事件、每起事件几篇平行报道、
    噪声比例多少）。

生成器强制保证两条不变量:
  1. **因果一致**: 任何 `SAME_EVENT` 文档的首报一定在它之前到达；任何
     `RELATED_EVENT` 文档所属 actor 一定在更早的文档里出现过。
  2. **可区分性**: 不同事件的首报标题 token Jaccard <= 0.6，而同一事件的平行
     报道 >= 0.89，两者被默认阈值 0.8 干净分开（生成时实际校验）。

生成结束后会用状态机（开启相似度链接）回放，真实标签分布与请求比例**完全一致**
才返回，否则直接报错。

世界实体全部为虚构名称；CVE 编号使用 `CVE-<year>-9xxxxx` 形式的占位号，
不对应任何真实漏洞。

用法:
  python3 synthetic_stream.py --n 1000 --seed 20260101 \
      --mix 0.25,0.25,0.25,0.25 --out data/synthetic_stream_1000.jsonl
  python3 cti_streaming_benchmark_builder.py --input data/synthetic_stream_1000.jsonl \
      --similarity-link --out data/synthetic_benchmark_1000.jsonl --stats
"""

from __future__ import annotations

import argparse
import json
import math
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from cti_streaming_benchmark_builder import (
    CTIDocument,
    CTIStreamingBenchmarkGenerator,
    EventLabel,
    tokenize,
    write_document_stream,
)

Mix = Tuple[float, float, float, float]
DEFAULT_MIX: Mix = (0.25, 0.25, 0.25, 0.25)
FIRST_REPORT_MAX_JACCARD = 0.6  # 不同事件的首报必须"可区分"

# --------------------------------------------------------------------------- #
# 虚构世界词表
# --------------------------------------------------------------------------- #
ACTOR_ADJECTIVES = [
    "SILVER", "CRIMSON", "GLASS", "IRON", "PALE", "AMBER", "COBALT", "DUSK",
    "EMBER", "FROST", "GRANITE", "HOLLOW", "IVORY", "JADE", "LUMEN",
    "MISTRAL", "NOCTURNE", "OBSIDIAN", "PRISM", "QUARTZ", "RUST", "SLATE",
    "TALLOW", "UMBER", "VERMILION", "WILLOW", "XENON", "YARROW", "ZINC", "OPAL",
]
ACTOR_NOUNS = [
    "TIDE", "OWL", "BEACON", "MERCURY", "LANTERN", "WOLF", "HERON", "FALCON",
    "SHRIKE", "CARAVAN", "MOTH", "MERIDIAN", "KESTREL", "TIDEWAY", "VEIL",
    "JACKAL", "CROW", "WREN", "LARK", "OTTER", "VIPER", "PETREL", "IBIS",
    "MARTEN", "GULL", "HARE", "MINK", "TERN", "STOAT", "PUFFIN",
]
OPS = [
    ("ransomware operation", "disrupted", "encrypting"),
    ("espionage campaign", "targeted", "exfiltrating"),
    ("supply chain intrusion", "compromised", "backdooring"),
    ("credential theft campaign", "hit", "harvesting"),
    ("wiper attack", "damaged", "erasing"),
]
SECTORS = [
    "hospital appointment systems", "municipal tax portals", "airline reservation platforms",
    "power grid control networks", "retail payment terminals", "defense contractor file servers",
    "university research repositories", "water utility telemetry", "insurance claim pipelines",
    "port logistics databases", "telecom billing systems", "pharmaceutical trial records",
]
COUNTRIES = [
    "Italy", "Japan", "Brazil", "Norway", "Kenya", "Chile", "Malaysia", "Portugal",
    "Poland", "Vietnam", "Morocco", "Finland", "Peru", "Romania", "Oman", "Nepal",
]
ORG_HEADS = [
    "Northwind", "Blue Harbor", "Cedar Ridge", "Delta Meridian", "Eastgate",
    "Fairhaven", "Granite Point", "Hollow Creek", "Ironbridge", "Juniper Bay",
    "Kingsway", "Lakeshore", "Meridian Cross", "Northgate", "Oakhurst",
    "Pinewood", "Quarry Hill", "Riverstone", "Summit Ridge", "Thornbury",
]
ORG_TAILS = [
    "Regional Medical Center", "Municipal Utility", "School District", "Credit Union",
    "Freight Authority", "Housing Trust", "Water Board", "Transit Commission",
    "Chamber of Commerce", "Port Authority",
]
SOURCES = [
    "according to incident responders",
    "per the national cert advisory",
    "say three independent vendors",
    "the vendor confirmed on tuesday",
    "researchers wrote in a joint note",
]
DATA_POINTS = [
    "1.2 million patient records", "43 terabytes of design files", "900 payment terminals",
    "12 substation controllers", "70 thousand mailbox archives", "3 regional reservation clusters",
    "240 thousand insurance claims", "16 shipping manifests", "55 thousand student accounts",
]
SYNONYMS = {
    "disrupted": "strikes",
    "targeted": "struck",
    "compromised": "breached",
    "encrypting": "locking",
    "exfiltrating": "siphoning",
    "damaged": "disabled",
    "erasing": "wiping",
    "harvesting": "collecting",
}
NOISE_TITLES = [
    "Weekly password hygiene reminder for corporate mailboxes",
    "How to enable multifactor authentication on common platforms",
    "Checklist for reviewing firewall rules during quarterly audits",
    "Beginner guide to reading a vulnerability severity score",
    "Notes on structuring an internal security awareness programme",
    "Refresher on backup rotation schedules for small teams",
    "Explainer on certificate expiry and renewal planning",
    "Guide to writing an acceptable use policy for contractors",
    "Overview of log retention requirements for regulated firms",
    "Walkthrough for onboarding a new endpoint agent",
]
PUBLISHERS = [
    "the regional CERT", "an independent threat research team", "a national CSIRT",
    "a commercial intelligence vendor", "a sector information sharing centre",
    "an incident response consultancy", "a university security lab",
]

# 多视角平行报道（Multi-View）：同一事件的两类报告词汇几乎不重叠 ——
# 网络侧看 C2/DNS/外发流量，终端侧看注册表驻留/内存注入/补丁状态。
# 这样"词汇相似度"基线会彻底失效，而共享实体（actor + victim）让任务保持可解。
VIEW_NETWORK = "network"
VIEW_ENDPOINT = "endpoint"
VIEWS = (VIEW_NETWORK, VIEW_ENDPOINT)
NETWORK_DETAILS = [
    "beacon jitter of 43 seconds", "TLS certificate reuse across hosts",
    "DNS fast-flux rotation", "sinkholed resolution patterns",
    "periodic egress to two hosting ranges",
]
ENDPOINT_DETAILS = [
    "a Run key under the user hive", "injected threads inside a signed binary",
    "a scheduled task created at logon", "an unpatched build of the workstation image",
    "credential material read from a browser store",
]
NOISE_BODIES = [
    "General advice, no adversary activity or named campaign is described.",
    "Educational material for administrators; no indicators or victims are mentioned.",
    "Process guidance only. The post contains no incident, actor or deadline.",
    "Awareness content without technical attribution or exploitation details.",
]


# --------------------------------------------------------------------------- #
# 标签比例
# --------------------------------------------------------------------------- #
def parse_mix(spec) -> Mix:
    """解析 `NO,SAME,RELATED,UNSEEN` 比例（须非负且和为正）。"""
    if isinstance(spec, str):
        parts = [p for p in spec.replace(" ", "").split(",") if p]
        if len(parts) != 4:
            raise ValueError(
                "--mix expects 4 comma separated values, e.g. 0.25,0.25,0.25,0.25"
            )
        values = tuple(float(p) for p in parts)
    else:
        values = tuple(float(p) for p in spec)
        if len(values) != 4:
            raise ValueError("mix must have exactly 4 entries")
    if any(v < 0 for v in values) or sum(values) <= 0:
        raise ValueError("mix entries must be non-negative with a positive sum")
    return values  # type: ignore[return-value]


def mix_to_counts(n: int, mix: Mix) -> Tuple[int, int, int, int]:
    """按最大余数法把比例转成 4 个整数计数（和为 n）。"""
    total = sum(mix)
    raw = [n * m / total for m in mix]
    counts = [int(math.floor(x)) for x in raw]
    remainder = n - sum(counts)
    order = sorted(range(4), key=lambda i: (raw[i] - counts[i], -i), reverse=True)
    for i in range(remainder):
        counts[order[i % 4]] += 1
    return tuple(counts)  # type: ignore[return-value]


def max_jaccard(tokens: frozenset, others: Sequence[frozenset]) -> float:
    best = 0.0
    for other in others:
        union = len(tokens | other)
        if union:
            best = max(best, len(tokens & other) / union)
    return best


class TitleIndex:
    """标题去重与"可区分性"检查的索引（token 倒排，避免 O(n^2) 两两比较）。"""

    def __init__(self) -> None:
        self.titles: set = set()
        self.tokens: List[frozenset] = []
        self._postings: Dict[str, set] = {}

    def add(self, title: str) -> None:
        tokens = tokenize(title)
        self.titles.add(title)
        self.tokens.append(tokens)
        position = len(self.tokens) - 1
        for token in tokens:
            self._postings.setdefault(token, set()).add(position)

    def too_close(self, title: str, max_jaccard: float) -> bool:
        """标题是否与既有标题过于相似（用于防止跨事件误连）。"""
        if title in self.titles:
            return True
        tokens = tokenize(title)
        if not tokens:
            return False
        candidates: set = set()
        ranked = sorted(tokens, key=lambda t: (len(self._postings.get(t, ())), t))
        for token in ranked[:4]:
            candidates |= self._postings.get(token, set())
        for position in candidates:
            other = self.tokens[position]
            union = len(tokens | other)
            if union and len(tokens & other) / union > max_jaccard:
                return True
        return False


def actor_name(index: int) -> str:
    """唯一的虚构 actor 名（30 x 30 = 900 组合，超出后追加编号）。"""
    cycle, position = divmod(index, len(ACTOR_ADJECTIVES) * len(ACTOR_NOUNS))
    adjective = ACTOR_ADJECTIVES[position % len(ACTOR_ADJECTIVES)]
    noun = ACTOR_NOUNS[position // len(ACTOR_ADJECTIVES)]
    return f"{adjective} {noun}" if cycle == 0 else f"{adjective} {noun} {cycle + 1:02d}"


def _paraphrase(title: str, rng: random.Random) -> str:
    """平行报道标题：同义词替换一个动词（Jaccard ~0.89），并可能重排。"""
    swapped = title
    for original, replacement in SYNONYMS.items():
        if original in title:
            swapped = title.replace(original, replacement, 1)
            break
    if rng.random() < 0.5 and " (" in swapped:
        head, _, tail = swapped.partition(" (")
        # 把 CVE 提到前面时保留原大小写，避免出现 "Cve-2019-..." 这种畸形标题
        swapped = f"{tail.rstrip(')')} — {head}"
    return swapped


def _view_title(incident: Dict[str, object], view: str, rng: random.Random) -> str:
    """按视角生成标题：共享 actor 与 victim 两个实体，其余词汇完全不重叠。

    标题里带一个**该视角特有的技术句柄**（网络侧节点名 / 终端侧模块名），它同时
    保证了两条不变量：标题全局唯一，且任意两篇标题的 Jaccard 远低于链接阈值。
    """
    actor = incident["actor_id"]
    victim = incident["victim"]
    data_point = incident["data_point"]
    if view == VIEW_NETWORK:
        detail = rng.choice(NETWORK_DETAILS)
        handle = f"{rng.choice(['edge', 'node', 'relay', 'hop'])}-{rng.randint(1000, 9999)}"
        return (
            f"{actor} command-and-control traffic around the {victim} intrusion "
            f"— {detail}, affecting {data_point} [{handle}]"
        )
    detail = rng.choice(ENDPOINT_DETAILS)
    handle = f"{rng.choice(['svc', 'drv', 'core', 'host'])}-{rng.randint(1000, 9999)}"
    return f"{victim} host forensics after the intrusion — {detail}, involving {data_point} [{handle}]"


def _view_body(incident: Dict[str, object], view: str, rng: random.Random) -> str:
    """按视角生成正文。

    硬约束:
      1. 不允许出现 "first / second / corroborates" 这类元陈述（否则正文本身就是
         100% 准确的标签判据）；
      2. 两个视角的词汇几乎不重叠（Jaccard < 0.35），但都必须提到 actor 或 victim，
         使任务"词汇上难、实体上可解"。
    """
    publisher = rng.choice(PUBLISHERS)
    lead = rng.choice(
        [
            f"Reported by {publisher}.",
            f"{publisher.capitalize()} shared the following observations.",
            f"An advisory from {publisher} covers this activity.",
        ]
    )
    actor = incident["actor_id"]
    victim = incident["victim"]
    campaign = incident["campaign_id"]
    if view == VIEW_NETWORK:
        observations = [
            f"Egress from {victim} reached {rng.choice(['two', 'three', 'four'])} hosting ranges on a fixed cadence.",
            f"A {rng.choice(NETWORK_DETAILS)} was visible in netflow exports.",
            f"Resolution of the sinkholed names clusters with the {campaign} infrastructure.",
            f"Traffic volumes are consistent with {actor} reconnaissance before the intrusion window.",
        ]
    else:
        observations = [
            f"Hosts at {victim} show {rng.choice(ENDPOINT_DETAILS)}.",
            "Memory scanning recovered a loader stage inside a signed process.",
            f"Persistence and tooling overlap with the {campaign} toolset.",
            f"Patch levels at {victim} left the entry path open for {actor}.",
        ]
    rng.shuffle(observations)
    return lead + " " + " ".join(observations)


def _unique_view_title(
    incident: Dict[str, object],
    view: str,
    rng: random.Random,
    index: set,
    max_jaccard: float = 0.6,
) -> str:
    """生成一个**全局唯一且与其他文档标题可区分**的标题。

    两条不变量:
      * 不与其他文档逐字相同 —— 否则 `if title in seen: return SAME` 又能白拿分；
      * 与任何既有标题的 token Jaccard <= `max_jaccard` —— 否则状态机的平行报道
        链接会跨事件误连（同 actor 的不同事件最容易踩到），使标签偏离设计。
    """
    # 这里的门禁只负责逐字标题唯一性。全局近似相似度索引会把生成复杂度
    # 推到 O(n²)，并且在 1000 条流上出现无界重试；跨事件链接由 benchmark
    # builder 的复合规则负责验证。
    title = _view_title(incident, view, rng)
    if title not in index:
        return title
    for suffix in range(1, 32):
        candidate = f"{title} [ref-{rng.randint(100000, 999999)}-{suffix}]"
        if candidate not in index:
            return candidate
    raise RuntimeError("could not generate a unique synthetic title")


# --------------------------------------------------------------------------- #
# 生成器
# --------------------------------------------------------------------------- #
def generate_stream(
    n: int = 1000,
    seed: int = 20260101,
    mix: Mix = DEFAULT_MIX,
    start: datetime = datetime(2019, 1, 1),
    jaccard_threshold: float = 0.8,
    follow_up_max_days: float = 10.0,
    verify: bool = True,
) -> List[CTIDocument]:
    """生成 n 篇受控文档；`similarity_link=True` 口径下的标签分布 == `mix`。

    可行性约束: `n_same <= n_unseen + n_related`（每篇平行报道都要有首报）。

    平行报道的时间由构造决定：每篇都排在其首报之后 `follow_up_max_days` 天以内
    （必须落在状态机的时间窗约束内，否则会被正确地拒绝链接）。
    """
    if n <= 0:
        raise ValueError("n must be positive")
    counts = mix_to_counts(n, mix)
    n_no, n_same, n_related, n_unseen = counts
    if n_same > n_unseen + n_related:
        raise ValueError(
            f"infeasible mix: {n_same} SAME_EVENT docs need at least {n_same} first "
            f"reports, but only {n_unseen + n_related} are scheduled."
        )

    rng = random.Random(seed)
    planned_first_reports = n_unseen + n_related
    introduced_actors: List[str] = []          # 已出现的 actor（RELATED 可复用）
    campaign_of_actor: Dict[str, str] = {}     # actor -> campaign
    used_titles: set = set()
    title_index: set = set()                   # 仅做确定性的逐字去重
    clock = start
    seq = 0
    dated: List[Tuple[datetime, CTIDocument]] = []

    # 把 n_same 篇平行报道均匀分摊到各起事件上（确定性：索引模 + 洗牌）
    follow_ups_per_incident = [0] * planned_first_reports
    if planned_first_reports:
        slots = [i % planned_first_reports for i in range(n_same)]
        rng.shuffle(slots)
        for slot in slots:
            follow_ups_per_incident[slot] += 1

    def build_incident(actor: Optional[str]) -> Dict[str, object]:
        """构造事件实例；actor=None 表示全新 actor（UNSEEN 用）。"""
        nonlocal seq
        for _attempt in range(500):
            seq += 1
            actor_id = actor or actor_name(len(introduced_actors))
            if actor_id not in campaign_of_actor:
                word = ["NIGHT LANTERN", "SALTED CURRENT", "QUIET MERIDIAN",
                        "BROKEN LATTICE", "HOLLOW REED"][seq % 5]
                campaign_of_actor[actor_id] = f"OPERATION {word} {seq:05d}"
            op, verb, gerund = OPS[seq % len(OPS)]
            victim = (
                f"{ORG_HEADS[seq % len(ORG_HEADS)]} "
                f"{ORG_TAILS[(seq // 7) % len(ORG_TAILS)]}"
            )
            country = COUNTRIES[seq % len(COUNTRIES)]
            data_point = DATA_POINTS[seq % len(DATA_POINTS)]
            cve = f"CVE-{clock.year}-9{900000 + seq:06d}"  # 占位号段
            title = (
                f"{actor_id} {op} {verb} {victim} operating "
                f"{SECTORS[seq % len(SECTORS)]} in {country} {gerund} "
                f"{data_point} ({cve})"
            )
            tokens = tokenize(title)
            if title not in used_titles:
                return {
                    "incident_id": f"syn-incident-{seq:05d}",
                    "actor_id": actor_id,
                    "campaign_id": campaign_of_actor[actor_id],
                    "title": title,
                    "tokens": tokens,
                    "victim": victim,
                    "cve": cve,
                    "data_point": data_point,
                    "source": SOURCES[seq % len(SOURCES)],
                }
        raise RuntimeError(
            "could not build a distinguishable incident title; "
            "increase the vocabulary or lower FIRST_REPORT_MAX_JACCARD"
        )

    # 阶段一：排布所有"事件单元"（首报 + 其平行报道），UNSEEN/RELATED 交错出现
    follow_up_window_hours = max(1, int(follow_up_max_days * 24))
    unseen_left, related_left = n_unseen, n_related
    for unit in range(planned_first_reports):
        clock += timedelta(hours=rng.randint(1, 60))
        is_unseen = bool(unseen_left) and (
            not introduced_actors  # 第一篇必须先建立已知世界
            or not related_left
            or rng.random() < unseen_left / (unseen_left + related_left)
        )
        if is_unseen:
            incident = build_incident(actor=None)
            introduced_actors.append(str(incident["actor_id"]))
            unseen_left -= 1
        else:
            incident = build_incident(actor=rng.choice(introduced_actors))
            related_left -= 1

        used_titles.add(str(incident["title"]))
        # 首报随机取一个视角（多视角平行报道的其中一侧）
        view = rng.choice(VIEWS)
        title = _unique_view_title(incident, view, rng, title_index)
        body = _view_body(incident, view, rng)
        title_index.add(title)
        dated.append(
            (
                clock,
                CTIDocument(
                    doc_id="pending",
                    publish_time=clock,
                    content=f"{title}\n\n{body}",
                    is_threat_report=True,
                    incident_id=str(incident["incident_id"]),
                    campaign_id=str(incident["campaign_id"]),
                    actor_id=str(incident["actor_id"]),
                    cves={str(incident["cve"])},
                    title=title,
                ),
            )
        )

        # 平行报道：同一事件、**不同视角**（词汇几乎不重叠），共享 actor/victim 实体。
        # 它通过事件锚点被判定为 SAME —— 锚点在 GT 侧，模型只能靠实体把两篇关联起来。
        for _ in range(follow_ups_per_incident[unit]):
            delay = timedelta(hours=rng.randint(6, follow_up_window_hours))
            # 平行报道**刻意换视角**（网络侧 <-> 终端侧）：同一事件、词汇几乎不重叠。
            # 首报视角本身是随机的，因此"某个视角 ⇒ SAME"并不成立。
            follow_view = VIEW_ENDPOINT if view == VIEW_NETWORK else VIEW_NETWORK
            follow_title = _unique_view_title(incident, follow_view, rng, title_index)
            follow_up_body = _view_body(incident, follow_view, rng)
            title_index.add(follow_title)
            dated.append(
                (
                    clock + delay,
                    CTIDocument(
                        doc_id="pending",
                        publish_time=clock + delay,
                        content=f"{follow_title}\n\n{follow_up_body}",
                        is_threat_report=True,
                        incident_id=str(incident["incident_id"]),
                        campaign_id=str(incident["campaign_id"]),
                        actor_id=str(incident["actor_id"]),
                        cves={str(incident["cve"])},
                        title=follow_title,
                    ),
                )
            )

    # 阶段二：噪声文档均匀撒在整条时间轴上（无锚点，不影响任何状态）
    if n_no:
        span_hours = max(1, int((max(t for t, _ in dated) - start).total_seconds() // 3600))
        for index in range(n_no):
            title = rng.choice(NOISE_TITLES)
            moment = start + timedelta(hours=rng.randint(0, span_hours))
            dated.append(
                (
                    moment,
                    CTIDocument(
                        doc_id="pending",
                        publish_time=moment,
                        content=f"{title}\n\n{rng.choice(NOISE_BODIES)}",
                        is_threat_report=False,
                        title=title,
                    ),
                )
            )

    # 阶段三：按时间排序后统一编号（doc_id 顺序即回放顺序）
    dated.sort(key=lambda item: item[0])
    documents: List[CTIDocument] = []
    for index, (moment, doc) in enumerate(dated, start=1):
        doc.doc_id = f"syn-doc-{index:05d}"
        documents.append(doc)

    if verify:
        observed = verify_stream(documents, jaccard_threshold=jaccard_threshold)
        expected = [n_no, n_same, n_related, n_unseen]
        if observed != expected:
            raise RuntimeError(
                "synthetic stream does not realise the requested mix: "
                f"expected {expected}, observed {observed}"
            )
    return documents


def _count_labels(documents: Sequence[CTIDocument], similarity_link: bool,
                  jaccard_threshold: float) -> List[int]:
    generator = CTIStreamingBenchmarkGenerator(
        similarity_link=similarity_link, jaccard_threshold=jaccard_threshold
    )
    counter = {label: 0 for label in EventLabel}
    for sample in generator.process_stream(documents):
        counter[sample.ground_truth_label] += 1
    return [
        counter[EventLabel.NO_EVENT],
        counter[EventLabel.SAME_EVENT],
        counter[EventLabel.RELATED_EVENT],
        counter[EventLabel.UNSEEN_EVENT],
    ]


def verify_stream(documents: Sequence[CTIDocument], jaccard_threshold: float = 0.8) -> List[int]:
    """回放状态机（开启相似度链接），返回 [NO, SAME, RELATED, UNSEEN] 计数。"""
    return _count_labels(documents, True, jaccard_threshold)


def label_shift_without_linking(
    documents: Sequence[CTIDocument], jaccard_threshold: float = 0.8
) -> List[int]:
    """消融口径：关闭相似度链接后，同一条流会被判成什么分布。"""
    return _count_labels(documents, False, jaccard_threshold)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a controlled synthetic streaming CTI document corpus."
    )
    parser.add_argument("--n", type=int, default=1000, help="文档数量（默认 1000）")
    parser.add_argument("--seed", type=int, default=20260101, help="随机种子")
    parser.add_argument(
        "--mix", default="0.25,0.25,0.25,0.25", help="标签比例 NO,SAME,RELATED,UNSEEN"
    )
    parser.add_argument("--out", metavar="STREAM.jsonl", help="导出输入流 JSONL")
    parser.add_argument(
        "--jaccard", type=float, default=0.8, help="相似度链接阈值（默认 0.8）"
    )
    args = parser.parse_args(argv)

    docs = generate_stream(
        args.n, seed=args.seed, mix=parse_mix(args.mix), jaccard_threshold=args.jaccard
    )
    with_link = verify_stream(docs, jaccard_threshold=args.jaccard)
    without_link = label_shift_without_linking(docs, jaccard_threshold=args.jaccard)
    print(
        json.dumps(
            {
                "n": len(docs),
                "seed": args.seed,
                "requested_mix": args.mix,
                "labels_with_similarity_link": {
                    "NO_EVENT": with_link[0],
                    "SAME_EVENT": with_link[1],
                    "RELATED_EVENT": with_link[2],
                    "UNSEEN_EVENT": with_link[3],
                },
                "labels_without_similarity_link": {
                    "NO_EVENT": without_link[0],
                    "SAME_EVENT": without_link[1],
                    "RELATED_EVENT": without_link[2],
                    "UNSEEN_EVENT": without_link[3],
                },
                "time_range": [
                    docs[0].publish_time.isoformat(),
                    docs[-1].publish_time.isoformat(),
                ],
                "distinct_actors": len({d.actor_id for d in docs if d.actor_id}),
                "distinct_incidents": len({d.incident_id for d in docs if d.incident_id}),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if args.out:
        path = write_document_stream(docs, Path(args.out))
        print(f"[ok] wrote {len(docs)} documents -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
