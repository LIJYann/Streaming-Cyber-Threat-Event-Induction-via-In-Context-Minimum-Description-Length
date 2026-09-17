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
        swapped = f"{tail.rstrip(')')} {head}".capitalize()
    return swapped


# --------------------------------------------------------------------------- #
# 生成器
# --------------------------------------------------------------------------- #
def generate_stream(
    n: int = 1000,
    seed: int = 20260101,
    mix: Mix = DEFAULT_MIX,
    start: datetime = datetime(2019, 1, 1),
    jaccard_threshold: float = 0.8,
    verify: bool = True,
) -> List[CTIDocument]:
    """生成 n 篇受控文档；`similarity_link=True` 口径下的标签分布 == `mix`。

    可行性约束: `n_same <= n_unseen + n_related`（每篇平行报道都要有首报）。
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
    remaining: Dict[EventLabel, int] = {
        EventLabel.NO_EVENT: n_no,
        EventLabel.SAME_EVENT: n_same,
        EventLabel.RELATED_EVENT: n_related,
        EventLabel.UNSEEN_EVENT: n_unseen,
    }

    documents: List[CTIDocument] = []
    introduced_actors: List[str] = []          # 已出现的 actor（RELATED 可复用）
    campaign_of_actor: Dict[str, str] = {}     # actor -> campaign
    in_flight: List[Dict[str, object]] = []    # 只有一篇报道的事件实例
    first_report_tokens: List[frozenset] = []  # 可区分性约束的参照集
    used_titles: set = set()
    clock = start
    seq = 0

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
            distinguishable = (
                max_jaccard(tokens, first_report_tokens) <= FIRST_REPORT_MAX_JACCARD
            )
            if title not in used_titles and distinguishable:
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

    while len(documents) < n:
        feasible = [
            label
            for label in (
                EventLabel.UNSEEN_EVENT,
                EventLabel.RELATED_EVENT,
                EventLabel.SAME_EVENT,
                EventLabel.NO_EVENT,
            )
            if remaining[label] > 0
            and not (label is EventLabel.SAME_EVENT and not in_flight)
            and not (label is EventLabel.RELATED_EVENT and not introduced_actors)
        ]
        if not feasible:
            raise RuntimeError("generation deadlock: no feasible label left")
        label = rng.choices(feasible, weights=[remaining[l] for l in feasible], k=1)[0]
        remaining[label] -= 1
        clock += timedelta(hours=rng.randint(1, 60))
        doc_id = f"syn-doc-{len(documents) + 1:05d}"

        if label is EventLabel.NO_EVENT:
            title = rng.choice(NOISE_TITLES)
            documents.append(
                CTIDocument(
                    doc_id=doc_id,
                    publish_time=clock,
                    content=f"{title}\n\n{rng.choice(NOISE_BODIES)}",
                    is_threat_report=False,
                    title=title,
                )
            )
            continue

        if label is EventLabel.SAME_EVENT:
            source = in_flight.pop(rng.randrange(len(in_flight)))
            title = _paraphrase(str(source["title"]), rng)
            body = (
                f"A second organisation published its own analysis of the "
                f"{source['victim']} intrusion, corroborating the {source['cve']} entry "
                f"vector and the {source['data_point']} impact figure. "
                f"Independent attribution: {source['actor_id']}."
            )
            documents.append(
                CTIDocument(
                    doc_id=doc_id,
                    publish_time=clock,
                    content=f"{title}\n\n{body}",
                    is_threat_report=True,
                    # 独立来源持有自己的事件 id：只能靠标题相似度关联到首报
                    incident_id=f"syn-report-{len(documents) + 1:05d}",
                    campaign_id=str(source["campaign_id"]),
                    actor_id=str(source["actor_id"]),
                    cves={str(source["cve"])},
                    title=title,
                )
            )
            continue

        if label is EventLabel.UNSEEN_EVENT:
            incident = build_incident(actor=None)
            introduced_actors.append(str(incident["actor_id"]))
        else:
            incident = build_incident(actor=rng.choice(introduced_actors))

        first_report_tokens.append(incident["tokens"])  # type: ignore[arg-type]
        used_titles.add(str(incident["title"]))
        in_flight.append(incident)

        body = (
            f"{str(incident['title']).split(' (')[0]}. First public reporting on this "
            f"intrusion. Analysts linked the activity to the {incident['campaign_id']} "
            f"cluster and flagged {incident['cve']} as the initial access vector. "
            f"Impact: {incident['data_point']} at {incident['victim']}."
        )
        documents.append(
            CTIDocument(
                doc_id=doc_id,
                publish_time=clock,
                content=f"{incident['title']}\n\n{body}",
                is_threat_report=True,
                incident_id=str(incident["incident_id"]),
                campaign_id=str(incident["campaign_id"]),
                actor_id=str(incident["actor_id"]),
                cves={str(incident["cve"])},
                title=str(incident["title"]),
            )
        )

    documents.sort(key=lambda d: (d.publish_time, d.doc_id))

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
