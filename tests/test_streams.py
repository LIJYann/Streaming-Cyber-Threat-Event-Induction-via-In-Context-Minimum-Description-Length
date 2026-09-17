"""Tests for the MISP ingest path, similarity linking and the synthetic generator."""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cti_streaming_benchmark_builder import (  # noqa: E402
    CTIDocument,
    CTIStreamingBenchmarkGenerator,
    EventLabel,
    incident_fingerprint,
    load_documents,
    load_misp_event_slices,
    load_misp_events,
    read_jsonl,
    tokenize,
    write_document_stream,
)
from synthetic_stream import (  # noqa: E402
    FIRST_REPORT_MAX_JACCARD,
    generate_stream,
    label_shift_without_linking,
    mix_to_counts,
    parse_mix,
    verify_stream,
)

MISP_MANIFEST_FIXTURE = {
    "aaaaaaaa-0000-4000-8000-000000000001": {
        "info": "APT 29 targets diplomatic missions in the Balkans",
        "date": "2019-01-02",
        "timestamp": 1546387200,
        "analysis": 2,
        "threat_level_id": 2,
        "Orgc": {"name": "CIRCL"},
        "Tag": [
            {"name": "type:OSINT"},
            {"name": "misp-galaxy:threat-actor=\"APT 29\""},
            {"name": "misp-galaxy:tool=\"Mimikatz\""},
        ],
    },
    "aaaaaaaa-0000-4000-8000-000000000002": {
        "info": "Guide to hardening exchange servers",
        "date": "2019-01-03",
        "timestamp": 1546473600,
        "Orgc": {"name": "CIRCL"},
        "Tag": [{"name": "tlp:white"}, {"name": "misp-galaxy:country=\"Belgium\""}],
    },
    "aaaaaaaa-0000-4000-8000-000000000003": {
        "info": "Overlapping attribution for the same intrusion",
        "date": "2019-01-04",
        "timestamp": 1546560000,
        "Orgc": {"name": "CIRCL"},
        "Tag": [
            {"name": "misp-galaxy:threat-actor=\"Sofacy\""},
            {"name": "misp-galaxy:threat-actor=\"STRONTIUM\""},
            {"name": "misp-galaxy:ransomware=\"Locky\""},
        ],
    },
}


# --------------------------------------------------------------------------- #
# MISP 摄取
# --------------------------------------------------------------------------- #
def test_misp_manifest_tags_become_anchors():
    docs = {d.doc_id: d for d in load_misp_events(MISP_MANIFEST_FIXTURE)}
    first = docs["aaaaaaaa-0000-4000-8000-000000000001"]
    assert first.actor_id == "APT 29"
    assert first.is_threat_report is True
    assert first.incident_id == incident_fingerprint(
        "APT 29 targets diplomatic missions in the Balkans"
    )
    assert first.publish_time == datetime(2019, 1, 2, 0, 0)  # unix ts -> UTC naive


def test_misp_event_without_anchors_is_noise():
    docs = {d.doc_id: d for d in load_misp_events(MISP_MANIFEST_FIXTURE)}
    guide = docs["aaaaaaaa-0000-4000-8000-000000000002"]
    assert guide.is_threat_report is False
    assert guide.actor_id is None and guide.campaign_id is None

    generator = CTIStreamingBenchmarkGenerator()
    assert generator.determine_ground_truth(guide).ground_truth_label is EventLabel.NO_EVENT


def test_misp_multiple_actor_tags_resolve_in_tag_order():
    """同一事件挂多个 actor 标签时，锚点必须取 tag 原序的第一个（可复现）。"""
    docs = {d.doc_id: d for d in load_misp_events(MISP_MANIFEST_FIXTURE)}
    overlapping = docs["aaaaaaaa-0000-4000-8000-000000000003"]
    assert overlapping.actor_id == "Sofacy"
    assert overlapping.campaign_id == "Locky"


def test_misp_accepts_full_event_wrapper():
    payload = [{"Event": dict(MISP_MANIFEST_FIXTURE["aaaaaaaa-0000-4000-8000-000000000001"])}]
    payload[0]["Event"]["uuid"] = "bbbbbbbb-0000-4000-8000-000000000001"
    docs = load_misp_events(payload)
    assert len(docs) == 1
    assert docs[0].doc_id == "bbbbbbbb-0000-4000-8000-000000000001"


def test_misp_loader_rejects_stix_bundle():
    with pytest.raises(ValueError):
        load_misp_events({"type": "bundle", "objects": []})


def test_misp_stream_round_trips_through_jsonl(tmp_path):
    docs = load_misp_events(MISP_MANIFEST_FIXTURE)
    path = write_document_stream(docs, tmp_path / "stream.jsonl")
    reloaded = load_documents(path)

    def labels(stream, link):
        generator = CTIStreamingBenchmarkGenerator(similarity_link=link)
        return [s.ground_truth_label.name for s in generator.process_stream(stream)]

    assert labels(docs, True) == labels(reloaded, True)
    assert labels(docs, False) == labels(reloaded, False)


# --------------------------------------------------------------------------- #
# 平行报道相似度链接
# --------------------------------------------------------------------------- #
def _full_misp_event(uuid: str = "cccccccc-0000-4000-8000-000000000001", **overrides) -> dict:
    """一个多轮维护的真实形态 MISP 事件：属性分三批到达。"""
    event = {
        "uuid": uuid,
        "info": "APT 29 targets diplomatic missions in the Balkans",
        "date": "2019-01-02",
        "publish_timestamp": 1546387200,           # 2019-01-02T00:00:00Z
        "timestamp": 1546820000,                   # 最后一次修改
        "Orgc": {"name": "CIRCL"},
        "Tag": [
            {"name": "misp-galaxy:threat-actor=\"APT 29\""},
            {"name": "misp-galaxy:ransomware=\"Locky\""},
        ],
        "Attribute": [
            {"type": "sha256", "value": "a" * 64, "timestamp": 1546387200},
            {"type": "domain", "value": "evil.example", "timestamp": 1546387300},
            # 第二天补充的 IOC（新的到达批次）
            {"type": "domain", "value": "c2.example", "timestamp": 1546480000},
            {"type": "vulnerability", "value": "CVE-2019-1234", "timestamp": 1546480100},
            # 第三批（数天后）
            {"type": "ip-dst", "value": "203.0.113.9", "timestamp": 1546820000},
        ],
    }
    event.update(overrides)
    return event


def test_attribute_slicing_yields_real_same_events():
    """抓手 A：同一个 MISP Event ID 的增量切片必须判为 SAME_EVENT。"""
    docs = load_misp_event_slices([_full_misp_event()], session_gap_hours=12)
    assert [d.doc_id for d in docs] == [
        "cccccccc-0000-4000-8000-000000000001#s1",
        "cccccccc-0000-4000-8000-000000000001#s2",
        "cccccccc-0000-4000-8000-000000000001#s3",
    ]
    # 三个切片共享真实 MISP Event ID 作为锚点
    assert {d.incident_id for d in docs} == {
        "misp-event:cccccccc-0000-4000-8000-000000000001"
    }
    samples = CTIStreamingBenchmarkGenerator().process_stream(docs)
    assert [s.ground_truth_label.name for s in samples] == [
        "UNSEEN_EVENT",
        "SAME_EVENT",
        "SAME_EVENT",
    ]
    assert samples[1].target_incident_id == "misp-event:cccccccc-0000-4000-8000-000000000001"


def test_attribute_slices_do_not_leak_the_label_in_text():
    """正文不能出现 slice/update 之类的字样，否则标签被文本直接泄露。"""
    docs = load_misp_event_slices([_full_misp_event()])
    for doc in docs:
        lowered = doc.content.lower()
        for leak in ("slice", "arrival", "update to", "increment", "#s"):
            assert leak not in lowered
    # 但增量切片必须只带新增属性（这是模型真正要用的证据）
    assert "c2.example" in docs[1].content
    assert "evil.example" not in docs[1].content


def test_slicing_keeps_per_slice_cves():
    docs = load_misp_event_slices([_full_misp_event()])
    assert docs[0].cves == set()
    assert "CVE-2019-1234" in docs[1].cves


def test_slicing_of_unattributed_event_is_noise():
    event = _full_misp_event(uuid="dddddddd-0000-4000-8000-000000000002",
                             Tag=[{"name": "tlp:white"}])
    docs = load_misp_event_slices([event])
    assert docs and all(not d.is_threat_report for d in docs)
    samples = CTIStreamingBenchmarkGenerator().process_stream(docs)
    assert all(s.ground_truth_label is EventLabel.NO_EVENT for s in samples)


def test_slicing_respects_max_slices():
    docs = load_misp_event_slices([_full_misp_event()], max_slices=2)
    assert len(docs) == 2


def test_slicing_accepts_directory(tmp_path):
    (tmp_path / "event.json").write_text(json.dumps(_full_misp_event()), encoding="utf-8")
    docs = load_misp_event_slices(tmp_path)
    assert len(docs) == 3


def _stub_doc(doc_id, when, title, actor, cves=(), incident="anchor-new"):
    return CTIDocument(
        doc_id,
        when,
        title,
        True,
        incident_id=incident,
        campaign_id=None,
        actor_id=actor,
        cves=set(cves),
        title=title,
    )


def test_link_requires_shared_actor_or_cve():
    """复合约束第 3 条: 只有标题相似、没有共享 actor/CVE 时不得判为 SAME。"""
    title = "ALPHA TIDE ransomware operation disrupted Fairhaven Credit Union in Italy"
    first = _stub_doc("a", datetime(2026, 1, 2), title, actor="ALPHA TIDE", incident="x1")
    other_actor = _stub_doc(
        "b", datetime(2026, 1, 3), title, actor="BETA WOLF", incident="x2"
    )
    samples = CTIStreamingBenchmarkGenerator().process_stream([first, other_actor])
    assert samples[1].ground_truth_label is EventLabel.UNSEEN_EVENT

    shared_cve = _stub_doc(
        "c",
        datetime(2026, 1, 3),
        title,
        actor="BETA WOLF",
        cves=["CVE-2026-900001"],
        incident="x3",
    )
    first_with_cve = _stub_doc(
        "d",
        datetime(2026, 1, 2),
        title,
        actor="ALPHA TIDE",
        cves=["CVE-2026-900001"],
        incident="x4",
    )
    samples = CTIStreamingBenchmarkGenerator().process_stream([first_with_cve, shared_cve])
    assert samples[1].ground_truth_label is EventLabel.SAME_EVENT


def test_link_respects_time_window():
    """复合约束第 2 条: 跨过时间窗的相似标题不算同一事件（真实平行报道集中在两周内）。"""
    title = "ALPHA TIDE ransomware operation disrupted Fairhaven Credit Union in Italy"
    near = _stub_doc("a", datetime(2026, 1, 2), title, actor="ALPHA TIDE", incident="x1")
    soon = _stub_doc("b", datetime(2026, 1, 10), title, actor="ALPHA TIDE", incident="x2")
    late = _stub_doc("c", datetime(2026, 6, 10), title, actor="ALPHA TIDE", incident="x3")

    samples = CTIStreamingBenchmarkGenerator().process_stream([near, soon, late])
    assert [s.ground_truth_label.name for s in samples] == [
        "UNSEEN_EVENT",
        "SAME_EVENT",
        "RELATED_EVENT",
    ]


def test_template_series_stays_related_not_same():
    """完全复刻 Locky 波次: 模板化标题 + 同 ransomware 家族 + 无共享 actor/CVE。"""
    def wave(day: int) -> CTIDocument:
        title = f'M2M - Locky 2017-09-{day:02d} offline ".ykcol" "Invoice IP1234567"'
        return CTIDocument(
            f"locky-{day}",
            datetime(2017, 9, day),
            title,
            True,
            incident_id=incident_fingerprint(title),
            campaign_id="Locky",
            actor_id=None,
            title=title,
        )

    samples = CTIStreamingBenchmarkGenerator().process_stream([wave(20), wave(25), wave(29)])
    assert [s.ground_truth_label.name for s in samples] == [
        "UNSEEN_EVENT",
        "RELATED_EVENT",
        "RELATED_EVENT",
    ]


def _parallel_pair() -> list:
    first = CTIDocument(
        "first",
        datetime(2026, 1, 2),
        "ALPHA TIDE ransomware operation disrupted Fairhaven Credit Union in Italy "
        "encrypting 1.2 million patient records (CVE-2026-900001)",
        True,
        incident_id="vendor-a-report",
        campaign_id="OPERATION NIGHT LANTERN",
        actor_id="ALPHA TIDE",
        title="ALPHA TIDE ransomware operation disrupted Fairhaven Credit Union in Italy "
        "encrypting 1.2 million patient records (CVE-2026-900001)",
    )
    second = CTIDocument(
        "second",
        datetime(2026, 1, 4),
        "second vendor analysis",
        True,
        incident_id="vendor-b-report",  # 独立来源，不共享事件 id
        campaign_id="OPERATION NIGHT LANTERN",
        actor_id="ALPHA TIDE",
        title="ALPHA TIDE ransomware operation strikes Fairhaven Credit Union in Italy "
        "encrypting 1.2 million patient records (CVE-2026-900001)",
    )
    return [first, second]


def test_similarity_link_marks_parallel_report():
    samples = CTIStreamingBenchmarkGenerator(similarity_link=True).process_stream(
        _parallel_pair()
    )
    assert [s.ground_truth_label.name for s in samples] == ["UNSEEN_EVENT", "SAME_EVENT"]
    assert samples[1].target_incident_id == "vendor-a-report"
    assert "Jaccard" in samples[1].rationale


def test_without_similarity_link_parallel_report_is_not_same():
    """消融：关掉链接后，独立来源的平行报道不会被判成 SAME_EVENT。"""
    samples = CTIStreamingBenchmarkGenerator(similarity_link=False).process_stream(
        _parallel_pair()
    )
    assert [s.ground_truth_label.name for s in samples] == [
        "UNSEEN_EVENT",
        "RELATED_EVENT",
    ]


def test_similarity_link_is_causal():
    """谁先到达谁定义事件：把平行报道放在首报之前，它必须是首个实例。"""
    first, second = _parallel_pair()
    second.publish_time = datetime(2026, 1, 1)
    samples = CTIStreamingBenchmarkGenerator(similarity_link=True).process_stream(
        [first, second]
    )
    assert [s.doc_id for s in samples] == ["second", "first"]
    assert samples[0].ground_truth_label is EventLabel.UNSEEN_EVENT
    assert samples[1].ground_truth_label is EventLabel.SAME_EVENT


def test_unrelated_titles_are_not_linked():
    docs = _parallel_pair()
    docs[1].title = (
        "BETA WOLF credential theft campaign hit Kingsway Transit Commission in Peru "
        "harvesting 70 thousand mailbox archives (CVE-2026-900777)"
    )
    samples = CTIStreamingBenchmarkGenerator(similarity_link=True).process_stream(docs)
    assert samples[1].ground_truth_label is not EventLabel.SAME_EVENT


def test_similarity_threshold_is_configurable():
    docs = _parallel_pair()
    samples = CTIStreamingBenchmarkGenerator(
        similarity_link=True, jaccard_threshold=0.99
    ).process_stream(docs)
    assert samples[1].ground_truth_label is not EventLabel.SAME_EVENT


def test_default_threshold_is_seven_tenths():
    assert CTIStreamingBenchmarkGenerator().jaccard_threshold == 0.7
    assert CTIStreamingBenchmarkGenerator().link_time_window_days == 14.0


# --------------------------------------------------------------------------- #
# 合成流
# --------------------------------------------------------------------------- #
def test_mix_helpers():
    assert parse_mix("0.25,0.25,0.25,0.25") == (0.25, 0.25, 0.25, 0.25)
    assert mix_to_counts(1000, (0.25, 0.25, 0.25, 0.25)) == (250, 250, 250, 250)
    assert sum(mix_to_counts(101, (0.1, 0.2, 0.3, 0.4))) == 101
    with pytest.raises(ValueError):
        parse_mix("0.5,0.5")
    with pytest.raises(ValueError):
        parse_mix("-1,1,1,1")


def test_synthetic_realises_requested_mix():
    docs = generate_stream(200, seed=7, mix=(0.25, 0.25, 0.25, 0.25))
    assert verify_stream(docs) == [50, 50, 50, 50]


def test_synthetic_is_deterministic():
    a = generate_stream(120, seed=11, mix=(0.2, 0.3, 0.3, 0.2))
    b = generate_stream(120, seed=11, mix=(0.2, 0.3, 0.3, 0.2))
    c = generate_stream(120, seed=12, mix=(0.2, 0.3, 0.3, 0.2))
    assert [d.doc_id for d in a] == [d.doc_id for d in b]
    assert [d.title for d in a] == [d.title for d in b]
    assert [d.title for d in a] != [d.title for d in c]
    assert verify_stream(a) == verify_stream(b) == [24, 36, 36, 24]


def test_synthetic_separates_distinct_events_from_parallel_reports():
    docs = generate_stream(150, seed=3)
    first_reports = [d for d in docs if d.title and "First public reporting" in d.content]
    tokens = [tokenize(d.title) for d in first_reports]
    for i, left in enumerate(tokens):
        for right in tokens[i + 1 :]:
            union = len(left | right)
            assert len(left & right) / union <= FIRST_REPORT_MAX_JACCARD

    # 每一篇被判为 SAME 的平行报道，与它实际链接到的首报之间必须高于阈值
    samples = CTIStreamingBenchmarkGenerator(similarity_link=True).process_stream(docs)
    same_samples = [s for s in samples if s.ground_truth_label is EventLabel.SAME_EVENT]
    assert len(same_samples) == verify_stream(docs)[1] > 0
    by_anchor = {d.incident_id: d for d in first_reports}
    for sample in same_samples:
        target = by_anchor[sample.target_incident_id]
        left, right = tokenize(sample.title), tokenize(target.title)
        jaccard = len(left & right) / len(left | right)
        assert jaccard >= 0.8


def test_synthetic_infeasible_mix_raises():
    with pytest.raises(ValueError):
        generate_stream(100, seed=1, mix=(0.0, 0.9, 0.05, 0.05))


def test_synthetic_round_trip_keeps_labels(tmp_path):
    docs = generate_stream(80, seed=5)
    path = write_document_stream(docs, tmp_path / "stream.jsonl")
    reloaded = load_documents(path)
    assert verify_stream(reloaded) == verify_stream(docs)


def test_without_linking_same_class_collapses_into_related():
    docs = generate_stream(120, seed=9)
    assert verify_stream(docs)[1] == 30
    assert label_shift_without_linking(docs)[1] == 0


# --------------------------------------------------------------------------- #
# 数据契约 / 可复现性
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name,expected_total,expected",
    [
        ("demo_benchmark.jsonl", 5, {"NO_EVENT": 1, "SAME_EVENT": 1, "RELATED_EVENT": 1, "UNSEEN_EVENT": 2}),
        ("sample_benchmark.jsonl", 6, {"NO_EVENT": 1, "SAME_EVENT": 1, "RELATED_EVENT": 2, "UNSEEN_EVENT": 2}),
            ("misp_osint_benchmark.jsonl", 1680, {"NO_EVENT": 1118, "SAME_EVENT": 3, "RELATED_EVENT": 221, "UNSEEN_EVENT": 338}),
            ("misp_sliced_benchmark.jsonl", 2082, {"NO_EVENT": 1370, "SAME_EVENT": 151, "RELATED_EVENT": 223, "UNSEEN_EVENT": 338}),
            ("misp_sliced_attributed_benchmark.jsonl", 712, {"SAME_EVENT": 151, "RELATED_EVENT": 223, "UNSEEN_EVENT": 338}),
        ("synthetic_benchmark_1000.jsonl", 1000, {"NO_EVENT": 250, "SAME_EVENT": 250, "RELATED_EVENT": 250, "UNSEEN_EVENT": 250}),
    ],
)
def test_committed_benchmarks_match_documented_counts(name, expected_total, expected):
    rows = read_jsonl(ROOT / "data" / name)
    assert len(rows) == expected_total
    counts = {}
    for row in rows:
        counts[row["ground_truth_label_name"]] = counts.get(row["ground_truth_label_name"], 0) + 1
        assert 0 <= row["ground_truth_label"] <= 3
    assert counts == expected


def test_committed_benchmarks_are_time_ordered():
    for name in ("misp_osint_benchmark.jsonl", "synthetic_benchmark_1000.jsonl"):
        rows = read_jsonl(ROOT / "data" / name)
        stamps = [r["publish_time"] for r in rows]
        assert stamps == sorted(stamps)


def test_misp_output_is_hash_seed_independent(tmp_path):
    """回归: 输出不得随 PYTHONHASHSEED 变化（曾因 set 迭代顺序漂移 48 条标签）。"""
    stream = ROOT / "data" / "misp_osint_stream.jsonl"
    if not stream.exists():
        pytest.skip("committed MISP stream snapshot missing")

    digests = []
    for seed in ("1", "2"):
        out = tmp_path / f"out_{seed}.jsonl"
        env = {**os.environ, "PYTHONHASHSEED": seed}
        subprocess.run(
            [
                sys.executable,
                "cti_streaming_benchmark_builder.py",
                "--input",
                str(stream),
                "--out",
                str(out),
                "--quiet",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            env=env,
        )
        digests.append(out.read_bytes())
    assert digests[0] == digests[1]


def test_dumped_misp_stream_reproduces_committed_labels(tmp_path):
    """提交的输入快照 + 默认设置，必须重新生成出提交的 benchmark。"""
    stream = ROOT / "data" / "misp_osint_stream.jsonl"
    if not stream.exists():
        pytest.skip("committed MISP stream snapshot missing")
    regenerated = CTIStreamingBenchmarkGenerator(similarity_link=True).process_stream(
        load_documents(stream)
    )
    committed = read_jsonl(ROOT / "data" / "misp_osint_benchmark.jsonl")
    assert [s.to_dict() for s in regenerated] == committed
