"""Unit tests for the streaming 4-way CTI ground-truth builder."""

import json
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
    demo_stream,
    load_stix_bundle,
    read_jsonl,
    summarize,
    write_jsonl,
)

STIX_BUNDLE = ROOT / "data" / "sample_stix_bundle.json"


def labels(samples):
    return [s.ground_truth_label.name for s in samples]


# --------------------------------------------------------------------------- #
# 状态机语义
# --------------------------------------------------------------------------- #
def test_demo_stream_labels():
    generator = CTIStreamingBenchmarkGenerator()
    samples = generator.process_stream(demo_stream())
    assert labels(samples) == [
        "NO_EVENT",
        "UNSEEN_EVENT",
        "SAME_EVENT",
        "RELATED_EVENT",
        "UNSEEN_EVENT",
    ]


def test_demo_stream_covers_all_four_labels():
    generator = CTIStreamingBenchmarkGenerator()
    stats = summarize(generator.process_stream(demo_stream()))
    assert stats["all_four_labels_present"] is True
    assert stats["missing_labels"] == []


def test_output_is_time_ordered_even_for_shuffled_input():
    docs = list(reversed(demo_stream()))
    generator = CTIStreamingBenchmarkGenerator()
    samples = generator.process_stream(docs)
    assert [s.publish_time for s in samples] == sorted(s.publish_time for s in samples)
    # 流式语义: 先到达的事件建立已知世界, 后到达的平行报道才是 SAME_EVENT
    assert labels(samples)[2] == "SAME_EVENT"


def test_same_event_requires_prior_arrival():
    """平行报道若先于首报到达, 它就是首个实例 (UNSEEN), 而不是 SAME。"""
    first = CTIDocument("later_id", datetime(2026, 1, 3), "c", True,
                        incident_id="inc", campaign_id="camp", actor_id="act")
    second = CTIDocument("earlier_id", datetime(2026, 1, 2), "c", True,
                         incident_id="inc", campaign_id="camp", actor_id="act")
    samples = CTIStreamingBenchmarkGenerator().process_stream([first, second])
    assert labels(samples) == ["UNSEEN_EVENT", "SAME_EVENT"]


def test_noise_document_is_gated():
    doc = CTIDocument("n1", datetime(2026, 1, 1), "tips", False,
                      incident_id="inc", campaign_id="camp")
    sample = CTIStreamingBenchmarkGenerator().determine_ground_truth(doc)
    assert sample.ground_truth_label is EventLabel.NO_EVENT
    assert sample.target_incident_id is None


# --------------------------------------------------------------------------- #
# 回归: 原脚本的两处缺陷
# --------------------------------------------------------------------------- #
def test_campaign_only_document_does_not_pollute_seen_incidents():
    """仅有 campaign 锚点的文档不应把 None 写进 seen_incidents。"""
    generator = CTIStreamingBenchmarkGenerator()
    doc = CTIDocument("a", datetime(2026, 1, 1), "x", True, campaign_id="c1")
    sample = generator.determine_ground_truth(doc)
    assert sample.ground_truth_label is EventLabel.UNSEEN_EVENT
    assert None not in generator.seen_incidents
    assert generator.seen_campaigns == {"c1"}

    # 该 campaign 下的新 incident 必须判为 RELATED，而不是被 None 假阳性带偏
    follow_up = CTIDocument("b", datetime(2026, 1, 2), "y", True,
                            incident_id="i2", campaign_id="c1")
    assert generator.determine_ground_truth(follow_up).ground_truth_label is (
        EventLabel.RELATED_EVENT
    )


def test_actor_only_report_is_not_silently_dropped():
    """已知 actor 下的新事件即使是首次无 campaign, 也应进入 RELATED 分支。"""
    generator = CTIStreamingBenchmarkGenerator()
    generator.seen_actors.add("APT99")
    doc = CTIDocument("a", datetime(2026, 1, 1), "x", True,
                      incident_id="i1", actor_id="APT99")
    assert generator.determine_ground_truth(doc).ground_truth_label is (
        EventLabel.RELATED_EVENT
    )


def test_related_event_registers_new_campaign():
    """RELATED 文档携带的新 campaign 也必须进入已知世界。"""
    generator = CTIStreamingBenchmarkGenerator()
    generator.seen_actors.add("APT29")
    doc = CTIDocument("a", datetime(2026, 1, 1), "x", True,
                      incident_id="i1", campaign_id="new_camp", actor_id="APT29")
    generator.determine_ground_truth(doc)
    assert "new_camp" in generator.seen_campaigns


def test_mixed_aware_and_naive_timestamps_do_not_crash():
    # +08:00 的 2026-01-02T08:00 等价于 UTC 2026-01-02T00:00
    aware = CTIDocument("a", datetime.fromisoformat("2026-01-02T08:00:00+08:00"), "x",
                        True, incident_id="i1", campaign_id="c1")
    naive = CTIDocument("b", datetime(2026, 1, 1), "y", True,
                        incident_id="i2", campaign_id="c1")
    samples = CTIStreamingBenchmarkGenerator().process_stream([aware, naive])
    assert [s.doc_id for s in samples] == ["b", "a"]
    assert samples[1].publish_time == "2026-01-02T00:00:00"


# --------------------------------------------------------------------------- #
# STIX 2.1 输入
# --------------------------------------------------------------------------- #
def test_stix_bundle_maps_to_expected_labels():
    generator = CTIStreamingBenchmarkGenerator()
    samples = generator.process_stream(load_stix_bundle(STIX_BUNDLE))
    assert labels(samples) == [
        "NO_EVENT",       # password best practices (x_no_event)
        "UNSEEN_EVENT",   # APT29 Ministry of Foreign Affairs
        "SAME_EVENT",     # second vendor, same incident
        "RELATED_EVENT",  # new incident under campaign_nobelium_2026
        "UNSEEN_EVENT",   # LockBit hospital
        "RELATED_EVENT",  # second LockBit wave
    ]


def test_stix_bundle_resolves_indirect_actor_attribution():
    """report -> campaign -> threat-actor 的间接归属需要被闭包解析出来。"""
    docs = {d.doc_id: d for d in load_stix_bundle(STIX_BUNDLE)}
    power_grid = next(d for d in docs.values() if "power grid" in d.content)
    assert power_grid.campaign_id == "campaign--00000000-0000-4000-8000-000000000201"
    assert power_grid.actor_id == "threat-actor--00000000-0000-4000-8000-000000000101"
    assert power_grid.cves == {"CVE-2025-9999"}


def test_stix_bundle_stats_reach_full_coverage():
    generator = CTIStreamingBenchmarkGenerator()
    stats = summarize(generator.process_stream(load_stix_bundle(STIX_BUNDLE)))
    assert stats["n_samples"] == 6
    assert stats["all_four_labels_present"] is True
    assert stats["label_distribution"]["RELATED_EVENT"] == 2


def test_load_stix_bundle_rejects_non_bundle():
    with pytest.raises(ValueError):
        load_stix_bundle({"not": "a bundle"})


# --------------------------------------------------------------------------- #
# JSONL 导出
# --------------------------------------------------------------------------- #
def test_jsonl_round_trip(tmp_path):
    generator = CTIStreamingBenchmarkGenerator()
    samples = generator.process_stream(demo_stream())
    out = write_jsonl(samples, tmp_path / "bench" / "demo.jsonl")
    assert out.exists()

    rows = read_jsonl(out)
    assert len(rows) == len(samples)
    assert [r["ground_truth_label"] for r in rows] == [0, 3, 1, 2, 3]
    assert rows[0]["ground_truth_label_name"] == "NO_EVENT"
    # 时间戳必须是绝对 ISO-8601，保证流式回放顺序可复现
    assert rows == sorted(rows, key=lambda r: r["publish_time"])
    for row in rows:
        json.loads(json.dumps(row))
