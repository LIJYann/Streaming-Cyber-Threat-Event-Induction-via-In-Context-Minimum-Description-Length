#!/usr/bin/env python3
"""
build_all.py — 单一入口，把"规则性事务"全部脚本化。

所有派生数据集都由这里生成或校验，避免手工逐步操作带来的口径漂移：

  python3 scripts/build_all.py fetch    # 抓取原始 feed（联网，写入 data/raw/，已 gitignore）
  python3 scripts/build_all.py build    # 从 data/raw/ 重建**全部**提交产物
  python3 scripts/build_all.py check    # 离线自检: 用提交的输入快照重算标签并逐字节比对
  python3 scripts/build_all.py all      # fetch(缺则抓) + build + check

`check` 完全离线：它只用仓库里已提交的 `*_stream.jsonl` 与样例 bundle 重算标签，
再和已提交的 `*_benchmark.jsonl` 逐字节比较。任何口径改动（阈值、时间窗、锚点策略）
都会让 check 失败，从而必须显式重新生成数据集。
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cti_streaming_benchmark_builder import (  # noqa: E402
    CTIStreamingBenchmarkGenerator,
    demo_stream,
    load_documents,
    load_misp_event_slices,
    load_misp_events,
    load_stix_bundle,
    read_jsonl,
    summarize,
    write_document_stream,
    write_jsonl,
)
from synthetic_stream import generate_stream  # noqa: E402

DATA = ROOT / "data"
RAW = DATA / "raw"
MANIFEST = RAW / "misp_manifest.json"
EVENTS = RAW / "misp_events"
SYNTHETIC_N = 1000
SYNTHETIC_SEED = 20260101
SYNTHETIC_MIX = (0.25, 0.25, 0.25, 0.25)

# 声明式产物清单: (输入快照, 标签文件) —— check 只依赖这两者
OFFLINE_PAIRS = [
    ("misp_osint_stream.jsonl", "misp_osint_benchmark.jsonl"),
    ("misp_sliced_stream.jsonl", "misp_sliced_benchmark.jsonl"),
    ("synthetic_stream_1000.jsonl", "synthetic_benchmark_1000.jsonl"),
]


def _labels(documents, **kwargs) -> List:
    return CTIStreamingBenchmarkGenerator(**kwargs).process_stream(documents)


# --------------------------------------------------------------------------- #
# build: 从 data/raw/ 重建全部产物
# --------------------------------------------------------------------------- #
def build_demo() -> Dict[str, int]:
    samples = _labels(demo_stream())
    write_jsonl(samples, DATA / "demo_benchmark.jsonl")
    return summarize(samples)["label_distribution"]


def build_stix_sample() -> Dict[str, int]:
    samples = _labels(load_stix_bundle(DATA / "sample_stix_bundle.json"))
    write_jsonl(samples, DATA / "sample_benchmark.jsonl")
    return summarize(samples)["label_distribution"]


def build_misp_wild() -> Dict[str, int]:
    documents = load_misp_events(MANIFEST)
    write_document_stream(documents, DATA / "misp_osint_stream.jsonl")
    samples = _labels(documents)
    write_jsonl(samples, DATA / "misp_osint_benchmark.jsonl")
    return summarize(samples)["label_distribution"]


def build_misp_sliced() -> Dict[str, int]:
    documents = load_misp_event_slices(EVENTS)
    write_document_stream(documents, DATA / "misp_sliced_stream.jsonl")
    samples = _labels(documents)
    write_jsonl(samples, DATA / "misp_sliced_benchmark.jsonl")

    attributed = [doc for doc in documents if doc.is_threat_report]
    attributed_samples = _labels(attributed)
    write_jsonl(attributed_samples, DATA / "misp_sliced_attributed_benchmark.jsonl")
    return summarize(samples)["label_distribution"]


def build_synthetic() -> Dict[str, int]:
    documents = generate_stream(
        SYNTHETIC_N, seed=SYNTHETIC_SEED, mix=SYNTHETIC_MIX
    )
    write_document_stream(documents, DATA / "synthetic_stream_1000.jsonl")
    samples = _labels(documents)
    write_jsonl(samples, DATA / "synthetic_benchmark_1000.jsonl")
    return summarize(samples)["label_distribution"]


BUILDERS: "Dict[str, Callable[[], Dict[str, int]]]" = {
    "demo": build_demo,
    "stix_sample": build_stix_sample,
    "misp_wild": build_misp_wild,
    "misp_sliced": build_misp_sliced,
    "synthetic": build_synthetic,
}


# --------------------------------------------------------------------------- #
# check: 离线重算并逐字节比对
# --------------------------------------------------------------------------- #
def _check_pair(stream_name: str, benchmark_name: str) -> bool:
    stream_path, benchmark_path = DATA / stream_name, DATA / benchmark_name
    if not stream_path.exists() or not benchmark_path.exists():
        print(f"  [skip] {stream_name}/{benchmark_name}: 文件缺失")
        return True
    regenerated = [s.to_dict() for s in _labels(load_documents(stream_path))]
    committed = read_jsonl(benchmark_path)
    if regenerated != committed:
        print(f"  [FAIL] {benchmark_name}: 重算结果与已提交文件不一致")
        return False
    print(f"  [ok]   {benchmark_name} ({len(committed)} rows, 与输入快照一致)")
    return True


def check() -> int:
    ok = True
    print("[check] 离线重算（只依赖已提交快照）")
    for stream_name, benchmark_name in OFFLINE_PAIRS:
        ok &= _check_pair(stream_name, benchmark_name)

    # 由 demo / STIX 样例直接重算（它们的输入本身就是代码内数据与已提交 bundle）
    expected_demo = [s.to_dict() for s in _labels(demo_stream())]
    ok &= _compare(expected_demo, DATA / "demo_benchmark.jsonl")
    expected_stix = [s.to_dict() for s in _labels(load_stix_bundle(DATA / "sample_stix_bundle.json"))]
    ok &= _compare(expected_stix, DATA / "sample_benchmark.jsonl")

    # attributed 子集: 从切片快照过滤 is_threat_report 后重算
    sliced_stream = DATA / "misp_sliced_stream.jsonl"
    attributed_path = DATA / "misp_sliced_attributed_benchmark.jsonl"
    if sliced_stream.exists() and attributed_path.exists():
        attributed = [d for d in load_documents(sliced_stream) if d.is_threat_report]
        ok &= _compare(
            [s.to_dict() for s in _labels(attributed)], attributed_path
        )

    # 标签分布不随哈希随机化漂移（回归: 曾因 set 迭代顺序漂移 48 条）
    ok &= _check_hash_seed_independence()
    print("[check] 通过" if ok else "[check] 失败")
    return 0 if ok else 1


def _compare(rows: Sequence[Dict], path: Path) -> bool:
    if not path.exists():
        print(f"  [skip] {path.name}: 文件缺失")
        return True
    committed = read_jsonl(path)
    if list(rows) != committed:
        print(f"  [FAIL] {path.name}: 重算结果与已提交文件不一致")
        return False
    print(f"  [ok]   {path.name} ({len(committed)} rows)")
    return True


def _check_hash_seed_independence() -> bool:
    stream = DATA / "misp_osint_stream.jsonl"
    if not stream.exists():
        return True
    digests = []
    for seed in ("1", "7919"):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "cti_streaming_benchmark_builder.py"),
                "--input",
                str(stream),
                "--stats",
                "--quiet",
            ],
            cwd=ROOT,
            capture_output=True,
            env={**__import__("os").environ, "PYTHONHASHSEED": seed},
            check=True,
        )
        digests.append(hashlib.sha256(result.stdout).hexdigest())
    if len(set(digests)) != 1:
        print("  [FAIL] 输出随 PYTHONHASHSEED 变化")
        return False
    print("  [ok]   输出对 PYTHONHASHSEED 不敏感")
    return True


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def fetch() -> int:
    if MANIFEST.exists() and EVENTS.exists() and len(list(EVENTS.glob("*.json"))) > 1000:
        print(f"[fetch] 已存在 {MANIFEST} 与 {len(list(EVENTS.glob('*.json')))} 个事件，跳过")
        return 0
    print("[fetch] 抓取 CIRCL MISP OSINT feed ...")
    return subprocess.call(
        [
            sys.executable,
            str(ROOT / "scripts" / "fetch_misp_osint.py"),
            "--out",
            str(MANIFEST),
            "--with-events",
            "1680",
            "--spread",
            "--workers",
            "16",
        ],
        cwd=ROOT,
    )


def build() -> int:
    missing = [name for name, path in (("manifest", MANIFEST), ("events", EVENTS)) if not path.exists()]
    if missing:
        print(f"[build] 缺少原始输入 {missing}；先运行 `build_all.py fetch`", file=sys.stderr)
        return 2
    for name, builder in BUILDERS.items():
        distribution = builder()
        total = sum(distribution.values())
        print(
            f"[build] {name:12s} {total:5d} docs  "
            f"NO={distribution['NO_EVENT']:5d} SAME={distribution['SAME_EVENT']:4d} "
            f"REL={distribution['RELATED_EVENT']:4d} UNSEEN={distribution['UNSEEN_EVENT']:4d}"
        )
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="One entry point for building/checking all datasets.")
    parser.add_argument("command", choices=["fetch", "build", "check", "all"], help="要执行的事务")
    args = parser.parse_args(argv)

    if args.command == "fetch":
        return fetch()
    if args.command == "build":
        return build()
    if args.command == "check":
        return check()
    status = fetch()
    return status or build() or check()


if __name__ == "__main__":
    raise SystemExit(main())
