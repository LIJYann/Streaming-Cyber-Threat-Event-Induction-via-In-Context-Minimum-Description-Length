#!/usr/bin/env python3
"""
fetch_misp_osint.py

抓取 CIRCL 公开 MISP OSINT feed 的 manifest（事件元数据流）并记录来源指纹，
用于离线重建真实 Benchmark。无需 API key。

feed 说明:
  * feed 目录: https://www.circl.lu/doc/misp/feed-osint/
  * manifest : manifest.json（`{uuid: {info, date, timestamp, Tag, ...}}`）
  * 单个事件 : <uuid>.json（完整 Event，含 Attribute/Galaxy，约 100-400 KB/个）

本脚本默认只抓 manifest：它已经包含 tags（含 `misp-galaxy:threat-actor="..."`），
足以构建 actor/campaign 锚点，且体积小（约 1.4 MB / 1680 事件）。
加 `--with-events N` 可额外抽样下载 N 个完整事件（含 IOC/CVE），用于特征扩展。

用法:
  python3 scripts/fetch_misp_osint.py                      # -> data/raw/misp_manifest.json
  python3 scripts/fetch_misp_osint.py --with-events 20      # 额外抽样 20 个完整事件
  python3 cti_streaming_benchmark_builder.py --misp data/raw/misp_manifest.json \
      --similarity-link --out data/misp_osint_benchmark.jsonl --stats
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FEED_BASE = "https://www.circl.lu/doc/misp/feed-osint/"
MANIFEST_URL = FEED_BASE + "manifest.json"
DEFAULT_OUT = Path("data/raw/misp_manifest.json")


def fetch(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "cti-benchmark-builder/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fetch the CIRCL MISP OSINT manifest.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="manifest 输出路径")
    parser.add_argument("--with-events", type=int, default=0, help="额外下载的完整事件数")
    parser.add_argument("--timeout", type=int, default=60, help="单次请求超时（秒）")
    args = parser.parse_args(argv)

    try:
        raw = fetch(MANIFEST_URL, args.timeout)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[error] could not fetch {MANIFEST_URL}: {exc}", file=sys.stderr)
        print(
            "[hint] 该 feed 只读公开，若网络受限可手动下载 manifest.json 后直接使用 "
            "--misp 指向本地文件。",
            file=sys.stderr,
        )
        return 2

    manifest = json.loads(raw.decode("utf-8"))
    if not isinstance(manifest, dict) or not manifest:
        print("[error] unexpected manifest payload", file=sys.stderr)
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    dates = sorted(v.get("date", "") for v in manifest.values() if v.get("date"))
    provenance = {
        "source_url": MANIFEST_URL,
        "fetched_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": digest,
        "n_events": len(manifest),
        "date_range": [dates[0], dates[-1]] if dates else None,
        "with_full_events": args.with_events,
        "local_path": str(args.out),
    }
    print(json.dumps(provenance, ensure_ascii=False, indent=2))

    if args.with_events:
        sample_dir = args.out.parent / "misp_events"
        sample_dir.mkdir(parents=True, exist_ok=True)
        uuids = sorted(manifest)[: args.with_events]
        for index, uuid in enumerate(uuids, start=1):
            target = sample_dir / f"{uuid}.json"
            if target.exists():
                continue
            try:
                target.write_bytes(fetch(f"{FEED_BASE}{uuid}.json", args.timeout))
            except (urllib.error.URLError, TimeoutError) as exc:
                print(f"[warn] {uuid}: {exc}", file=sys.stderr)
            if index % 10 == 0:
                print(f"  fetched {index}/{len(uuids)} full events", file=sys.stderr)
        print(f"[ok] full event samples -> {sample_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
