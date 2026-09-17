# 数据集来源与指纹

所有 JSONL 都是**派生数据**：任何一个文件都可以用仓库里的脚本，从原始公开源
重新生成（命令附在每节末尾）。

## 1. 真实流：CIRCL MISP OSINT feed

| 项目 | 值 |
|------|-----|
| 来源 | `https://www.circl.lu/doc/misp/feed-osint/manifest.json` |
| 抓取时间 (UTC) | 2026-09-17 |
| manifest SHA-256 | `124fcce3d9709870b0ab1116d9d49a5ebed4cf635a063ca7acd16e629890c7d6` |
| 事件数 | 1680 |
| 事件日期范围 | 2011-09-22 → 2026-08-13 |
| 发布机构数 | 27（CIRCL 1057 / Krawczyk Industries 286 / CthulhuSPRL.be 218 / …） |
| 带 galaxy 标签的事件 | 655 |
| 许可 | 公开 OSINT feed（每个事件带 `tlp:white` 类标签），仅使用事件级元数据 |

派生文件：

| 文件 | 条数 | SHA-256 |
|------|------|---------|
| `misp_osint_stream.jsonl` | 1680 | `5b5dbe617995ff182768b1e866681af482fd2ad16c332e659caee9419074eed3` |
| `misp_osint_benchmark.jsonl` | 1680 | `fda6a73f1afcbe577e4a45669a7f677e1cd4ec5a38427b31afc4004484417874` |

标签分布：`NO_EVENT 1118 / SAME_EVENT 13 / RELATED_EVENT 214 / UNSEEN_EVENT 335`。

```bash
python3 scripts/fetch_misp_osint.py
python3 cti_streaming_benchmark_builder.py --misp data/raw/misp_manifest.json \
    --out data/misp_osint_benchmark.jsonl --dump-stream data/misp_osint_stream.jsonl --stats
```

> 原始 manifest 不入库（`data/raw/` 已在 `.gitignore` 中），体积约 1.4 MB 且
> feed 每日更新；`misp_osint_stream.jsonl` 就是可用于离线复现的输入快照。

## 2. 受控合成流

| 项目 | 值 |
|------|-----|
| 生成器 | `synthetic_stream.py`（种子 20260101，均衡比例 0.25 × 4） |
| 文档数 | 1000 |
| 模拟时间范围 | 2019-01-01 → 2022-08-01 |
| 涉及其它实体 | 250 个虚构 actor、750 个事件实例 |

| 文件 | 条数 | SHA-256 |
|------|------|---------|
| `synthetic_stream_1000.jsonl` | 1000 | `4e5a70b84eb9edfd89153b9aa24793e50343944cb21c4af3e815061fdc987d03` |
| `synthetic_benchmark_1000.jsonl` | 1000 | `7ef811bba2ab564d7f26e3c0ef33e4ced3acef099633d384e3410ca9fd76b74c` |

标签分布：`250 / 250 / 250 / 250`（与请求比例完全一致，由生成器内部校验）。
关闭相似度链接后同一条流的分布变为 `250 / 0 / 500 / 250` —— 这就是
`SAME_EVENT` 这一类完全依赖平行报道链接的证据。

所有实体名与 CVE 编号均为虚构占位（`CVE-<year>-9xxxxx`），不对应任何真实漏洞。

```bash
python3 synthetic_stream.py --n 1000 --seed 20260101 --out data/synthetic_stream_1000.jsonl
python3 cti_streaming_benchmark_builder.py --input data/synthetic_stream_1000.jsonl \
    --out data/synthetic_benchmark_1000.jsonl --stats
```

## 3. 小样例（回归测试用）

| 文件 | 条数 | 说明 |
|------|------|------|
| `demo_benchmark.jsonl` | 5 | 手工演示流，四类标签各有覆盖 |
| `sample_stix_bundle.json` | 6 report / 11 SDO | 离线 STIX 2.1 样例，含间接归属链路 |
| `sample_benchmark.jsonl` | 6 | 由上述 bundle 生成 |

## 可复现性说明

* 输出对 `PYTHONHASHSEED` 不敏感：同一输入在 `PYTHONHASHSEED=1/2/3/99` 下产生的
  JSONL 字节完全一致（已实测，见 `tests/test_builder.py::test_misp_output_is_hash_seed_independent`）。
* 时间戳统一归一化为 naive UTC，`publish_time` 排序即流式回放顺序。
