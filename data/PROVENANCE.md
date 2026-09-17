# 数据集来源与指纹

所有 JSONL 都是**派生数据**：任何一个文件都能由仓库脚本从原始公开源重建。
不要手工编辑这些文件 —— 改完 `python3 scripts/build_all.py check` 会失败。

```bash
python3 scripts/build_all.py fetch   # 联网抓原始 feed 到 data/raw/（已 gitignore）
python3 scripts/build_all.py build   # 重建全部提交产物
python3 scripts/build_all.py check   # 离线重算并逐字节比对已提交产物
```

## 1. 真实流 A：CIRCL MISP OSINT feed（事件级元数据）

| 项目 | 值 |
|------|-----|
| 来源 | `https://www.circl.lu/doc/misp/feed-osint/manifest.json` |
| 抓取时间 (UTC) | 2026-09-17 |
| manifest SHA-256 | `124fcce3d9709870b0ab1116d9d49a5ebed4cf635a063ca7acd16e629890c7d6` |
| 事件数 | 1680 |
| 事件日期范围 | 2011-09-22 → 2026-08-13 |
| 发布机构数 | 27（CIRCL 1057 / Krawczyk Industries 286 / CthulhuSPRL.be 218 / …） |
| 带 galaxy 标签的事件 | 655 |
| 许可 | 公开 OSINT feed（事件带 `tlp:white` 类标签），仅使用事件级元数据 |

| 文件 | 条数 | SHA-256 |
|------|------|---------|
| `misp_osint_stream.jsonl`（输入快照） | 1680 | `5b5dbe617995ff182768b1e866681af482fd2ad16c332e659caee9419074eed3` |
| `misp_osint_benchmark.jsonl`（标签） | 1680 | `4c28f3166d723a554bbbc2315b44131e90cbf550dd9a4e373cf964d305f75228` |

标签分布：`NO 1118 / SAME 3 / RELATED 221 / UNSEEN 338`，时间跨度 2014-10 → 2026-09。

## 2. 真实流 B：同一 feed 的**增量切片**（真实 SAME_EVENT 的来源）

抓取 1680 个**完整事件**（含 `Attribute`，约 875 MB，`data/raw/` 不入库），
再按属性的**到达批次**把一个事件切成多条流式文档。切片共享真实
`misp-event:<uuid>` 锚点，因此增量切片判为 `SAME_EVENT` —— 标签由真实 MISP Event ID
支撑，不依赖任何文本启发式。

切分规则（`--session-gap-hours`，默认 12 小时）：把"事件发布时刻 + 所有属性时间戳"
按时间排序，间隔超过阈值的相邻时间点切成不同批次；每批属性作为一条文档到达；
每事件最多 5 片（超出时合并间隔最小的相邻批次）。

| 文件 | 条数 | 说明 |
|------|------|------|
| `misp_sliced_stream.jsonl` | 2082 | 输入快照（1680 事件 → 2082 片） |
| `misp_sliced_benchmark.jsonl` | 2082 | 全部切片标签 |
| `misp_sliced_attributed_benchmark.jsonl` | 712 | 仅带归属锚点的子集（无 NO_EVENT） |

标签分布：

| 数据集 | NO | SAME | RELATED | UNSEEN |
|--------|----|------|---------|--------|
| 全部切片（wild） | 1370 | **151** | 223 | 338 |
| 仅归属子集（augmented） | 0 | **151** | 223 | 338 |

SHA-256：

| 文件 | SHA-256 |
|------|---------|
| `misp_sliced_stream.jsonl` | `ef654542c29f5a45d3e8ac3748e33852009a0fd9d899c600ec8b0cf0ea27b7bd` |
| `misp_sliced_benchmark.jsonl` | `8d9e3bdfba261fd9e74eaf5f07c9f6a1ae0784e1dddb8a0b2f6aa5fe1bad7e8c` |
| `misp_sliced_attributed_benchmark.jsonl` | `8a7c8f1ef0bf6703d8ef7721edbde6f9546d1d4fb5f55b0ca3a4855e5bc94621` |

> 原始完整事件不入库（875 MB 且 feed 每日更新）；提交的 `*_stream.jsonl` 快照已包含
> 重建标签所需的全部字段。

## 3. 受控合成流

| 项目 | 值 |
|------|-----|
| 生成器 | `synthetic_stream.py`（种子 20260101，比例 0.25 × 4） |
| 文档数 | 1000 |
| 模拟时间范围 | 2019-01-01 → 2020-10-09 |
| 实体 | 250 个虚构 actor、750 个事件实例 |

| 文件 | 条数 | SHA-256 |
|------|------|---------|
| `synthetic_stream_1000.jsonl` | 1000 | `a23ab6f18ea2613d8a2624234a1d029e5990e4a9cee06bb1e8539d00e42411b5` |
| `synthetic_benchmark_1000.jsonl` | 1000 | `fda6442d1391ab1a4f6c8b7306607e6751b76f96c79cc8befe281ac5c707a844` |

标签分布：`250 / 250 / 250 / 250`（与请求比例完全一致，生成器内部校验）。
关闭相似度链接后同一条流变为 `250 / 0 / 500 / 250` —— `SAME_EVENT` 完全依赖平行报道
链接。平行报道与其首报的间隔被约束在 10 天以内（落在状态机的 14 天时间窗内）。

实体名与 CVE 编号均为虚构占位（`CVE-<year>-9xxxxx`），不对应任何真实漏洞。

## 4. 小样例（回归测试用）

| 文件 | 条数 | SHA-256 | 说明 |
|------|------|---------|------|
| `demo_benchmark.jsonl` | 5 | `a722ddfdbd9cd63ad89b11b150b3fa838052de6f5c7c298aa5139898bda04ac7` | 手工演示流，四类齐全 |
| `sample_stix_bundle.json` | — | `129e6eaa92341d6405b3fed3a87ab8421a8e2e7b4965d4fecf6c72122f602075` | 离线 STIX 2.1 样例 |
| `sample_benchmark.jsonl` | 6 | `5f3278c10932e0510ce4a64a9242a1458e7f4a06f540d11fadee46b9f117d5fa` | 由上述 bundle 生成 |

## 可复现性

* `scripts/build_all.py check` 离线重算每一个已提交的 `*_benchmark.jsonl` 并逐字节比对；
  同时验证输出对 `PYTHONHASHSEED` 不敏感（回归：曾因 `frozenset` 迭代顺序漂移 48 条标签）。
* 时间戳统一归一化为 naive UTC，`publish_time` 排序即流式回放顺序。
* **模型输入约定**：`*_stream.jsonl` 是 ground-truth 侧的复现快照，含
  `incident_id` / `actor_id` / `campaign_id` 等锚点字段；喂给模型时只能使用
  `publish_time`、`title`、`content`，否则等于泄漏标签。
