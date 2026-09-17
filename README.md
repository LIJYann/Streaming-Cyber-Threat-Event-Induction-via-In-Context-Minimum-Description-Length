# Streaming Cyber-Threat Event Induction — Benchmark Builder

从 STIX 2.1 / MISP 元数据流**自动构建"在线事件实例发现"四分类 Benchmark**。

标注是**流式**的：状态只由 `t <= now` 已经到达的文档更新，因此每篇文档的标签
等价于"它到达时，系统已知世界"下的判定 —— 这正是 In-Context Minimum Description
Length 在线事件归纳要评测的设定。标签不是对全量语料做一次聚类的产物。

## 数据集规模

| 数据集 | 文档数 | 时间跨度 | 标签分布 (NO / SAME / REL / UNSEEN) | 用途 |
|--------|--------|----------|--------------------------------------|------|
| **真实流** `data/misp_osint_benchmark.jsonl` | **1680** | 2014-10 → 2026-09 | 1118 / 13 / 214 / 335 | CIRCL 公开 MISP OSINT feed，真实元数据与倾斜分布 |
| **受控合成流** `data/synthetic_benchmark_1000.jsonl` | **1000** | 模拟 2019 → 2022 | 250 / 250 / 250 / 250 | 严格均衡，用于消融与类别层面指标 |
| STIX 样例 `data/sample_benchmark.jsonl` | 6 | 2026-01 | 1 / 1 / 2 / 2 | 离线回归测试，含间接归属链路 |
| 演示流 `data/demo_benchmark.jsonl` | 5 | 2026-01 | 1 / 1 / 1 / 2 | 状态机 smoke test |

数据来源、SHA-256 指纹与复现命令见 [`data/PROVENANCE.md`](data/PROVENANCE.md)。

## 快速开始

纯标准库实现，Python >= 3.8，无需安装依赖（跑测试需要 `pytest`）。

```bash
# 真实流：抓取 CIRCL MISP OSINT manifest 并构建 Benchmark（无需 API key）
python3 scripts/fetch_misp_osint.py
python3 cti_streaming_benchmark_builder.py --misp data/raw/misp_manifest.json \
    --out data/misp_osint_benchmark.jsonl --dump-stream data/misp_osint_stream.jsonl --stats

# 或者直接用仓库里已生成的离线快照重建（不需要重新抓取）
python3 cti_streaming_benchmark_builder.py --input data/misp_osint_stream.jsonl \
    --out /tmp/misp_rebuilt.jsonl --stats

# 受控合成流：规模与标签比例都可指定，结果可复现
python3 synthetic_stream.py --n 1000 --seed 20260101 --mix 0.25,0.25,0.25,0.25 \
    --out data/synthetic_stream_1000.jsonl
python3 cti_streaming_benchmark_builder.py --input data/synthetic_stream_1000.jsonl \
    --out data/synthetic_benchmark_1000.jsonl --stats

# 离线 STIX 2.1 bundle
python3 cti_streaming_benchmark_builder.py --stix data/sample_stix_bundle.json \
    --out data/sample_benchmark.jsonl --stats

# 消融：关闭平行报道链接
python3 cti_streaming_benchmark_builder.py --input data/misp_osint_stream.jsonl \
    --no-similarity-link --stats --quiet

# 测试
python3 -m pytest tests -q      # 39 passed
```

## 标签语义

| 值 | 标签 | 含义 | 判定依据（只看向过去） |
|----|------|------|------------------------|
| 0 | `NO_EVENT` | 噪声，无事件级因果锚点 | 非威胁报告，或无 `incident` / `campaign` 锚点 |
| 1 | `SAME_EVENT` | 已知事件的平行报道 / 增量更新 | 共享 `incident` 锚点，或标题 token Jaccard ≥ 0.8 的平行报道 |
| 2 | `RELATED_EVENT` | 同一组织 / 战役下相关但独立的事件 | `incident` 全新，但 `campaign` 或 `actor` 已出现过 |
| 3 | `UNSEEN_EVENT` | 首次出现的新组织 / 新战役全新事件 | `incident` / `campaign` / `actor` 全部未见过 |

判定顺序是**优先级短路**的：`NO_EVENT` → `SAME_EVENT` → `RELATED_EVENT` → `UNSEEN_EVENT`。

### 平行报道链接（`similarity_link`）

真实 feed 里"同一事件被多家机构分别报道"往往**不共享任何 id**，只靠元数据锚点会
把这类文档判成 `UNSEEN_EVENT`。开启后额外做一次因果的标题相似度检索：新文档标题与
**已到达**文档标题的 token Jaccard ≥ 阈值（默认 0.8）即判为 `SAME_EVENT`，目标锚点
指向先到达的那篇。

该选项**默认开启**，`--no-similarity-link` 可关闭用于消融。在合成流上的效果非常直接：

| 口径 | NO / SAME / RELATED / UNSEEN |
|------|------------------------------|
| 开启链接 | 250 / 250 / 250 / 250 |
| 关闭链接 | 250 / **0** / 500 / 250 |

即合成流里的 `SAME_EVENT` 类**完全**来自平行报道链接。

## 输入映射

### STIX 2.1

| STIX SDO | 映射到 |
|----------|--------|
| `report` | 一篇文档；`published`（缺省 `created`）为发布时间 |
| `incident` | `incident_id`（Same 判定锚点） |
| `campaign` | `campaign_id`（Related 判定锚点） |
| `threat-actor` | `actor_id`（Related 判定锚点） |
| `vulnerability` | `cves`（特征补充） |

* **归属闭包遍历**：锚点从 `object_refs` 出发沿 `relationship` 做可达闭包，
  `report -> campaign -> threat-actor` 这类间接归属（`attributed-to`）也能解析出来。
* **只把 `report` 变成文档**：`incident` 是事件实例本身，只作锚点。
* **`x_no_event: true`** 扩展用于显式注入 `NO_EVENT` 噪声稿。
* **未挂 incident 的 report** 以自身 STIX id 作为事件实例锚点。

### MISP（CIRCL OSINT feed）

| MISP 字段 / 标签 | 映射到 |
|------------------|--------|
| `uuid` / `timestamp` / `date` | `doc_id` / `publish_time` |
| `info` | `content` + `title`，并由标题指纹给出 `incident_id` |
| `misp-galaxy:threat-actor=...`、`mitre-*-intrusion-set` 等 | `actor_id` |
| `misp-galaxy:campaign` / `ransomware` / `malpedia` / `rat` 等 | `campaign_id` |
| `misp-galaxy:threat-actor/malware/tool/...` 任一 | `is_threat_report=True` |
| `CVE-....` 标签 | `cves`（本 feed 为空，保留通用性） |

两类锚点集合定义在 `MISP_ACTOR_GALAXIES` / `MISP_CAMPAIGN_GALAXIES`，可按需扩展。
一个事件若同时挂多个归属标签（如既标 `Sofacy` 又标 `STRONTIUM`），锚点取**文档 tag
原序**中最先出现的那个 —— 这一点对结果可复现是必需的，见下文缺陷 4。

## 输出

JSON Lines，一篇文档一行，可直接作为流式回放评测集：

```json
{"doc_id": "report--...-0002", "publish_time": "2026-01-02T14:00:00",
 "title": "APT29 targeted Ministry of Foreign Affairs",
 "content": "...", "ground_truth_label": 3, "ground_truth_label_name": "UNSEEN_EVENT",
 "target_incident_id": "incident--...-0301", "rationale": "Novel incident with novel attribution (...)"}
```

* `publish_time` 统一归一化为 naive UTC，排序即回放顺序。
* `rationale` 记录判定理由，便于人工抽检标注质量。
* `--dump-stream` 可同时导出**输入**文档流（含锚点与标题），使他人无需重新抓取原始
  feed 即可复现同一条 Benchmark；`data/*_stream.jsonl` 就是这类快照。

## 相对最初草稿的修正

最初版本能跑通 5 篇演示，但在真实数据流上会出错。以下问题均已修复并加了回归测试：

1. **`None` 污染已知世界**：仅有 `campaign` 锚点（无 `incident`）的文档会走到 UNSEEN
   分支并把 `None` 写进 `seen_incidents`，此后 `None in seen_incidents` 恒为真 ——
   后续每一篇"无 incident 但有 campaign"的**全新**文档都被误判为 `SAME_EVENT`
   （且 `target_incident_id` 为 `None`）。现在只登记非空锚点。
2. **`RELATED` 分支不登记新锚点**：原逻辑只在 UNSEEN 分支更新记忆库，于是"已知
   actor + 新 campaign"这类文档的新 campaign 永远进不了已知世界。现在所有非噪声
   文档统一登记。
3. **时区混排崩溃**：STIX 的 `Z`、MISP 的 unix 时间戳与手工构造的 naive datetime
   混排排序会抛 `TypeError`。现在统一归一化为 naive UTC。
4. **不可复现（重跑结果漂移）**：真实 feed 上有 48 条文档的标签在两次运行间不稳定。
   根因是用 `frozenset` 迭代（受字符串哈希随机化影响）决定锚点与相似度候选：
   多归属标签事件的 actor 会随机取到 `Sofacy` 或 `STRONTIUM`，相似度检索的候选
   集合顺序也会漂移。现在锚点按 tag 原序取、候选按 `(频次, token)` 排序，
   输出在 `PYTHONHASHSEED=1/2/3/99` 下字节一致。

另外补上了显式括号（`not A or (B and C)` 的优先级靠 `and` 绑定，容易读错）、
同时间戳的次级排序键、`--out/--dump-stream/--stats` 与标签覆盖自检。

## 已知局限

* 标签是**元数据驱动的弱监督**：锚点质量决定标签质量；跨源 `incident` 未对齐时，
  同一事件会被判成 `UNSEEN_EVENT`（这正是相似度链接要补的场景，但它只覆盖
  标题高度重合的情况）。
* 真实 OSINT feed 的 `SAME_EVENT` 天然稀疏（1680 篇里 13 篇）。这不是实现缺陷而是
  数据属性：该 feed 的事件标题彼此区分度较高。需要均衡类别时请用合成流。
* 该 feed 中被链接上的 `SAME_EVENT` 主要来自同模板的连续系列报道（例如 2017 年
  Locky 每日垃圾邮件波次 `M2M - Locky 2017-10-02/04/05 ...`）。把它们当作"同一
  事件的增量报道"还是"同一行动下的独立事件"是一个**标注策略**选择；若你倾向后者，
  提高 `--jaccard` 或改用 `--no-similarity-link` 即可得到更保守的口径。
* `NO_EVENT` 占比在真实流上约 67%，因为 feed 中大量条目是通用科普/工具介绍，
  只挂着 `attack-pattern`、`country`、`sector` 这类"非事件锚点"标签。
* `RELATED_EVENT` 的边界依赖 `campaign` / `actor` 的粒度一致性；把恶意软件家族
  galaxy 当作战役聚类是本文档的显式策略，不是标准。
* 判定目前只用身份锚点与标题相似度，不使用 CVE / TTP 相似度；`cves` 仅随样本导出。

## 目录结构

```
├── cti_streaming_benchmark_builder.py   # 状态机 + STIX/MISP/JSON 摄取 + JSONL 导出 + CLI
├── synthetic_stream.py                  # 受控合成流生成器（比例可控 + 自校验）
├── scripts/fetch_misp_osint.py          # CIRCL MISP OSINT manifest 抓取（含指纹记录）
├── data/
│   ├── PROVENANCE.md                    # 来源、SHA-256、复现命令
│   ├── misp_osint_stream.jsonl          # 真实流输入快照（1680）
│   ├── misp_osint_benchmark.jsonl       # 真实流标签（1680）
│   ├── synthetic_stream_1000.jsonl      # 合成流输入（1000）
│   ├── synthetic_benchmark_1000.jsonl   # 合成流标签（1000）
│   ├── sample_stix_bundle.json          # 离线 STIX 2.1 样例（含间接归属）
│   ├── sample_benchmark.jsonl           # 由样例 bundle 生成（6）
│   └── demo_benchmark.jsonl             # 内置演示流（5）
└── tests/
    ├── test_builder.py                  # 状态机语义 + 回归 + STIX + JSONL
    └── test_streams.py                  # MISP 摄取 + 相似度链接 + 合成流 + 数据契约
```
