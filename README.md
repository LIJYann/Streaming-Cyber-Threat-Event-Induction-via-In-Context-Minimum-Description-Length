# Streaming Cyber-Threat Event Induction — Benchmark Builder

从 STIX 2.1 / MISP 元数据流**自动构建"在线事件实例发现"四分类 Benchmark**。

与静态语料的一次性聚类不同，标注是**流式**的：状态只由 `t <= now` 已经到达的文档
更新，因此每篇文档的标签等价于"它到达时，系统已知世界"下的判定 —— 这正是
In-Context Minimum Description Length 在线事件归纳要评测的设定。

## 快速开始

纯标准库实现，Python >= 3.8，无需安装依赖（测试需要 `pytest`）。

```bash
# 1. 内置演示流（5 篇文档，覆盖全部 4 类标签）
python3 cti_streaming_benchmark_builder.py --demo

# 2. 从 STIX 2.1 Bundle 构建并导出 JSONL
python3 cti_streaming_benchmark_builder.py \
    --stix data/sample_stix_bundle.json \
    --out data/sample_benchmark.jsonl \
    --stats

# 3. 从自有文档流（JSON / JSONL）构建
python3 cti_streaming_benchmark_builder.py --input my_documents.json --out out.jsonl --stats

# 4. 测试
python3 -m pytest tests -q
```

## 标签语义

| 值 | 标签 | 含义 | 判定依据（只看向过去） |
|----|------|------|------------------------|
| 0 | `NO_EVENT` | 噪声，无事件级因果锚点 | 非威胁报告，或无 `incident` / `campaign` 锚点 |
| 1 | `SAME_EVENT` | 已知事件的平行报道 / 增量更新 | 该 `incident_id` 已在本流中出现过 |
| 2 | `RELATED_EVENT` | 同一组织 / 战役下相关但独立的事件 | `incident` 全新，但 `campaign` 或 `actor` 已出现过 |
| 3 | `UNSEEN_EVENT` | 首次出现的新组织 / 新战役全新事件 | `incident` / `campaign` / `actor` 全部未见过 |

判定顺序是**优先级短路**的：`NO_EVENT` → `SAME_EVENT` → `RELATED_EVENT` → `UNSEEN_EVENT`。

## 输入：STIX 2.1 映射规则

| STIX SDO | 映射到 |
|----------|--------|
| `report` | 一篇文档；`published`（缺省 `created`）为发布时间 |
| `incident` | `incident_id`（Same 判定锚点） |
| `campaign` | `campaign_id`（Related 判定锚点） |
| `threat-actor` | `actor_id`（Related 判定锚点） |
| `vulnerability` | `cves`（特征补充） |

关键实现细节：

* **归属闭包遍历**：文档锚点从 `object_refs` 出发沿 `relationship` 对象做可达闭包，
  所以 `report -> campaign -> threat-actor` 这类间接归属（`attributed-to`）也能解析出来。
  `data/sample_stix_bundle.json` 中的 report 只引用 campaign，actor 仍被正确还原。
* **只把 `report` 变成文档**：`incident` 是事件实例本身，只作为锚点，不重复生成文档。
* **`x_no_event: true` 扩展**：把通用安全科普稿显式注入为 `NO_EVENT` 噪声。
* **未挂 incident 的 report**：以自身 STIX id 作为事件实例锚点（未被 incident 串联的
  报告本身就是独立事件实例）。

## 输出

JSON Lines，一篇文档一行，可直接作为流式回放评测集：

```json
{"doc_id": "report--...-0002", "publish_time": "2026-01-02T14:00:00",
 "content": "APT29 targeted Ministry of Foreign Affairs\n\n...",
 "ground_truth_label": 3, "ground_truth_label_name": "UNSEEN_EVENT",
 "target_incident_id": "incident--...-0301", "rationale": "Novel incident with novel attribution (...)"}
```

`publish_time` 一律归一化为 naive UTC（跨源时区混排不会崩，且保证回放顺序可复现）；
`rationale` 记录判定理由，便于人工抽检标注质量。

已提交的样例产物：

* `data/demo_benchmark.jsonl` — 演示流输出（5 条：1 / 1 / 1 / 2）
* `data/sample_benchmark.jsonl` — STIX Bundle 输出（6 条：1 / 1 / 2 / 2）

## 相对最初草稿的修正

原始脚本能跑通演示，但有三处会在真实数据上出错的问题，已修复并加了回归测试：

1. **`None` 污染已知世界**：仅有 `campaign` 锚点（无 `incident`）的文档会走到
   UNSEEN 分支并把 `None` 写进 `seen_incidents`，此后 `None in seen_incidents`
   恒为真 —— 后续每一篇"无 incident 但有 campaign"的**全新**文档都会被误判为
   `SAME_EVENT`（且 `target_incident_id` 为 `None`）。现在只登记非空锚点。
2. **`RELATED` 分支不登记新锚点**：原逻辑只在 UNSEEN 分支更新记忆库，于是"已知
   actor + 新 campaign"这类文档的新 campaign 永远不会进入已知世界。现在统一登记。
3. **时区混排崩溃**：STIX 的 `Z`、MISP 的时间戳与手工构造的 naive datetime 混在
   一起排序会抛 `TypeError`。现在统一归一化为 naive UTC。

此外补上了显式的括号（`not A or (B and C)` 的优先级靠 `and` 绑定，容易读错）、
同时间戳的次级排序键（结果可复现）、`--out/--stats` 导出与标签覆盖自检。

## 接入真实开源数据

1. **STIX 摄取**：AlienVault OTX、MISP、CISA Advisories 都能导出 STIX 2.1 Bundle，
   直接 `--stix` 喂进来即可（不需要 `stix2` 库）。
2. **噪声自动丰富**：把无 CVE、无具体 IOC 的通用安全新闻（KrebsOnSecurity、
   BleepingComputer）或仅描述无实战利用的 NIST 漏洞条目标为 `x_no_event: true`。
3. **MISP 直连**：MISP 的 Event / Galaxy（`threat-actor`、`campaign`）层级天然对应本
   脚本的 incident / campaign / actor 锚点，`load_documents()` 可作为适配入口。

## 已知局限

* 标签是**元数据驱动**的弱监督：锚点质量决定标签质量，跨源 `incident` 未对齐时会
  把同一事件判成 `UNSEEN_EVENT` 而非 `SAME_EVENT`。
* 判定只看身份锚点，不使用 CVE / TTP 相似度；`cves` 目前仅作为特征随样本导出。
* `NO_EVENT` 与 `RELATED_EVENT` 的边界依赖 `campaign` / `actor` 的粒度一致性。

## 目录结构

```
├── cti_streaming_benchmark_builder.py   # 状态机 + STIX/JSON 摄取 + JSONL 导出 + CLI
├── data/
│   ├── sample_stix_bundle.json          # 可运行的 STIX 2.1 样例（含间接归属）
│   ├── sample_benchmark.jsonl           # 由样例 Bundle 生成
│   └── demo_benchmark.jsonl             # 由内置演示流生成
└── tests/test_builder.py                # 14 个用例：状态机语义 + 三处回归 + STIX + 导出
```
