# Streaming Cyber-Threat Event Induction — Benchmark Builder

从 STIX 2.1 / MISP 元数据流**自动构建"在线事件实例发现"四分类 Benchmark**。

标注是**流式**的：状态只由 `t <= now` 已经到达的文档更新，因此每篇文档的标签
等价于"它到达时，系统已知世界"下的判定 —— 这正是 In-Context Minimum Description
Length 在线事件归纳要评测的设定。标签不是对全量语料做一次聚类的产物。

## 一键脚本（所有规则性事务都在这里）

```bash
python3 scripts/build_all.py fetch   # 联网抓原始 feed（写 data/raw/，已 gitignore）
python3 scripts/build_all.py build   # 重建全部提交产物
python3 scripts/build_all.py freeze  # 写入 data/FROZEN.sha256 指纹锁（数据已冻结）
python3 scripts/build_all.py check   # 离线重算 + 逐字节比对已提交产物
python3 scripts/build_all.py all     # 上面三步

# 统一在线评测：预热窗只更新记忆，不计入指标
python3 scripts/evaluate.py \
  --stream data/model_input/misp_sliced_input_notitle.jsonl \
  --benchmark data/misp_sliced_benchmark.jsonl \
  --warmup 200 --baseline title_jaccard \
  --metrics macro_f1,b_cubed,ari

python3 -m pytest tests -q           # 60 passed
```

`check` 只依赖仓库里已提交的快照：它会重新标注每一个 `*_stream.jsonl` 并与已提交的
`*_benchmark.jsonl` 逐字节比对，同时验证输出对 `PYTHONHASHSEED` 不敏感。任何口径
改动（阈值、时间窗、锚点策略）都会让 check 失败，从而必须显式重建数据集。

**数据已冻结**：`data/FROZEN.sha256` 记录全部提交产物的指纹，`check` 会校验它。

## 模型输入 vs Ground Truth

不要直接把 `*_benchmark.jsonl` 喂模型 —— 它含 `incident_id` / `actor_id` /
`campaign_id` / `target_incident_id` / `ground_truth_label*`，等于给答案。模型侧用
`data/model_input/*.jsonl`：

```json
{"id": "03f6c81d91e8db71", "publish_time": "2016-02-18T22:03:37",
 "title": "OSINT APT28: A Window into Russia's Cyber Espionage Operations? ...",
 "text": "...\n\nSample hashes: 11 SHA-1, 11 SHA-256 — e.g. sha1 f5b3e98...; ..."}
```

`id` 是不透明哈希（`#s2` 这类切片序号被刻意抹掉，否则直接暗示 `SAME_EVENT`），
回连 `*_benchmark.jsonl` 的 `id` 字段取标签即可。

## 泄露审计（已固化为回归测试）

| 检查项 | 结果 |
|--------|------|
| 正文含 `misp-galaxy:` | 0 / 2082（修复前 826 条，且"不含该串 ⇒ NO_EVENT"准确率 100%） |
| 正文含来源机构名 | 0 / 2082（修复前某些发布方的切片 100% 是 NO_EVENT） |
| 元数据 token 单规则纯度 | 最强 0.66 = 多数类基线，无捷径 |
| 十六进制实体 token 占比 | 中位数 0%、p95 0%（修复前是截断哈希墙，最长 5964 字符） |
| `content` 长度 | 中位数 290 / p95 763 / 最大 1195 字符 |
| 正文含示例值 / 分析师批注 | 91.3% / 32.9% |
| YARA 规则体倾倒 | 0（只保留规则名） |
| 合成流首报 vs 平行报道 | 网络流量侧 vs 终端取证侧的多视角报告；共享事件实体但不使用 first/second report 元陈述 |

残留的类别相关性只有**数据固有一项**：`SAME` 切片正文更短（中位 166 vs `UNSEEN` 411），
因为增量证据本来就少。建议论文里显式披露或做长度归一化对照。

## 标题捷径审计（审稿人一定会问的那个问题）

**事实**：`SAME_EVENT` 的增量切片来自同一个 MISP Event，而 MISP 沿用同一条 headline，
所以同一事件的切片**标题逐字相同**（实测 112 个多切片事件中 111 个 = 99.1%）。

这个事实无法回避，但可以量化 + 消融。跑 `python3 scripts/baselines.py` 得到全部基线
（都跑在真正喂给模型的 `data/model_input/*.jsonl` 上，标签用 `id` 回连）：

| 资产 | 口径 | `title_seen` SAME-F1 | `*_jaccard` SAME-F1 | 最好朴素规则 macro-F1 |
|------|------|----------------------|---------------------|------------------------|
| Real-Wild 1680 | 带标题 | 0.667（仅 3 个正例） | 0.012 | 0.366 |
| Real-Augmented 2082 | 带标题 | 0.540 | 0.263 | 0.318 |
| Real-Augmented-Attributed 712 | 带标题 | **0.990** ← 伪任务风险 | 0.717 | 0.436 |
| Real-Augmented 2082 | **无标题** | — | **0.046** | 0.210 |
| Real-Augmented-Attributed 712 | **无标题** | — | **0.037** | 0.169 |
| Controlled-Synthetic 1000 | 带/无标题 | 0.000 | 受控多视角（不作为真实流捷径结论） | — |

结论与使用协议：

1. **主任务（4-way）没有被捷径解掉**：任何朴素规则（含 `title_seen`）的 macro-F1 上限
   只有 0.318 ~ 0.436，`RELATED` 全部为 0。论文应以 macro-F1（开集、多类）为主指标。
2. **`SAME` 专项结论必须用无标题口径**：`*_input_notitle.jsonl` 抹掉 headline，
   此时文本相似度基线掉到 SAME-F1 0.037–0.046，模型只能靠 CVE/actor/受害目标/指标集合
   等证据判断。带标题口径（0.990）只用于"用了捷径能到多少"的对照。
3. **正文不再重复标题**：切片正文只承载证据（指标与批注），标题单独放在 `title` 字段，
   两个口径因此可以干净地切换。
4. 合成流的 `SAME` 采用网络流量侧与终端取证侧的多视角报告，刻意降低词汇重合；它用于
   受控消歧，不应替代真实流上的开放世界结论。合成报告显式携带事件锚点以保证生成标签可复现，
   因此关闭 similarity-link 不会改变其标签分布。

统一评测入口 `scripts/evaluate.py` 从第一个文档开始更新状态，但通过 `--warmup` 排除冷启动窗的
   指标；除 4-way Macro-F1 外，还输出 B-cubed F1 与 ARI。预测文件每行使用
   `{"id": "...", "label": "...", "target": "..."}`，`target` 指向被合并的较早文档。

这三条已固化为 `tests/test_baselines.py`：既断言"没有规则能刷满 4-way"，也断言
"无标题后捷径确实失效"，同时把 attributed 子集的 0.990 保留为**显式已知属性**，
防止有人在不知情的情况下用它宣称 SAME 召回率。

## 流式评测协议与可解性审计

正式评测从固定的 warm-up 窗口之后开始；例如 200 表示前 200 篇只用于建立状态，不计入分数。统一入口为：

```bash
python scripts/evaluate.py \
  --stream data/model_input/misp_sliced_input_notitle.jsonl \
  --benchmark data/misp_sliced_benchmark.jsonl \
  --warmup 200 --metrics macro_f1,b_cubed,ari
```

除了四分类 Macro-F1，还报告最终事件簇的 B-cubed F1 与 ARI；`NO_EVENT` 文档不进入预测事件簇。
可解性审计由 `scripts/solvability_audit.py` 生成。当前 `Real-Augmented/notitle` 中无锚点比例为：SAME 43.0%、RELATED 16.6%；因此论文不能宣称去标题后所有样本都具备充分语义证据，应将该比例作为真实数据限制公开报告。Controlled-Synthetic 采用网络流量侧与终端取证侧多视角文本，保留 actor/victim 等共享实体用于受控消歧。

## 四个评测资产

| 资产 | 文件 | 文档数 | 时间跨度 | NO / SAME / RELATED / UNSEEN |
|------|------|--------|----------|------------------------------|
| **Real-Wild** | `data/misp_osint_benchmark.jsonl` | 1680 | 2014-10 → 2026-09 | 1118 / 3 / 221 / 338 |
| **Real-Augmented**（增量切片） | `data/misp_sliced_benchmark.jsonl` | 2082 | 2014-10 → 2026-09 | 1370 / **151** / 223 / 338 |
| **Real-Augmented-Attributed** | `data/misp_sliced_attributed_benchmark.jsonl` | 712 | 2014-10 → 2026-08 | 0 / 151 / 223 / 338 |
| **Controlled-Synthetic** | `data/synthetic_benchmark_1000.jsonl` | 1000 | 模拟 2019 → 2020 | 250 / 250 / 250 / 250 |

外加两个回归用小样例：STIX 样例 6 篇、演示流 5 篇。
来源 URL、SHA-256 与重建命令见 [`data/PROVENANCE.md`](data/PROVENANCE.md)。

建议的呈现方式（两者互补，不要试图抹平差异）：

* **Real-Wild** 就是开集压力测试：主看高噪声下的 `NO_EVENT` 拒识率（false alarm）
  与 `UNSEEN` 的发现纯度；它只有 3 条 `SAME`，适合做 case study 而不是召回率结论。
* **Real-Augmented / Synthetic** 用于细粒度消歧的统计显著性：报告 4-way Macro-F1
  与动态混淆矩阵，重点看模型区分 `SAME` vs `RELATED` 的决策边界质量。

## 标签语义

| 值 | 标签 | 含义 | 判定依据（只看向过去） |
|----|------|------|------------------------|
| 0 | `NO_EVENT` | 噪声，无事件级因果锚点 | 非威胁报告，或无 `incident` / `campaign` 锚点 |
| 1 | `SAME_EVENT` | **同一次攻击突破实例**的平行报道 / 增量证据 | 共享 `incident` 锚点（真实 Event ID / 标题指纹），或满足复合约束的平行报道链接 |
| 2 | `RELATED_EVENT` | 同一组织/武器家族在不同时间对不同目标的**独立行动** | `incident` 全新，但 `campaign` 或 `actor` 已出现过 |
| 3 | `UNSEEN_EVENT` | 首次出现的新组织 / 新战役全新事件 | `incident` / `campaign` / `actor` 全部未见过 |

判定顺序是**优先级短路**的：`NO_EVENT` → `SAME_EVENT` → `RELATED_EVENT` → `UNSEEN_EVENT`。

## 策略决定：为什么 Locky 每日波次是 `RELATED` 而不是 `SAME`

MISP 的协作机制天然带有去重与合并：同一事件有新进展时，分析员往**同一个 Event ID**
追加 Attributes/Objects，而不是新建 Event。因此跨 Event ID 的"平行报道"在 MISP 上
极度稀缺，而模板化的连续波次（如 2017 年 Locky 每日垃圾邮件）却很多。

把后者判成 `SAME` 属于概念混淆（受害者群体正交、基础设施与载荷每波轮换，是**同一
家族的不同行动**）。因此平行报道链接采用**复合约束**，三条同时满足才允许：

1. `Jaccard(title) >= 0.7`（默认阈值）
2. `|Δt| <= 14 天`（真实平行报道集中在爆发后 1~2 周内）
3. **共享 CVE 或同一 actor**（弱实体证据）

第 3 条是关键：Locky 波次之间既不共享 CVE 也没有共享 actor 标签，因此被正确挡在
`SAME` 之外，落回 `RELATED`（同 campaign、不同事件实例）。

| 口径 | Real-Wild 的 SAME 数 | 说明 |
|------|----------------------|------|
| 只有标题相似度（旧） | 13 | 主要来自 Locky 模板系列 → 概念污染 |
| 复合约束（当前默认） | 3 | 剩下的是标题完全相同的重发 + 一条真实跨源平行报道 |
| `--no-similarity-link` | 2 | 完全关闭链接的保守基线（只剩共享标题指纹的重发） |

关闭链接后只剩"共享 incident 锚点（标题指纹完全相同）"的那部分；复合约束相对它只多出
**1 条**真实跨源平行报道，说明启发式链接已被压到只保留高置信度案例。

## 真实 `SAME_EVENT` 是怎么补齐的（抓手 A：属性到达切片）

同一 feed 的 1680 个**完整事件**（含 `Attribute`）按属性到达批次切片：

* 把"事件发布时刻 + 所有属性时间戳"排序，间隔 > `--session-gap-hours`（默认 12h）
  切成不同批次；
* 每批属性作为一条文档到达，切片共享真实 `misp-event:<uuid>` 锚点；
* 首片 → `UNSEEN`/`RELATED`，后续片 → **`SAME_EVENT`**。

这样得到 **151 条真实 `SAME_EVENT`**（是 Real-Wild 的 50 倍），而且标签由**真实 MISP
Event ID** 支撑，不依赖任何文本启发式 —— 学术上没有可攻击的语义漏洞。

两个刻意的设计细节：

* **正文不泄露标签**：所有切片统一用中性的 `[attributes] N records: ...` 表述，
  不出现 "slice / arrival / update" 等字样（有回归测试守着）。
* **不可纯靠字符串匹配**：实测有 135 个标题同时对应多种标签 —— 例如另一家机构用
  完全相同的标题发布了**不同** Event ID 的事件时，它不会被误判为 `SAME`（缺少
  共享 actor/CVE 证据），而是 `UNSEEN`。

## 输入映射

### STIX 2.1

| STIX SDO | 映射到 |
|----------|--------|
| `report` | 一篇文档；`published`（缺省 `created`）为发布时间 |
| `incident` | `incident_id`（Same 判定锚点） |
| `campaign` | `campaign_id`（Related 判定锚点） |
| `threat-actor` | `actor_id`（Related 判定锚点） |
| `vulnerability` | `cves`（特征补充） |

锚点从 `object_refs` 出发沿 `relationship` 做可达闭包，因此
`report -> campaign -> threat-actor` 这类间接归属（`attributed-to`）也能解析出来；
`incident` 只作锚点不重复生成文档；`x_no_event: true` 用于显式注入噪声稿。

### MISP

| MISP 字段 / 标签 | 映射到 |
|------------------|--------|
| `uuid` / `timestamp` / `date` | `doc_id` / `publish_time` |
| `info` | `content` + `title`；manifest 流由标题指纹给出 `incident_id`，切片流用真实 Event ID |
| `misp-galaxy:threat-actor=...`、`mitre-*-intrusion-set` 等 | `actor_id` |
| `misp-galaxy:campaign` / `ransomware` / `malpedia` / `rat` 等 | `campaign_id` |
| `misp-galaxy:threat-actor/malware/tool/...` 任一 | `is_threat_report=True` |
| `Attribute[].timestamp` | 切片边界（`--misp-events`） |
| `Attribute[].value` 中的 CVE | `cves`（每个切片单独统计） |

一个事件若同时挂多个归属标签（如既标 `Sofacy` 又标 `STRONTIUM`），锚点取**文档 tag
原序**中最先出现的那个；这是结果可复现的必要条件，见下文缺陷 4。

## 输出

JSON Lines，一篇文档一行：

```json
{"doc_id": "report--...-0002", "publish_time": "2026-01-02T14:00:00",
 "title": "APT29 targeted Ministry of Foreign Affairs", "content": "...",
 "ground_truth_label": 3, "ground_truth_label_name": "UNSEEN_EVENT",
 "target_incident_id": "misp-event:8f0c...", "rationale": "Novel incident with novel attribution (...)"}
```

* `publish_time` 统一归一化为 naive UTC，排序即回放顺序。
* `rationale` 记录判定理由，便于人工抽检标注质量。
* `--dump-stream` 同时导出**输入**文档流（`*_stream.jsonl`），使他人无需重新抓取
  feed 即可复现 Benchmark。注意这些快照含锚点字段，**模型输入只能用
  `publish_time` / `title` / `content`**。

## 相对最初草稿的修正

最初版本能跑通 5 篇演示，但在真实数据流上会出错。以下均已修复并有回归测试：

1. **`None` 污染已知世界**：仅有 `campaign` 锚点（无 `incident`）的文档会把 `None`
   写进 `seen_incidents`，此后每一篇同类**全新**文档都被误判为 `SAME_EVENT`。
   现在只登记非空锚点。
2. **`RELATED` 分支不登记新锚点**：原逻辑只在 UNSEEN 分支更新记忆库，"已知 actor +
   新 campaign"的新 campaign 永远进不了已知世界。现在所有非噪声文档统一登记。
3. **时区混排崩溃**：STIX 的 `Z`、MISP 的 unix 时间戳与手工 naive datetime 混排排序
   会抛 `TypeError`。现在统一归一化为 naive UTC。
4. **不可复现（重跑漂移）**：真实 feed 上有 48 条文档的标签在两次运行间不稳定 ——
   根因是用 `frozenset` 迭代（受字符串哈希随机化影响）决定锚点与相似度候选。
   现在锚点按 tag 原序取、候选按 `(频次, token)` 排序，输出在
   `PYTHONHASHSEED=1/2/3/99` 下字节一致。
5. **切片边界错误**：只保留会话起点会让"属于上一批、时间戳晚于本批起点"的属性
   落进下一批（并丢失该批 CVE）。现在按会话**区间**归批，并把事件发布时刻本身
   作为第一个到达点。

## 已知局限

* 标签是**元数据驱动的弱监督**：锚点质量决定标签质量。跨源未对齐的 incident 需要
  相似度链接才能识别，而链接只覆盖标题高度重合且共享弱实体证据的情况。
* Real-Wild 的 `NO_EVENT` 占 67%：feed 中大量条目是通用科普/工具介绍，只挂
  `attack-pattern`、`country`、`sector` 这类非事件锚点标签。
* 若两家机构用**完全相同**的标题报道同一事件、但既没有共享 actor 也没有 CVE，
  当前策略会判为 `UNSEEN`（保守），而不是 `SAME`；这是刻意的取舍 —— 见"策略决定"。
* 切片流里 `SAME` 依赖"同一 Event ID 的后续属性到达"，因此天然偏向**多轮维护**的
  事件；单轮发布的事件贡献不了 `SAME`。
* 判定只用身份锚点、标题相似度与时间窗，不使用 TTP 相似度；`cves` 目前仅作为特征
  随样本导出，尚未参与聚类。

## 目录结构

```
├── cti_streaming_benchmark_builder.py   # 状态机 + STIX/MISP/切片摄取 + JSONL 导出 + CLI
├── synthetic_stream.py                  # 受控合成流生成器（比例可控 + 自校验）
├── scripts/
│   ├── build_all.py                     # 单一入口: fetch / build / check
│   └── fetch_misp_osint.py              # CIRCL MISP OSINT 抓取（manifest + 完整事件）
├── data/
│   ├── PROVENANCE.md                    # 来源、SHA-256、复现命令
│   ├── misp_osint_{stream,benchmark}.jsonl              # Real-Wild (1680)
│   ├── misp_sliced_{stream,benchmark}.jsonl             # Real-Augmented (2082)
│   ├── misp_sliced_attributed_benchmark.jsonl           # 归属子集 (712)
│   ├── synthetic_{stream_1000,benchmark_1000}.jsonl     # Controlled (1000)
│   ├── sample_stix_bundle.json / sample_benchmark.jsonl # STIX 样例 (6)
│   └── demo_benchmark.jsonl                             # 演示流 (5)
└── tests/
    ├── test_builder.py                  # 状态机语义 + 回归 + STIX + JSONL
    └── test_streams.py                  # MISP 摄取 + 切片 + 链接约束 + 合成流 + 数据契约
```
