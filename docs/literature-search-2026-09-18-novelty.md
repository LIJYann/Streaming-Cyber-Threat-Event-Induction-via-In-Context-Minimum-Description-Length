# ICLR 2027 novelty search: streaming CTI event induction with in-context MDL

检索日期：2026-09-18（UTC）；检索入口：AnySearch（academic/general search）与公开出版商、ACL Anthology、arXiv、NeurIPS 页面。主题词组合包括 `streaming cyber threat intelligence event detection`、`online event induction`、`cross-document event coreference`、`prompt-based event coreference`、`language modeling compression/MDL`、`CTI benchmark`。本报告只记录可公开核验的来源；“未检索到”不等价于“绝对不存在”。

## 结论先行

在本轮检索到的公开文献中，没有发现同时具备以下四项的先行工作：

1. 以**到达顺序/只看过去状态**为约束的 CTI 文档流；
2. 对每个新文档做 `NO_EVENT / SAME_EVENT / RELATED_EVENT / UNSEEN_EVENT` 级别的在线事件实例归纳；
3. 用语言模型的条件描述长度或 in-context MDL 作为事件归属/新颖性判据；
4. 在 STIX/MISP 来源上提供可复现、含真实增量到达切片和开集噪声的 benchmark。

因此，项目的**组合型 novelty 可信度为中高（约 0.78，条件式）**：benchmark/任务定义的独特性较强，MDL 作为决策信号的理论来源已有先例，prompt ECR 和 streaming coreference 也各自有先例。若论文把贡献表述成“首次提出 MDL”“首次提出在线 coreference”或“首次 CTI event extraction”，则不成立；应准确表述为“将压缩视角用于 CTI 在线事件实例归纳，并发布流式开集 benchmark”。

## 可信来源与与项目的关系

| 来源 | 已覆盖内容 | 与本项目的距离/缺口 |
|---|---|---|
| Delétang et al., **Language Modeling Is Compression**, ICLR 2024. [arXiv](https://arxiv.org/abs/2309.10668) · [ICLR](https://proceedings.iclr.cc/paper_files/paper/2024/file/3cbf627fa24fb6cb576e04e689b9428b-Paper-Conference.pdf) | 证明预测与无损压缩的等价关系，讨论 in-context compression、log-loss 与代码长度。 | 理论/一般模型研究；不做事件聚类、CTI 或在线标签。项目可借其定义 MDL 评分，但应用和任务不同。 |
| Chevalier et al., **Adapting Language Models to Compress Contexts (AutoCompressors)**, EMNLP 2023. [ACL](https://aclanthology.org/2023.emnlp-main.232/) | 将长上下文压缩为可作为 soft prompt 的摘要向量。 | 压缩上下文表示，不是“比较候选事件假设的代码长度”，也没有 CTI stream 或事件标签。 |
| Rao, McNamee & Dredze, **Streaming Cross Document Entity Coreference Resolution**, COLING 2010. [ACL](https://aclanthology.org/C10-2121/) | 明确研究高容量文本流中的 streaming cross-document coreference；使用流式聚类思想。 | 目标是实体而非事件；无 LM/MDL、CTI、安全事件和四分类开集协议。它是“在线状态更新”最近的通用先例。 |
| Bugert, Reimers & Gurevych, **Generalizing Cross-Document Event Coreference Resolution Across Multiple Corpora**, Computational Linguistics 2021. [ACL](https://aclanthology.org/2021.cl-3.18/) · DOI `10.1162/coli_a_00407` | 定义 CDCR 并在 ECB+、Gun Violence、Football 三个语料上评估跨语料泛化；指出事件动作和时间的重要性及 corpus overfit。 | 离线、静态语料和已知语料标签；没有只看过去的 stream、CTI、NO/ SAME/RELATED/UNSEEN 或 MDL。说明项目应做跨 feed/跨时间泛化，而不能只在单一 MISP 切片上报告。 |
| Xu, Li & Zhu, **CorefPrompt: Prompt-based Event Coreference Resolution by Measuring Event Type and Argument Compatibilities**, EMNLP 2023. [ACL](https://aclanthology.org/2023.emnlp-main.954/) · DOI `10.18653/v1/2023.emnlp-main.954` | 把 ECR 转成 cloze-style prompt，并用 event-type/argument compatibility 辅助任务。 | 这是最接近“prompt-based event coreference”的方法学先例，但仍是静态 ECR benchmark；没有在线记忆、MDL 选择或 CTI。论文需明确 MDL scoring 与 CorefPrompt 的区别。 |
| Wang et al., **MAVEN-ERE: A Unified Large-scale Dataset for Event Coreference, Temporal, Causal, and Subevent Relation Extraction**, EMNLP 2022. [DOI](https://doi.org/10.18653/v1/2022.emnlp-main.60) · [arXiv](https://arxiv.org/abs/2211.07342) | 大规模人工 ERE 数据集，含 103,193 条 event coreference chains、1,216,217 temporal、57,992 causal、15,841 subevent relations。 | 规模化静态事件关系标注；没有时间到达约束、CTI 语料或开放世界新事件发现。项目可将其作为一般 ECR 对照来源，但不能宣称事件关系 benchmark 首创。 |
| Satyapanich, Ferraro & Finin, **CASIE: Extracting Cybersecurity Event Information from Text**, AAAI 2020. [AAAI](https://ojs.aaai.org/index.php/AAAI/article/view/6401) · DOI `10.1609/aaai.v34i05.6401` | 1,000 篇 2017–2019 英文新闻；五类网络安全事件、语义角色和 20 类事件参数；做事件检测/参数抽取。 | CTI/cyber event extraction 的重要基线，但样本级触发词/角色抽取，不做跨文档事件实例归并或流式开集判定。 |
| Man Duc Trong et al., **Introducing a New Dataset for Event Detection in Cybersecurity Texts**, EMNLP 2020. [ACL](https://aclanthology.org/2020.emnlp-main.433/) · DOI `10.18653/v1/2020.emnlp-main.433` | 手工标注 30 个 cybersecurity event types，强调 document-level ED。 | 事件触发词检测、静态文档；没有 SAME/RELATED/UNSEEN 事件实例状态，也无在线评测。 |
| Marchiori et al., **STIXnet: A Novel and Modular Solution for Extracting All STIX Objects in CTI Reports**, 2023. [arXiv](https://arxiv.org/abs/2303.09999) · [ACM](https://dl.acm.org/doi/10.1145/3600160.3600182) | 面向 CTI 报告自动抽取 STIX 实体和关系；强调从非结构化报告恢复结构化 CTI。 | 结构化抽取/KG 方向；不是事件实例归并、在线状态机或 MDL。它是项目 STIX 输入映射的直接邻近工作。 |
| Rani et al., **TTPXHunter: Actionable Threat Intelligence Extraction as TTPs from Finished Cyber Threat Reports**, 2024. [arXiv](https://arxiv.org/html/2403.03267v3) · [ACM](https://dl.acm.org/doi/10.1145/3696427) | 从 CTI 报告抽取 ATT&CK TTP；构造 39,296 句子-TTP 与 149 篇报告-TTP 数据，支持 STIX 输出。 | 完成报告上的 TTP 分类/抽取，非增量事件发现；没有事件实例身份、跨报告 SAME/RELATED/UNSEEN 或 MDL。 |
| Alam et al., **CTIBench: A Benchmark for Evaluating LLMs in Cyber Threat Intelligence**, NeurIPS 2024 Datasets & Benchmarks. [NeurIPS](https://neurips.cc/virtual/2024/poster/97556) · [Paper](https://proceedings.neurips.cc/paper_files/paper/2024/hash/5acd3c628aa1819fbf07c39ef73e7285-Paper-Datasets_and_Benchmarks_Track.pdf) · [arXiv](https://arxiv.org/abs/2406.07599) | CTI-MCQ、CVE→CWE、CVSS、ATT&CK technique extraction、threat-actor attribution 等五类 LLM 评测任务。 | 目前最重要的 CTI-LLM benchmark 邻居，但任务是知识/抽取/归因，非流式事件诱导；没有到达顺序、在线记忆或四类事件状态。项目应将 CTIBench 作为“广义 CTI benchmark”对照，而不是同任务竞争者。 |

## closest-work clusters

### A. 在线/跨文档归并（方法邻近）

Rao et al. 建立 streaming cross-document coreference 的问题形态；Bugert et al. 说明静态 CDCR 对跨语料泛化敏感。项目继承“维护历史状态并将新文档接入已有簇”的骨架，但把对象从 entity/event mention 改成 CTI 文档级事件实例，并显式加入 `NO_EVENT`、`RELATED_EVENT` 和 `UNSEEN_EVENT` 的开放世界决策。现有来源没有把这种四路状态机与 LM 描述长度结合起来。

### B. 事件 coreference 与 prompt（任务/提示邻近）

CorefPrompt 是 prompt-based ECR 的直接方法学先例；MAVEN-ERE 和 Bugert et al. 提供静态事件关系/跨语料评测先例。项目的可辩护差异是：候选簇不是全量语料聚类后得到，而是每个到达时刻可见历史的状态；`SAME_EVENT` 是同一攻击突破实例的增量/平行证据，`RELATED_EVENT` 是相同 actor/campaign 的独立行动。

### C. CTI 事件/结构化抽取与基准（领域邻近）

CASIE、EMNLP 2020 cybersecurity ED、STIXnet、TTPXHunter 覆盖事件触发词、参数、STIX 对象、ATT&CK TTP；CTIBench 覆盖 LLM 的 CTI 知识、抽取与归因。它们都没有流式事件实例诱导。项目应避免把“事件抽取/ATT&CK 映射”写成自身 novelty；应强调从已有 CTI 文档生成在线事件归属和发现标签。

### D. 压缩/MDL（理论邻近）

Language Modeling Is Compression 为使用 LM 条件概率转代码长度提供理论依据；AutoCompressors 研究上下文摘要压缩。项目若以候选事件簇/假设的增量描述长度差作为决策分数，创新点在**决策应用与在线协议**，不是压缩等价定理本身。需要在论文中给出：候选历史窗口、代码长度计算、冷启动/warm-up、候选簇增长和拒识阈值的精确定义。

## 已覆盖与未覆盖 gap

### 已被项目资产覆盖（依据仓库 README、`data/PROVENANCE.md` 与公开 GitHub 页面）

- 输入同时支持 STIX 2.1/MISP 元数据投影；模型侧只暴露 `publish_time/title/text`，GT 锚点与标签字段被移除。
- 真实 MISP OSINT feed（1,680 条）与同一事件属性到达切片（2,082 条，151 条 `SAME_EVENT`），另有 1,000 条四类均衡受控合成流。
- 明确定义 `NO_EVENT → SAME_EVENT → RELATED_EVENT → UNSEEN_EVENT` 的短路优先级和只看过去状态；提供 warm-up、Macro-F1、B-cubed、ARI 评测入口。
- 已审计标题/来源机构/galaxy/哈希等泄露；公开指出同一事件标题重复、无标题消融、SAME/UNSEEN 文本长度差异和真实流的无锚点比例。
- 数据快照、来源 URL、重建脚本与 `FROZEN.sha256` 支持离线重算。

### 仍需补强或在论文中明确为 limitation

- **独立人工语义金标**：当前标签主要由 MISP Event ID、campaign/actor 锚点、时间窗与标题/CVE/actor 复合规则生成，属于元数据驱动弱监督；需要抽样人工复核、inter-annotator agreement 或至少误标率估计。
- **跨源事件对齐**：MISP 内同一 Event ID 的增量切片很强，但不同 feed/机构对同一攻击的 incident ID 不一致；当前相似度链接保守且只覆盖高标题相似、共享弱实体的案例。
- **真正持续流与延迟**：数据按历史时间回放，尚未证明在实时到达、乱序、重复、删除/更正、长期记忆压缩下仍稳定；应补充乱序/重复/时间窗敏感性与内存/延迟曲线。
- **LLM-特定证据**：需要与静态 prompt ECR（如 CorefPrompt）、embedding/检索聚类、窗口化在线聚类和压缩基线作统一消融；仅报告某个模型超过 GPT-4o/7B 等属于当前项目禁止的未复现实验声明。
- **开集与类别不平衡**：Real-Wild `NO_EVENT` 占比高且 `SAME` 极少；必须报告 per-class precision/recall、拒识/误警、事件簇指标和置信区间，避免只报总体 accuracy 或把合成均衡结果外推到真实流。
- **MDL 公平性**：比较不同模型时要固定 tokenizer、上下文长度、候选数量、prompt token 开销和模型参数成本；否则“代码更短”可能只是分词或模板差异。
- **外部 benchmark 复现**：建议在至少一个公开静态 CDCR（如 ECB+）和一个 CTI 抽取数据集上做迁移/零样本对照，用于证明增益来自在线协议而非数据特定捷径。

## Novelty confidence（条件评分）

| 维度 | 置信度 | 依据 |
|---|---:|---|
| CTI 文档流 + 在线四类事件实例任务 | 0.85 | 检索到的 CTI 工作集中在静态抽取/TTP/归因；streaming coref 工作集中在通用 entity。 |
| STIX/MISP 增量切片 benchmark | 0.85 | 未检索到公开 benchmark 同时提供真实到达切片、开放噪声和 SAME/RELATED/UNSEEN 语义；但“首次”仍需扩大检索范围并引用数据快照证据。 |
| LM 条件描述长度用于该任务 | 0.75 | 压缩视角有坚实先例，但把 MDL 用作 CTI 在线归属仍未见直接重合；需严谨区分理论先例。 |
| Prompt-based event coreference 本身 | 0.35 | CorefPrompt 已明确占据该点；只能作为实现方式或 baseline，不能单独宣称 novelty。 |
| “首次 online event induction”绝对表述 | 0.50 | 本轮未发现直接同任务论文，但检索覆盖有限，建议改为“to our knowledge, no prior work found in the searched public literature”。 |

综合判断：**中高（约 0.78），依赖贡献表述和补实验**。最安全的主张是“一个面向 CTI 的、只看过去状态的在线事件实例诱导 benchmark 与 in-context MDL 判据”；最危险的主张是“首次事件抽取/首次事件 coreference/首次 MDL”。

## 建议论文 related-work 句式

> Existing cybersecurity event-extraction and CTI benchmarks primarily detect triggers, extract arguments/TTPs, or evaluate knowledge and attribution (CASIE; Trong et al.; STIXnet; TTPXHunter; CTIBench). General event-coreference research studies static cross-document clustering and prompt-based compatibility (Bugert et al.; MAVEN-ERE; CorefPrompt), while streaming coreference has mainly focused on entities (Rao et al.). We therefore study a different setting: open-world CTI documents arriving over time, where event-instance decisions must use only past context, and candidate assignments are scored with in-context description length. 

这段应与实际方法和实验一致；不要据此宣称不存在任何未检索到的工作。

