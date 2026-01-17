# KillChain 概览设计

## 文档目的

本文件定义 KillChain（攻击链）分析的定位、目标、核心算法与数据结构，作为 Analysis 模块溯源能力的核心设计文档。

## 读者对象

- 负责 KillChain 算法实现的同学
- 负责前端 KillChain 展示的同学
- 负责答辩讲解与测试的同学

## 引用关系

- 任务模型与状态机：`70-任务模型与状态机.md`
- 候选路径构造与评分：`71-候选路径构造与评分.md`
- LLM 选择器与回退机制：`72-LLM选择器与回退机制.md`
- TTP 相似度匹配：`73-TTP相似度匹配.md`
- KillChain 结果展示规范：`74-KillChain结果展示规范.md`
- ECS 字段规范：`../../80-规范/81-ECS字段规范.md`

## 1. KillChain 的定位与目标

### 1.1 定位

KillChain 是 Analysis 模块溯源任务的核心算法实现，用于重建完整的攻击路径并生成可解释的分析报告。

### 1.2 目标

KillChain 分析实现以下核心功能：

1. **战术分段**：基于 MITRE ATT&CK 战术将攻击事件自动分段；
2. **路径重建**：识别各战术阶段之间的连接路径；
3. **智能选择**：使用大语言模型（Large Language Model, LLM）选择最合理的攻击链；
4. **可解释性**：生成 10-20 句中文的全链解释，包含主谓宾结构；
5. **置信度评估**：输出可信度评分（0.0-1.0）。

### 1.3 与溯源任务的关系

溯源任务包含两个核心分析模块：

```
溯源任务 (Trace Task)
    │
    ├─→ TTP 相似度匹配 (组织归因)
    │
    └─→ KillChain 分析 (路径重建 + 解释生成)
```

**模块定位**

- **溯源任务**：前端触发创建的异步任务容器；
- **TTP 相似度匹配**：基于 Canonical Findings 计算与 APT 组织的相似度；
- **KillChain 分析**：基于图谱数据重建攻击路径并生成解释。

两个模块互补，共同构成完整的溯源分析能力。

---

## 2. 基于 MITRE ATT&CK 战术的分段机制

### 2.1 AttackState 枚举

系统使用有限状态自动机（Finite State Automaton, FSA）识别攻击阶段。状态枚举固定为：

| 状态值 | MITRE ATT&CK 战术 | 说明 |
|--------|-------------------|------|
| `INITIAL_ACCESS` | TA0001 Initial Access | 初始入侵 |
| `EXECUTION` | TA0002 Execution | 执行 |
| `PRIVILEGE_ESCALATION` | TA0004 Privilege Escalation | 权限提升 |
| `LATERAL_MOVEMENT` | TA0008 Lateral Movement | 横向移动 |
| `COMMAND_AND_CONTROL` | TA0011 Command and Control | 命令与控制 |
| `DISCOVERY` | TA0007 Discovery | 发现 |
| `IMPACT` | TA0040 Impact | 影响 |

实现绑定点：

- 状态定义：`backend/app/services/analyze/killchain.py:AttackState`
- 状态转换规则：`backend/app/services/analyze/killchain.py:FSABuilder`

### 2.2 StateSegment 结构

每个战术阶段（Segment）包含：

- `seg_idx: int` - 段索引
- `state: AttackState` - 战术状态
- `t_start: float` - 段起始时间（Unix 时间戳）
- `t_end: float` - 段结束时间（Unix 时间戳）
- `anchor_in_uid: str` - 段入口锚点节点 UID
- `anchor_out_uid: str` - 段出口锚点节点 UID
- `abnormal_edge_summaries: list[dict]` - 段内 top 6 异常边摘要

### 2.3 分段生成规则

分段生成遵循固定流程：

1. **告警边提取**：从告警边集合（`is_alarm=true`）开始；
2. **战术分组**：按 `threat.tactic.id` 将边分组到对应战术状态；
3. **时间排序**：按时间顺序对每个战术状态的边排序；
4. **段生成**：为每个战术状态生成一个 Segment，选择入口/出口锚点；
5. **时间范围计算**：计算每个 Segment 的时间范围（`t_start`, `t_end`）；
6. **摘要提取**：从每个 Segment 中选择 top 6 异常边作为摘要。

实现绑定点：

- FSA 构建：`backend/app/services/analyze/killchain.py:build_fsa_graph()`
- 段摘要生成：`backend/app/services/analyze/killchain.py:summarize_edge()`

---

## 3. 数据结构概览

### 3.1 KillChain 核心数据结构

```python
@dataclass(slots=True)
class KillChain:
    """
    Phase C 输出：最终选出的 killchain（全链一致性）。
    """
    kc_uuid: str                        # KillChain 唯一标识符
    fsa_graph: FSAGraph                 # 关联的 FSA 图
    segments: List[SegmentSummary]      # 攻击阶段段摘要
    selected_paths: List[CandidatePath] # LLM 选择的关键路径
    explanation: str                     # LLM 生成的攻击链解释
    confidence: float = 0.0             # LLM 评估的可信度 (0.0-1.0)
    trace: List[Dict[str, Any]] = field(default_factory=list)  # 分析过程追踪
```

### 3.2 SegmentSummary 结构

```python
@dataclass(slots=True)
class SegmentSummary:
    """
    单个战术阶段的摘要。
    """
    seg_idx: int                        # 段索引
    state: AttackState                  # 战术状态
    t_start: float                      # 段起始时间
    t_end: float                        # 段结束时间
    anchor_in_uid: str                  # 入口锚点 UID
    anchor_out_uid: str                 # 出口锚点 UID
    abnormal_edge_summaries: List[Dict] # 段内异常边摘要 (top 6)
```

### 3.3 CandidatePath 结构

```python
@dataclass(slots=True)
class CandidatePath:
    """
    连接两个相邻段的候选路径。
    """
    path_id: str                        # 路径唯一标识
    src_anchor: str                     # 源锚点
    dst_anchor: str                     # 目标锚点
    t_min: float                        # 路径最早时间
    t_max: float                        # 路径最晚时间
    edges: List[GraphEdge]              # 路径包含的边
    steps: List[Dict]                   # 精简的边摘要（供 LLM 使用）
    signature: str = ""                 # 路径签名（用于去重）
```

### 3.4 数据流示意

```
Neo4j 图谱 (告警边 + Telemetry)
    │
    ├─→ Phase A: FSA 状态机
    │     ├─→ 识别战术阶段 (Segments)
    │     └─→ 选择段锚点 (anchors)
    │
    ├─→ Phase B: 候选路径枚举
    │     ├─→ 枚举段间路径 (CandidatePaths)
    │     └─→ 计算路径评分
    │
    ├─→ Phase C: LLM 路径选择
    │     ├─→ 输入裁剪 (PayloadReducer)
    │     ├─→ 启发式预筛 (HeuristicPreselector)
    │     ├─→ LLM 选择 (LLMChooser / MockChooser)
    │     └─→ 输出校验
    │
    └─→ Phase D: 持久化
          ├─→ 写入 custom.killchain.uuid (边)
          ├─→ 写入 analysis.task_id (节点)
          └─→ 写入任务结果 (OpenSearch)
```

---

## 4. KillChain 结果的输出形式

### 4.1 持久化形式

KillChain 结果通过以下方式持久化：

1. **Neo4j 边属性**：`custom.killchain.uuid` (ECS 合规字段)
2. **Neo4j 节点属性**：`analysis.task_id`
3. **OpenSearch 任务文档**：`task.result.killchain` (可选，直接嵌入)

实现绑定点：

- 持久化逻辑：`backend/app/services/analyze/killchain.py:persist_killchain_to_db()`

### 4.2 前端查询方式

前端通过以下方式获取 KillChain 结果：

1. **通过任务 ID 查询**：
   - 接口：`GET /api/v1/analysis/tasks/{task_id}`
   - 返回：`task.result.killchain_uuid` 和 `task.result.killchain`

2. **通过 kc_uuid 直接查询**（可选）：
   - 接口：`GET /api/v1/analysis/killchain/{kc_uuid}`
   - 返回：完整的 KillChain 数据结构

### 4.3 task.result 扩展字段

任务文档的 `task.result` 字段扩展为：

```json
{
  "task": {
    "result": {
      "ttp_similarity": {
        "attack_tactics": ["TA0001", "TA0006", ...],
        "attack_techniques": ["T1059", "T1055", ...],
        "similar_apts": [...]
      },
      "trace": {
        "updated_edges": 42,
        "path_edges": 8
      },
      "killchain_uuid": "abc-123-def",  // 新增：KillChain UUID
      "killchain": {                     // 新增（可选）：完整 KillChain 数据
        "kc_uuid": "abc-123-def",
        "confidence": 0.85,
        "segments": [
          {
            "seg_idx": 0,
            "state": "INITIAL_ACCESS",
            "t_start": 1234567890.0,
            "t_end": 1234567900.0,
            "anchor_in_uid": "Process:pid=1234",
            "anchor_out_uid": "Host:host.id=web-001",
            "abnormal_edge_count": 3
          },
          ...
        ],
        "selected_paths": [
          {
            "path_id": "p-abc123",
            "src_anchor": "Host:host.id=web-001",
            "dst_anchor": "Process:pid=5678",
            "hop_count": 3,
            "edge_ids": ["event-id-1", "event-id-2", "event-id-3"]
          },
          ...
        ],
        "explanation": "攻击者进程 p_c2 (pid:1234) 从外部 IP ..."
      }
    }
  }
}
```

---

## 5. LLM 解释文本生成规则

### 5.1 解释文本要求

LLM 生成的 `explanation` 字段必须满足以下要求：

**1. 长度与结构**

- 文本长度为 10-20 句中文；
- 每个关键节点包含主谓宾结构。

**2. 内容要素**

解释文本必须包含以下关键信息：

- **初始入侵点识别**：明确攻击者进入内部网络的入口；
- **横向移动路径**：描述攻击者在内部网络中的移动轨迹；
- **权限提升路径**：分析攻击者如何获取更高权限；
- **数据泄露路径**：追踪从存储中提取数据的完整路径；
- **攻击者归因**：通过提取攻击工具、脚本、配置文件的指纹特征进行归因；
- **C2 服务器分析**：识别攻击者与 C2 服务器的 IP 地址关联。

**3. 实体标注格式**

使用易懂的形式加上括号标注实体：

- `p_c2 (pid:1234)` 代表 C2 进程；
- `host_web (host.id:host-001)` 代表 Web 主机；
- `user_admin (user.name:admin)` 代表管理员用户。

### 5.2 置信度评分

`confidence` 字段规则固定：

- **范围**：0.0 - 1.0
- **LLM 模式**：由 LLM 在输出中提供
- **Fallback 模式**：固定为 0.5
- **单段场景**：固定为 0.3

实现绑定点：

- LLM prompt：`backend/app/services/analyze/killchain_llm.py:build_choose_prompt()`
- 置信度提取：`backend/app/services/analyze/killchain_llm.py:validate_choose_result()`

---

## 6. 与其他分析模块的关系

### 6.1 与 TTP 相似度匹配的关系

| 维度 | KillChain | TTP 相似度匹配 |
|------|-----------|----------------|
| **输入数据** | 图谱边 + 告警边 | Canonical Findings |
| **输出目标** | 攻击路径重建 | APT 组织归因 |
| **核心算法** | FSA + LLM | TF-IDF + 余弦相似度 |
| **结果形式** | 路径 + 解释文本 | Top-3 相似组织 |
| **展示方式** | 战术时间线 + 解释 | 相似度列表 |

### 6.2 与候选路径构造的关系

KillChain 复用候选路径构造模块（Phase B）：

- **候选路径构造**：枚举所有可能的段间连接路径
- **KillChain 选择**：使用 LLM 从候选路径中选择最合理的路径

实现绑定点：

- 候选路径构造：`backend/app/services/analyze/killchain.py:enumerate_paths_between_anchors()`
