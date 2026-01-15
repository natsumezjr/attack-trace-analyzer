# KillChain 结果展示规范

## 文档目的

本文件定义 KillChain 分析结果在前端的展示规范，包括基础版与完整版的展示内容、API 接口规范、数据字段映射与图谱高亮规则。

## 读者对象

- 负责 KillChain 前端展示实现的同学
- 负责 API 接口设计的同学
- 负责测试与验收的同学

## 引用关系

- KillChain 概览设计：`69-KillChain概览设计.md`
- 前端与中心机接口（权威口径）：`../../80-规范/88-前端与中心机接口.md`
- ECS 字段规范：`../../80-规范/81-ECS字段规范.md`

---

## 1. 展示模式

### 1.1 基础版视图（默认展开）

基础版视图提供 KillChain 的核心信息概览，包含：

1. **可信度评分条**
   - 可视化评分条（0.0 - 1.0）
   - 颜色规则：
     - `> 0.7`：绿色（高可信度）
     - `0.4 - 0.7`：黄色（中等可信度）
     - `< 0.4`：红色（低可信度）
   - 显示数值百分比

2. **MITRE ATT&CK 战术时间线**
   - 横向流程图展示各战术阶段
   - 格式：`[Initial Access] → [Execution] → [...] → [Impact]`
   - 每个阶段显示：
     - 战术名称（中文）
     - 时间范围（可选 hover 显示）

3. **LLM 解释摘要**
   - 显示 explanation 的前 3 句话
   - 省略号提示有更多内容
   - "查看详情"按钮

4. **操作按钮**
   - "查看详情"（展开完整版）
   - "导出 KillChain"（导出为 Markdown）

### 1.2 完整版视图（点击展开）

完整版视图提供 KillChain 的详细信息，包含：

1. **概览卡片**
   - kc_uuid（可复制）
   - confidence（评分条）
   - segment_count（段数量）
   - selected_path_count（路径数量）

2. **完整 MITRE ATT&CK 战术时间线**
   - 可交互的时间线
   - 点击阶段展开查看详情
   - 每个阶段显示：
     - 战术状态（state）
     - 时间范围（t_start, t_end）
     - 入口/出口锚点（anchor_in_uid, anchor_out_uid）
     - 异常边数量（abnormal_edge_count）

3. **完整 LLM 解释文本**
   - 10-20 句中文完整解释
   - 可折叠/展开
   - 关键信息高亮（实体、IP、进程等）
   - "复制"按钮
   - "导出为 Markdown"按钮

4. **段间连接路径列表**
   - 每条路径显示：
     - path_id
     - 源锚点 → 目标锚点
     - hop 数量
     - 边 ID 列表（可折叠）
     - "在图谱中高亮"按钮

5. **返回基础版**
   - "收起详情"按钮

---

## 2. API 接口规范

### 2.1 通过任务 ID 查询（主接口）

**接口**：`GET /api/v1/analysis/tasks/{task_id}`

**响应扩展**：

```json
{
  "status": "ok",
  "task": {
    "task.id": "trace-abc-123",
    "task.status": "succeeded",
    "task.result": {
      "killchain_uuid": "uuid-xxx-yyy",  // 新增：KillChain UUID
      "killchain": {                      // 新增（可选）：完整数据
        "kc_uuid": "uuid-xxx-yyy",
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
          }
        ],
        "selected_paths": [
          {
            "path_id": "p-abc123",
            "src_anchor": "Host:host.id=web-001",
            "dst_anchor": "Process:pid=5678",
            "hop_count": 3,
            "edge_ids": ["event-id-1", "event-id-2", "event-id-3"]
          }
        ],
        "explanation": "攻击者进程 p_c2 (pid:1234) 从外部 IP 1.2.3.4..."
      }
    }
  }
}
```

### 2.2 通过 kc_uuid 直接查询（可选）

**接口**：`GET /api/v1/analysis/killchain/{kc_uuid}`

**响应结构**：

```json
{
  "status": "ok",
  "killchain": {
    "kc_uuid": "uuid-xxx-yyy",
    "confidence": 0.85,
    "segments": [...],
    "selected_paths": [...],
    "explanation": "..."
  }
}
```

**错误响应**：

- `404 Not Found`：kc_uuid 不存在
- `500 Internal Server Error`：查询失败

---

## 3. 数据字段映射

### 3.1 Segment 字段映射

| API 字段 | 显示名称 | 格式 | 说明 |
|----------|----------|------|------|
| `seg_idx` | 段索引 | 整数 | 从 0 开始 |
| `state` | 战术状态 | 枚举字符串 | 对应中文见下表 |
| `t_start` | 起始时间 | ISO 8601 | 可转换为本地时间 |
| `t_end` | 结束时间 | ISO 8601 | 可转换为本地时间 |
| `anchor_in_uid` | 入口锚点 | UID 字符串 | 可截取显示 |
| `anchor_out_uid` | 出口锚点 | UID 字符串 | 可截取显示 |
| `abnormal_edge_count` | 异常边数 | 整数 | top 6 异常边 |

### 3.2 战术状态中英文映射

| state (英文) | 中文显示 |
|--------------|----------|
| `INITIAL_ACCESS` | 初始入侵 |
| `EXECUTION` | 执行 |
| `PRIVILEGE_ESCALATION` | 权限提升 |
| `LATERAL_MOVEMENT` | 横向移动 |
| `COMMAND_AND_CONTROL` | 命令与控制 |
| `DISCOVERY` | 发现 |
| `IMPACT` | 影响 |

### 3.3 Path 字段映射

| API 字段 | 显示名称 | 格式 | 说明 |
|----------|----------|------|------|
| `path_id` | 路径 ID | 字符串 | 可复制 |
| `src_anchor` | 源锚点 | UID 字符串 | 简化显示 |
| `dst_anchor` | 目标锚点 | UID 字符串 | 简化显示 |
| `hop_count` | 跳数 | 整数 | 边的数量 |
| `edge_ids` | 边 ID 列表 | 字符串数组 | 可折叠显示 |

---

## 4. 图谱高亮规则

### 4.1 高亮触发方式

1. **自动高亮**：当 KillChain 面板展开时，自动高亮所有 killchain 路径
2. **手动高亮**：点击"在图谱中高亮"按钮，高亮特定路径
3. **清除高亮**：关闭 KillChain 面板时，清除所有高亮

### 4.2 高亮样式规范

KillChain 路径边的样式固定为：

```typescript
// 边样式
{
  stroke: '#FF6B6B',      // 红色
  lineWidth: 3,           // 线宽
  lineDash: [5, 5],       // 虚线
  opacity: 0.9            // 不透明度
}

// 节点样式（路径上的节点）
{
  fill: '#FFE5E5',        // 浅红色填充
  stroke: '#FF6B6B',      // 红色边框
  lineWidth: 2            // 边框宽度
}
```

### 4.3 高亮性能优化

为避免性能问题，高亮功能需满足：

1. **最大高亮边数**：限制为 100 条
2. **延迟渲染**：使用 `requestAnimationFrame` 分批渲染
3. **虚拟滚动**：对于大量节点，使用虚拟滚动
4. **取消机制**：高亮请求可被后续请求取消

---

## 5. UI 组件规范

### 5.1 组件接口

```typescript
interface KillChainPanelProps {
  task: AnalysisTaskItem;           // 分析任务数据
  onHighlightPath?: (pathIds: string[]) => void;  // 图谱高亮回调
  onExport?: (killchain: KillChainData) => void;  // 导出回调
}

interface KillChainData {
  kc_uuid: string;
  confidence: number;
  segments: SegmentData[];
  selected_paths: PathData[];
  explanation: string;
}

interface SegmentData {
  seg_idx: number;
  state: string;
  t_start: string;  // ISO 8601
  t_end: string;
  anchor_in_uid: string;
  anchor_out_uid: string;
  abnormal_edge_count: number;
}

interface PathData {
  path_id: string;
  src_anchor: string;
  dst_anchor: string;
  hop_count: number;
  edge_ids: string[];
}
```

### 5.2 组件状态

```typescript
interface KillChainPanelState {
  isExpanded: boolean;           // 是否展开完整版
  isLoading: boolean;            // 是否正在加载
  error: string | null;          // 错误信息
  highlightedPathId: string | null;  // 当前高亮的路径 ID
}
```

### 5.3 交互行为

1. **默认状态**：
   - 显示基础版视图
   - `isExpanded = false`

2. **点击"查看详情"**：
   - 展开完整版视图
   - `isExpanded = true`
   - 自动高亮图谱上的所有 killchain 路径
   - 触发 `onHighlightPath(allPathIds)`

3. **点击"收起详情"**：
   - 折叠到基础版视图
   - `isExpanded = false`
   - 清除图谱高亮
   - 触发 `onHighlightPath([])`

4. **点击特定路径的"在图谱中高亮"**：
   - 高亮该路径的边
   - 触发 `onHighlightPath([pathId])`

5. **点击"导出 KillChain"**：
   - 生成 Markdown 格式的 killchain 报告
   - 触发文件下载
   - 触发 `onExport(killchainData)`

---

## 6. 报告导出格式

### 6.1 Markdown 章节

导出的 KillChain 章节格式固定为：

```markdown
## 6. KillChain 攻击链分析

### 6.1 概览

- kc_uuid: `uuid-xxx-yyy`
- confidence: `0.85`
- segment_count: `6`
- selected_path_count: `5`

### 6.2 MITRE ATT&CK 战术分段

[初始入侵] → [执行] → [权限提升] → [横向移动] → [命令与控制] → [影响]

#### 分段详情

**1. 初始入侵 (INITIAL_ACCESS)**
- 时间范围：2025-01-16T10:00:00Z → 2025-01-16T10:05:00Z
- 入口锚点：Process:pid=1234
- 出口锚点：Host:host.id=web-001
- 异常边数：3

**2. 执行 (EXECUTION)**
...

### 6.3 LLM 全链解释

攻击者进程 p_c2 (pid:1234) 从外部 IP 1.2.3.4 连接到受害主机 host_web (host.id:host-001)...
（完整 10-20 句解释）

### 6.4 段间连接路径

**路径 1**: p-abc123
- 源锚点：Host:host.id=web-001
- 目标锚点：Process:pid=5678
- hop 数量：3
- 边 ID 列表：event-id-1, event-id-2, event-id-3

**路径 2**: ...
```

### 6.2 导出触发条件

1. **手动导出**：点击"导出 KillChain"按钮
2. **自动包含**：在完整溯源报告导出时自动包含该章节
3. **可选包含**：在报告导出设置中提供"包含 KillChain 分析"勾选项

---

## 7. 实现绑定点

### 7.1 前端组件

- 组件文件：`frontend/components/killchain/killchain-panel.tsx`
- 集成位置：`frontend/app/trace/page.tsx`
- 样式文件：`frontend/components/killchain/killchain-panel.css`（可选）

### 7.2 API 客户端

- API 函数：`frontend/lib/api/analysis.ts`
  - `fetchKillChainByTaskId(taskId: string)`
  - `fetchKillChainByUUID(kcUuid: string)`（可选）

### 7.3 报告生成

- 报告生成器：`frontend/lib/export/report-generator.ts`
  - 在 `generateMarkdownReport()` 中添加 killchain 章节

---

## 8. 测试验收标准

### 8.1 功能测试

1. **基础版视图**：
   - ✅ 可信度评分条颜色正确
   - ✅ 战术时间线显示完整
   - ✅ LLM 解释摘要显示前 3 句

2. **完整版视图**：
   - ✅ 展开/折叠功能正常
   - ✅ 所有 segment 显示完整
   - ✅ 所有 path 显示完整
   - ✅ LLM 解释完整显示

3. **图谱高亮**：
   - ✅ 展开面板时自动高亮
   - ✅ 点击路径高亮功能正常
   - ✅ 收起面板时清除高亮

4. **报告导出**：
   - ✅ 导出的 Markdown 格式正确
   - ✅ 包含所有必要信息
   - ✅ 文件下载成功

### 8.2 性能测试

1. **渲染性能**：
   - 基础版渲染时间 < 100ms
   - 完整版展开时间 < 300ms

2. **高亮性能**：
   - 高亮 100 条边不卡顿
   - 高亮操作响应时间 < 200ms

### 8.3 兼容性测试

1. **向后兼容**：
   - 不包含 killchain 的任务正常显示
   - 旧版本任务不报错

2. **边界情况**：
   - 空segments处理
   - 超长explanation换行处理
   - 特殊字符转义
