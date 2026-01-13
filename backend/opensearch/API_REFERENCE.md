# OpenSearch 模块 API 参考文档

本文档详细说明 opensearch 模块中每个对外接口的使用方法，用通俗易懂的语言解释每个函数的作用、参数和返回值。

## 📚 目录

- [客户端操作](#客户端操作)
- [索引管理](#索引管理)
- [存储功能](#存储功能)
- [数据分析](#数据分析)
- [索引映射](#索引映射)

（1）前端需要调用的函数
1. store_events() — 存储事件/告警
- 接收事件列表，自动路由到对应索引
- 自动去重（基于 event.id）
- 返回存储统计
2. run_data_analysis() — 执行数据分析
- 告警融合去重（Raw Findings → Canonical Findings）
- 返回分析结果


（2）函数索引
1. 客户端操作（8 个函数）
get_client() - 获取客户端
index_exists() - 检查索引是否存在
ensure_index() - 确保索引存在
search() - 搜索文档
get_document() - 根据 ID 获取文档
update_document() - 更新文档
index_document() - 存储单个文档
bulk_index() - 批量存储文档
2. 索引管理（4 个函数/常量）
INDEX_PATTERNS - 索引模式常量
get_index_name() - 生成索引名称
hash_token() - Token 哈希
initialize_indices() - 初始化所有索引
3. 存储功能（2 个函数）
store_events() - 存储事件（自动路由+去重）
route_to_index() - 路由到索引
4. 数据分析（3 个函数）
run_data_analysis() - 完整数据分析流程
deduplicate_findings() - 告警融合去重
run_security_analytics() - Security Analytics 检测
5. 索引映射（5 个常量）
ecs_events_mapping - ECS 事件映射
raw_findings_mapping - 原始告警映射
canonical_findings_mapping - 规范告警映射
attack_chains_mapping - 攻击链映射
client_registry_mapping - 客户端注册映射
---

## 客户端操作

### `get_client()` / `get_open_search_client()`

**这个函数是干什么的？**

获取 OpenSearch 客户端对象。就像你要打电话，需要先拿到电话机一样，操作 OpenSearch 之前需要先获取客户端。

**为什么需要这个？**

- 这是连接 OpenSearch 的基础
- 客户端会自动管理连接，不需要每次都重新连接
- 使用单例模式，整个程序只创建一个客户端，节省资源

**什么时候用？**

通常不需要直接调用，其他函数内部会自动调用。只有在需要直接操作 OpenSearch 客户端时才使用。

**示例：**

```python
from opensearch import get_client

# 获取客户端（通常不需要直接调用）
client = get_client()

# 直接使用客户端进行一些特殊操作
info = client.info()
print(f"OpenSearch 版本: {info['version']['number']}")
```

**返回值：**
- `OpenSearch` 客户端对象

---

### `index_exists(index_name: str) -> bool`

**这个函数是干什么的？**

检查一个索引（类似数据库的表）是否存在。

**为什么需要这个？**

- 在存储数据前，确认索引是否存在
- 避免在操作不存在的索引时报错
- 用于条件判断，比如"如果索引不存在就创建"

**参数：**
- `index_name`: 索引名称，比如 `"ecs-events-2026.01.13"`

**返回值：**
- `True`: 索引存在
- `False`: 索引不存在

**示例：**

```python
from opensearch import index_exists, get_index_name, INDEX_PATTERNS

# 检查今天的 ecs-events 索引是否存在
index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
if index_exists(index_name):
    print("索引已存在，可以直接存储数据")
else:
    print("索引不存在，需要先创建")
```

---

### `ensure_index(index_name: str, mapping: dict) -> None`

**这个函数是干什么的？**

确保索引存在，如果不存在就创建它。就像"如果房子不存在就建一个"。

**为什么需要这个？**

- 自动创建索引，不需要手动检查
- 避免重复创建（如果已存在就跳过）
- 确保数据能正常存储

**参数：**
- `index_name`: 索引名称
- `mapping`: 索引的字段映射（定义每个字段的类型）

**返回值：**
- 无（如果出错会抛出异常）

**示例：**

```python
from opensearch import ensure_index, ecs_events_mapping, get_index_name, INDEX_PATTERNS

# 确保今天的 ecs-events 索引存在
index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
ensure_index(index_name, ecs_events_mapping)
# 如果索引不存在，会自动创建；如果已存在，什么都不做
```

---

### `search(index_name: str, query: dict, size: int = 100) -> list[dict]`

**这个函数是干什么的？**

在指定的索引中搜索数据。就像在图书馆里找书一样，告诉它要找什么，它会返回匹配的结果。

**为什么需要这个？**

- 这是查询数据的主要方式
- 支持各种复杂的搜索条件
- 可以按字段、时间范围、关键词等搜索

**参数：**
- `index_name`: 要搜索的索引名称
- `query`: 查询条件（OpenSearch 查询语法）
- `size`: 最多返回多少条结果（默认 100）

**返回值：**
- 匹配的文档列表，每个文档是一个字典

**查询示例：**

```python
from opensearch import search, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])

# 1. 搜索所有文档
all_events = search(index_name, {"match_all": {}}, size=10)

# 2. 按字段精确匹配
events = search(index_name, {
    "term": {"host.name": "test-host"}
})

# 3. 按时间范围搜索
events = search(index_name, {
    "range": {
        "@timestamp": {
            "gte": "2026-01-13T00:00:00",
            "lte": "2026-01-13T23:59:59"
        }
    }
})

# 4. 组合查询（AND）
events = search(index_name, {
    "bool": {
        "must": [
            {"term": {"event.kind": "event"}},
            {"term": {"host.name": "test-host"}}
        ]
    }
})
```

**别名：**
- `search_documents()` 和 `search()` 是同一个函数

---

### `get_document(index_name: str, doc_id: str) -> dict | None`

**这个函数是干什么的？**

根据文档的 ID 直接获取单个文档。就像你知道书的编号，直接去书架上拿。

**为什么需要这个？**

- 比搜索更快（直接定位，不需要遍历）
- 当你已经知道文档 ID 时使用
- 用于查看特定事件的详细信息

**参数：**
- `index_name`: 索引名称
- `doc_id`: 文档的 ID（通常是 `event.id`）

**返回值：**
- 如果找到：返回文档字典
- 如果不存在：返回 `None`

**示例：**

```python
from opensearch import get_document, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
event_id = "evt-12345"

# 获取指定 ID 的事件
event = get_document(index_name, event_id)

if event:
    print(f"事件 ID: {event['event']['id']}")
    print(f"主机: {event['host']['name']}")
    print(f"消息: {event.get('message', 'N/A')}")
else:
    print("事件不存在")
```

---

### `update_document(index_name: str, doc_id: str, document: dict) -> None`

**这个函数是干什么的？**

更新已存在的文档。就像修改文件中的某一行。

**为什么需要这个？**

- 修改已存储的数据
- 添加新字段或更新字段值
- 比如更新事件的处理状态

**参数：**
- `index_name`: 索引名称
- `doc_id`: 要更新的文档 ID
- `document`: 要更新的字段（只包含要修改的字段）

**返回值：**
- 无（如果出错会抛出异常）

**示例：**

```python
from opensearch import update_document, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
event_id = "evt-12345"

# 更新事件的处理状态
update_document(
    index_name,
    event_id,
    {
        "custom": {
            "processed": True,
            "processed_at": "2026-01-13T10:00:00"
        }
    }
)
```

**注意：**
- 只会更新指定的字段，其他字段保持不变
- 如果文档不存在会报错

---

### `index_document(index_name: str, document: dict, doc_id: str = None) -> None`

**这个函数是干什么的？**

存储单个文档到索引。就像把一张纸放到文件夹里。

**为什么需要这个？**

- 存储单个事件或告警
- 适合少量数据的场景
- 如果数据量大，建议使用 `bulk_index()` 或 `store_events()`

**参数：**
- `index_name`: 索引名称
- `document`: 要存储的文档（字典）
- `doc_id`: 文档 ID（可选，如果不提供会从 document 中提取 `event.id`）

**返回值：**
- 无（如果出错会抛出异常）

**示例：**

```python
from opensearch import index_document, get_index_name, INDEX_PATTERNS
from datetime import datetime

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])

# 存储一个事件
event = {
    "ecs": {"version": "9.2.0"},
    "@timestamp": datetime.now().isoformat(),
    "event": {
        "id": "evt-12345",
        "kind": "event",
        "created": datetime.now().isoformat(),
    },
    "host": {
        "id": "h-001",
        "name": "server-01",
    },
    "message": "用户登录",
}

index_document(index_name, event)
# 或者指定 ID
index_document(index_name, event, doc_id="evt-12345")
```

---

### `bulk_index(index_name: str, documents: list[dict]) -> dict`

**这个函数是干什么的？**

批量存储多个文档。就像一次把很多张纸放到文件夹里，比一张一张放快得多。

**为什么需要这个？**

- 批量存储效率高（一次网络请求处理多个文档）
- 适合大量数据的场景
- 返回成功和失败的统计信息

**参数：**
- `index_name`: 索引名称
- `documents`: 文档列表，每个文档格式为：
  ```python
  {
      "id": "doc-id",  # 可选
      "document": {...}  # 或直接是文档内容
  }
  ```

**返回值：**
```python
{
    "success": 10,      # 成功数量
    "failed": 0,        # 失败数量
    "errors": [...]     # 错误列表（如果有失败）
}
```

**示例：**

```python
from opensearch import bulk_index, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])

# 准备多个文档
documents = [
    {"id": "evt-001", "document": {"event": {"id": "evt-001"}, ...}},
    {"id": "evt-002", "document": {"event": {"id": "evt-002"}, ...}},
    {"document": {"event": {"id": "evt-003"}, ...}},  # 也可以不指定 id
]

# 批量存储
result = bulk_index(index_name, documents)
print(f"成功: {result['success']}, 失败: {result['failed']}")
```

---

## 索引管理

### `INDEX_PATTERNS`

**这个是什么？**

一个字典，定义了所有索引的名称模式。就像给不同类型的文件起名字的模板。

**为什么需要这个？**

- 统一管理索引名称
- 避免写错索引名
- 方便修改索引命名规则

**内容：**

```python
INDEX_PATTERNS = {
    "ECS_EVENTS": "ecs-events",
    "RAW_FINDINGS": "raw-findings",
    "CANONICAL_FINDINGS": "canonical-findings",
    "ATTACK_CHAINS": "attack-chains",
    "CLIENT_REGISTRY": "client-registry",
}
```

**示例：**

```python
from opensearch import INDEX_PATTERNS

# 获取索引模式
pattern = INDEX_PATTERNS["ECS_EVENTS"]  # "ecs-events"
```

---

### `get_index_name(pattern: str, date: datetime = None) -> str`

**这个函数是干什么的？**

根据模式生成带日期的索引名称。比如 `"ecs-events"` + `2026-01-13` = `"ecs-events-2026.01.13"`。

**为什么需要这个？**

- 索引按日期分割，方便管理和查询
- 自动格式化日期
- 统一索引命名规则

**参数：**
- `pattern`: 索引模式（从 `INDEX_PATTERNS` 获取）
- `date`: 日期（可选，默认是今天）

**返回值：**
- 完整的索引名称，如 `"ecs-events-2026.01.13"`

**示例：**

```python
from opensearch import get_index_name, INDEX_PATTERNS
from datetime import datetime

# 获取今天的索引名
today_index = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
# 结果: "ecs-events-2026.01.13"

# 获取指定日期的索引名
specific_date = datetime(2026, 1, 1)
index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], specific_date)
# 结果: "ecs-events-2026.01.01"
```

---

### `hash_token(token: str) -> str`

**这个函数是干什么的？**

对 token（令牌）进行哈希加密。就像把密码加密存储，即使泄露了也看不到原始内容。

**为什么需要这个？**

- 安全存储 token，不存储明文
- 用于客户端注册时的 token 验证
- 使用 SHA256 算法加密

**参数：**
- `token`: 原始 token 字符串

**返回值：**
- 哈希后的字符串（64 个字符的十六进制）

**示例：**

```python
from opensearch import hash_token

# 对 token 进行哈希
original_token = "my-secret-token-123"
hashed = hash_token(original_token)
# 结果: "a1b2c3d4e5f6..." (64 个字符)

# 存储哈希值而不是原始 token
# 验证时也用同样的方式哈希后比较
```

---

### `initialize_indices() -> None`

**这个函数是干什么的？**

初始化所有需要的索引。就像建房子前先打好所有地基。

**为什么需要这个？**

- 一键创建所有索引
- 确保系统启动时所有索引都已准备好
- 通常在应用启动时调用一次

**返回值：**
- 无（如果出错会抛出异常）

**示例：**

```python
from opensearch import initialize_indices

# 在应用启动时调用
def startup():
    print("初始化 OpenSearch 索引...")
    initialize_indices()
    print("索引初始化完成")

# 或者直接调用
initialize_indices()
```

**注意：**
- 如果索引已存在，不会报错，会跳过
- 会创建今天的索引（带日期后缀）
- `client-registry` 索引不带日期后缀

---

## 存储功能

### `store_events(events: list[dict]) -> dict`

**这个函数是干什么的？**

存储事件到 OpenSearch，**这是最常用的存储函数**。它会自动：
1. 判断每个事件应该存到哪个索引（根据 `event.kind` 和 `event.dataset`）
2. 检查是否重复（根据 `event.id`），重复的会被丢弃
3. 批量存储，提高效率

**为什么需要这个？**

- **自动路由**：不用手动判断数据存哪里
- **自动去重**：避免重复数据
- **批量处理**：一次处理多个事件，效率高
- **返回统计**：告诉你存储了多少、失败了多少、重复了多少

**参数：**
- `events`: 事件列表，每个事件是一个字典

**返回值：**
```python
{
    "total": 10,           # 总事件数
    "success": 8,           # 成功存储数（去重后）
    "failed": 0,            # 失败数
    "duplicated": 2,        # 重复数（被丢弃的）
    "details": {            # 每个索引的详细统计
        "ecs-events-2026.01.13": {
            "success": 5,
            "failed": 0,
            "duplicated": 0
        },
        "raw-findings-2026.01.13": {
            "success": 3,
            "failed": 0,
            "duplicated": 0
        }
    }
}
```

**路由规则：**
- `event.kind == "event"` → `ecs-events-*`
- `event.kind == "alert"` + `event.dataset == "finding.canonical"` → `canonical-findings-*`
- `event.kind == "alert"` + 其他 → `raw-findings-*`

**去重规则：**
- 根据 `event.id` 检查是否已存在
- 如果已存在，丢弃该事件
- 如果不存在，正常存储

**示例：**

```python
from opensearch import store_events
from datetime import datetime

# 准备事件数据
events = [
    {
        "event": {
            "id": "evt-001",
            "kind": "event",  # 会存到 ecs-events
            "created": datetime.now().isoformat(),
        },
        "host": {"name": "server-01"},
        "message": "用户登录",
    },
    {
        "event": {
            "id": "finding-001",
            "kind": "alert",  # 会存到 raw-findings
            "dataset": "finding.raw",
            "created": datetime.now().isoformat(),
        },
        "rule": {"id": "rule-001"},
        "message": "检测到可疑活动",
    },
]

# 存储事件（自动路由和去重）
result = store_events(events)

print(f"总数: {result['total']}")
print(f"成功: {result['success']}")
print(f"重复: {result['duplicated']}")

# 查看各索引的详情
for index_name, details in result['details'].items():
    print(f"{index_name}: 成功 {details['success']} 个")
```

---

### `route_to_index(item: dict) -> str`

**这个函数是干什么的？**

根据事件的类型，判断应该存到哪个索引。就像邮局根据地址判断应该送到哪个邮局。

**为什么需要这个？**

- 自动分类数据
- 确保数据存到正确的索引
- 通常不需要直接调用，`store_events()` 内部会使用

**参数：**
- `item`: 事件字典

**返回值：**
- 索引名称，如 `"ecs-events-2026.01.13"`

**示例：**

```python
from opensearch import route_to_index

# 普通事件
event = {"event": {"kind": "event"}}
index = route_to_index(event)
# 结果: "ecs-events-2026.01.13"

# 告警
alert = {"event": {"kind": "alert", "dataset": "finding.raw"}}
index = route_to_index(alert)
# 结果: "raw-findings-2026.01.13"
```

---

## 数据分析

### `run_data_analysis() -> dict`

**这个函数是干什么的？**

执行完整的数据分析流程，包括：
1. Security Analytics 检测（当前为 MVP 版本）
2. 告警融合去重（Raw Findings → Canonical Findings）

**为什么需要这个？**

- 一键执行所有分析任务
- 自动化处理流程
- 适合定时任务或批量处理

**返回值：**
```python
{
    "detection": {
        "success": True,
        "message": "Security Analytics 检测需要先配置 detector（当前为 MVP 版本）"
    },
    "deduplication": {
        "total": 10,        # Raw Findings 总数
        "merged": 8,        # 被合并的告警数
        "canonical": 5,     # 生成的 Canonical Findings 数量
        "errors": 0         # 错误数量
    }
}
```

**示例：**

```python
from opensearch import run_data_analysis

# 执行完整的数据分析
result = run_data_analysis()

print("检测阶段:", result["detection"]["success"])
print("去重阶段:")
print(f"  原始告警: {result['deduplication']['total']}")
print(f"  合并数: {result['deduplication']['merged']}")
print(f"  规范告警: {result['deduplication']['canonical']}")
```

**注意：**
- Security Analytics 检测当前为 MVP 版本，需要手动配置 detector
- 主要功能是告警融合去重

---

### `deduplicate_findings() -> dict`

**这个函数是干什么的？**

将 Raw Findings（原始告警）合并成 Canonical Findings（规范告警）。

**工作原理：**
1. 从 `raw-findings-*` 索引读取所有告警
2. 根据指纹算法识别相似的告警（相同攻击、相同主机、相同实体、相同时间窗口）
3. 将相似的告警合并成一条 Canonical Finding
4. 写入到 `canonical-findings-*` 索引

**为什么需要这个？**

- 同一个攻击可能被多个检测引擎发现，产生多个告警
- 合并后减少告警数量，提高可读性
- 合并后的告警包含所有来源信息，更可靠

**指纹算法：**
```
指纹 = technique_id + host_id + entity_id + time_bucket
```
- `technique_id`: ATT&CK 技术 ID
- `host_id`: 主机 ID
- `entity_id`: 实体标识（进程、IP、文件哈希等）
- `time_bucket`: 时间桶（3 分钟窗口）

**返回值：**
```python
{
    "total": 10,        # Raw Findings 总数
    "merged": 8,        # 被合并的告警数
    "canonical": 5,     # 生成的 Canonical Findings 数量
    "errors": 0         # 错误数量
}
```

**示例：**

```python
from opensearch import deduplicate_findings

# 执行告警融合去重
result = deduplicate_findings()

print(f"原始告警: {result['total']}")
print(f"合并数: {result['merged']}")
print(f"规范告警: {result['canonical']}")
```

---

### `run_security_analytics() -> dict`

**这个函数是干什么的？**

触发 OpenSearch Security Analytics 检测（当前为 MVP 版本）。

**为什么需要这个？**

- Security Analytics 是 OpenSearch 的安全分析插件
- 可以从事件中检测异常并生成告警
- 当前版本需要手动配置 detector 和规则

**返回值：**
```python
{
    "success": True,
    "message": "Security Analytics 检测需要先配置 detector（当前为 MVP 版本）"
}
```

**示例：**

```python
from opensearch import run_security_analytics

# 运行 Security Analytics 检测
result = run_security_analytics()

if result["success"]:
    print("检测完成")
else:
    print(f"检测失败: {result['message']}")
```

**注意：**
- 当前为 MVP 版本，返回提示信息
- 未来版本将实现实际的 API 调用

---

## 索引映射

索引映射定义了索引中每个字段的类型和属性。就像数据库表的结构定义。

### `ecs_events_mapping`

ECS Events 索引的字段映射，用于存储普通事件数据。

**主要字段：**
- `@timestamp`: 日期时间
- `event.id`: 事件 ID（关键词）
- `event.kind`: 事件类型（关键词）
- `host.id`, `host.name`: 主机信息
- `user.id`, `user.name`: 用户信息
- `process.*`: 进程信息
- `source.ip`, `destination.ip`: 网络信息
- `file.path`, `file.hash.sha256`: 文件信息

**使用场景：**
- 存储系统日志、审计日志等普通事件
- 用于后续的安全分析

---

### `raw_findings_mapping`

Raw Findings 索引的字段映射，用于存储原始告警。

**主要字段：**
- 包含 `ecs_events_mapping` 的所有字段
- `event.severity`: 严重程度（整数）
- `rule.*`: 规则信息
- `threat.tactic.*`, `threat.technique.*`: ATT&CK 框架信息
- `custom.finding.*`: 自定义告警信息

**使用场景：**
- 存储从各种检测引擎（Wazuh、Falco、Suricata 等）产生的原始告警
- 作为告警融合去重的输入

---

### `canonical_findings_mapping`

Canonical Findings 索引的字段映射，用于存储规范化的告警。

**主要字段：**
- 包含 `raw_findings_mapping` 的所有字段
- `custom.finding.fingerprint`: 告警指纹
- `custom.finding.providers`: 来源引擎列表
- `custom.evidence.event_ids`: 证据事件 ID 列表

**使用场景：**
- 存储合并后的规范告警
- 用于最终的安全分析和展示

---

### `attack_chains_mapping`

Attack Chains 索引的字段映射，用于存储攻击链信息。

**主要字段：**
- `chain.id`: 攻击链 ID
- `chain.start_ts`, `chain.end_ts`: 开始和结束时间
- `chain.stages`: 攻击阶段（嵌套对象）
- `chain.key_path`: 关键路径（嵌套对象）
- `chain.similar_apts`: 相似 APT 组织（嵌套对象）

**使用场景：**
- 存储关联的攻击事件链
- 用于攻击路径分析和 APT 关联分析

---

### `client_registry_mapping`

Client Registry 索引的字段映射，用于存储客户端注册信息。

**主要字段：**
- `client.id`: 客户端 ID
- `client.listen_url`: 监听地址
- `client.version`: 客户端版本
- `client.host.*`: 客户端主机信息
- `client.capabilities.*`: 客户端能力（wazuh、falco 等）
- `client.token_hash`: Token 哈希
- `poll.*`: 轮询状态信息

**使用场景：**
- 存储已注册的客户端信息
- 用于客户端管理和状态跟踪

---

## 📝 使用建议

### 1. 存储数据

**推荐使用 `store_events()`**，它会自动处理路由和去重：

```python
from opensearch import store_events

events = [...]  # 你的事件列表
result = store_events(events)
```

### 2. 查询数据

**使用 `search()`** 进行各种查询：

```python
from opensearch import search, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
results = search(index_name, {"match_all": {}}, size=100)
```

### 3. 初始化

**在应用启动时调用一次**：

```python
from opensearch import initialize_indices

initialize_indices()
```

### 4. 数据分析

**定期执行数据分析**：

```python
from opensearch import run_data_analysis

# 可以放在定时任务中
result = run_data_analysis()
```

---

## 🔗 相关文档

- [测试指南](../TEST_OPENSEARCH.md) - 如何测试各个功能
- [README](./README.md) - 模块概述和快速开始
