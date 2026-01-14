# OpenSearch 模块测试指南

## 测试进度

**总体进度：70%** (7/10 步骤完成)

---

## 测试环境准备

### 前置条件检查清单

- [ ] OpenSearch 服务运行中
- [ ] 环境变量配置正确（`OPENSEARCH_NODE`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD`）
- [ ] Python 环境已安装依赖（`opensearch-py`）
- [ ] 工作目录：`backend`（所有命令都在 backend 目录下执行）

---

## 测试步骤

### 步骤 1：连接测试 (10%)

**目标**：验证 OpenSearch 连接是否正常

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.client import get_client
client = get_client()
print('连接成功:', client.info())
EOF
```

**预期结果**：
- 输出 OpenSearch 集群信息（版本号、集群名称等）
- 无连接错误

**验证**：
- [x] 连接成功
- [x] 能看到集群信息

**完成状态**：✅ 已完成
- 集群名称：docker-cluster
- OpenSearch 版本：3.4.0
- 节点名称：92842f35254f

---

### 步骤 2：索引初始化 (20%)

**目标**：创建所有必需的索引

**指令**（推荐 - 使用测试脚本）：
```powershell
cd backend/app/services/opensearch/scripts
uv run python test_step2_init_indices.py
```

或者从 backend 目录：
```powershell
cd backend
uv run python -m app.services.opensearch.scripts.test_step2_init_indices
```

**指令**（PowerShell - 内联方式）：
```powershell
cd backend
@"
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.index import initialize_indices
initialize_indices()
"@ | uv run python
```

**指令**（Bash/Linux）：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.index import initialize_indices
initialize_indices()
EOF
```

**预期结果**：
- 输出 "所有索引初始化完成"
- 创建以下索引：
  - `ecs-events-YYYY-MM-DD`（今日日期）
  - `raw-findings-YYYY-MM-DD`
  - `canonical-findings-YYYY-MM-DD`
  - `client-registry`

**验证**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.client import get_client
from app.services.opensearch.index import INDEX_PATTERNS, get_index_name
from datetime import datetime
client = get_client()
today = datetime.now()
indices = [
    get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today),
    get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today),
    get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], today),
    INDEX_PATTERNS['CLIENT_REGISTRY']
]
for idx in indices:
    exists = client.indices.exists(idx)
    print(f'{idx}: {"存在" if exists else "不存在"}')
EOF
```

**完成状态**：✅ 已完成
- 已创建索引：
  - `ecs-events-2026-01-14`
  - `raw-findings-2026-01-14`
  - `canonical-findings-2026-01-14`
  - `attack-chains-2026-01-14`
  - `client-registry`（如果已创建）

---

### 步骤 3：数据写入测试 (30%)

**目标**：测试 Telemetry 数据写入和路由

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.storage import store_events
from datetime import datetime, timezone

# 创建测试 Telemetry 数据
test_event = {
    "ecs": {"version": "9.2.0"},
    "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "event": {
        "id": "test-evt-001",
        "kind": "event",
        "dataset": "hostlog.auth",
        "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "category": ["authentication"],
        "action": "user_login"
    },
    "host": {"id": "h-test-001", "name": "test-host"},
    "user": {"name": "testuser"},
    "source": {"ip": "192.168.1.100"},
    "message": "Test authentication event"
}

result = store_events([test_event])
print("写入结果:", result)
print(f"成功: {result['success']}, 失败: {result['failed']}, 重复: {result['duplicated']}")
EOF
```

**预期结果**：
- `success: 1`
- `failed: 0`
- `duplicated: 0`
- 数据写入到 `ecs-events-YYYY-MM-DD` 索引

**验证**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.client import get_client
from app.services.opensearch.index import INDEX_PATTERNS, get_index_name
from datetime import datetime
client = get_client()
today = datetime.now()
index_name = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
doc = client.get(index=index_name, id='test-evt-001')
print('文档内容:', doc['_source']['event']['id'])
EOF
```

**完成状态**：✅ 已完成
- 写入结果：成功 1，失败 0，重复 0
- 数据已成功写入到 `ecs-events-2026-01-14` 索引
- 文档 ID：`test-evt-001`

---

### 步骤 4：路由规则测试 (40%)

**目标**：验证不同 event.kind 和 event.dataset 的路由是否正确

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.storage import store_events, route_to_index
from datetime import datetime, timezone

# 测试1: Telemetry (event.kind="event")
telemetry = {
    "event": {"kind": "event", "dataset": "hostlog.process"},
    "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
}
route1 = route_to_index(telemetry)
print(f"Telemetry 路由: {route1}")

# 测试2: Raw Finding (event.kind="alert", dataset != "finding.canonical")
raw_finding = {
    "event": {"kind": "alert", "dataset": "finding.raw.falco"},
    "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
}
route2 = route_to_index(raw_finding)
print(f"Raw Finding 路由: {route2}")

# 测试3: Canonical Finding (event.kind="alert", dataset="finding.canonical")
canonical_finding = {
    "event": {"kind": "alert", "dataset": "finding.canonical"},
    "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
}
route3 = route_to_index(canonical_finding)
print(f"Canonical Finding 路由: {route3}")

print("\n路由测试完成")
EOF
```

**预期结果**：
- Telemetry → `ecs-events-YYYY-MM-DD`
- Raw Finding → `raw-findings-YYYY-MM-DD`
- Canonical Finding → `canonical-findings-YYYY-MM-DD`

**完成状态**：✅ 已完成
- Telemetry 路由：`ecs-events-2026-01-14` ✓
- Raw Finding 路由：`raw-findings-2026-01-14` ✓
- Canonical Finding 路由：`canonical-findings-2026-01-14` ✓
- 所有路由规则测试通过

---

### 步骤 5：三时间字段处理测试 (50%)

**目标**：验证三时间字段（@timestamp, event.created, event.ingested）的处理逻辑

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.storage import store_events
from datetime import datetime, timezone

# 测试：缺失 event.created，应该回填为 @timestamp
test_event = {
    "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "event": {
        "id": "test-time-001",
        "kind": "event",
        "dataset": "hostlog.auth"
        # 故意不写 created
    },
    "host": {"id": "h-test-001", "name": "test-host"},
    "message": "Test time fields"
}

result = store_events([test_event])
print("写入结果:", result)

# 验证三时间字段
from app.services.opensearch.client import get_client
from app.services.opensearch.index import INDEX_PATTERNS, get_index_name
from datetime import datetime as dt
client = get_client()
today = dt.now()
index_name = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
doc = client.get(index=index_name, id='test-time-001')['_source']

print("\n三时间字段验证:")
print(f"@timestamp: {doc.get('@timestamp')}")
print(f"event.created: {doc.get('event', {}).get('created')}")
print(f"event.ingested: {doc.get('event', {}).get('ingested')}")
print(f"\n验证: event.created 应该等于 @timestamp: {doc.get('event', {}).get('created') == doc.get('@timestamp')}")
EOF
```

**预期结果**：
- `@timestamp` 存在
- `event.created` 存在且等于 `@timestamp`
- `event.ingested` 存在且为当前时间

**完成状态**：✅ 已完成
- ✓ @timestamp 存在
- ✓ event.created 存在且等于 @timestamp（自动回填）
- ✓ event.ingested 存在
- 三时间字段处理逻辑正确

---

### 步骤 6：幂等去重测试 (60%)

**目标**：验证相同 event.id 的重复写入会被去重

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.storage import store_events
from datetime import datetime, timezone

# 创建相同 event.id 的两个事件
event1 = {
    "ecs": {"version": "9.2.0"},
    "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "event": {
        "id": "test-dup-001",
        "kind": "event",
        "dataset": "hostlog.auth",
        "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    },
    "host": {"id": "h-test-001", "name": "test-host"},
    "message": "First write"
}

event2 = {
    "ecs": {"version": "9.2.0"},
    "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "event": {
        "id": "test-dup-001",  # 相同的 ID
        "kind": "event",
        "dataset": "hostlog.auth",
        "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    },
    "host": {"id": "h-test-001", "name": "test-host"},
    "message": "Second write (should be deduplicated)"
}

# 第一次写入
result1 = store_events([event1])
print("第一次写入:", result1)

# 第二次写入（应该被去重）
result2 = store_events([event2])
print("第二次写入:", result2)

print(f"\n验证: 第二次写入应该被去重")
print(f"  success: {result2['success']} (应该是0)")
print(f"  duplicated: {result2['duplicated']} (应该是1)")
EOF
```

**预期结果**：
- 第一次写入：`success: 1, duplicated: 0`
- 第二次写入：`success: 0, duplicated: 1`

**完成状态**：✅ 已完成
- 第一次写入：成功 1，重复 0 ✓
- 第二次写入：成功 0，重复 1 ✓
- 幂等去重功能正常

---

### 步骤 7：Security Analytics 检测测试 (70%)

**目标**：验证 Security Analytics 检测功能是否正常

**前置条件**：
- 确保有测试数据在 `ecs-events-*` 索引中
- Security Analytics detector 已配置

**说明**：
- 默认只查询已有findings（快速验证API功能）
- 使用 `--trigger-scan` 参数可以触发新扫描（完整测试，需要等待扫描完成）
- 如果已有findings，默认方式即可验证功能；如果没有findings，建议使用 `--trigger-scan` 触发扫描

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.analysis import run_security_analytics

print("=" * 60)
print("Security Analytics 检测测试")
print("=" * 60)

# 运行检测（不触发新扫描，只查询已有findings）
result = run_security_analytics(trigger_scan=False)

print("\n检测结果:")
print(f"  成功: {result['success']}")
print(f"  Findings总数: {result['findings_count']}")
print(f"  新Findings: {result.get('new_findings_count', 0)}")
print(f"  存储成功: {result['stored']}")
print(f"  来源: {result['source']}")

if result['findings_count'] > 0:
    print("\n✓ 检测功能正常")
else:
    print("\n⚠ 没有findings，可能需要:")
    print("  1. 确保有测试数据")
    print("  2. 运行 force_scan=True 强制触发新扫描")
EOF
```

**预期结果**：
- `success: True`
- 能看到 findings 数量或提示信息

**完成状态**：✅ 已完成
- 发现已有findings: 36个
- 最新finding时间戳: 1768306851443（955.5分钟前）
- 成功查询并存储36个findings到raw-findings索引
- 检测功能正常

**说明**：
- 已有findings说明之前Security Analytics已经执行过扫描（可能是schedule自动触发）
- 这些findings被成功转换为ECS格式并存储到raw-findings索引

---

### 步骤 8：手动触发 Workflow 测试 (80%)

**目标**：验证手动触发 workflow 的功能

**注意（重要）**：
- 在部分 OpenSearch 版本/配置中（例如 3.x），Security Analytics 的 workflow execute 可能会触发 Alerting 读取系统索引，
  进而报错：`alerting_exception ... indices:data/read/get[s]`。
- 这类报错即使使用 `admin` + `all_access` 也可能发生，更像是系统索引/插件内部限制，并不一定代表账号权限配置错误。
- 推荐优先使用步骤 7/10 的 schedule 触发路径（`run_security_analytics(force_scan=True)`），它不依赖 workflow execute。
  如确实要验证 execute，可设置环境变量：`OPENSEARCH_SA_PREFER_WORKFLOW_EXECUTE=1`。

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.analysis import _get_detector_id, _get_workflow_id_for_detector, _execute_workflow_manually
from app.services.opensearch.client import get_client
import time

client = get_client()

# 获取 detector ID
detector_id = _get_detector_id(client)
print(f"Detector ID: {detector_id}")

if detector_id:
    # 获取 workflow ID
    workflow_id = _get_workflow_id_for_detector(client, detector_id)
    print(f"Workflow ID: {workflow_id}")
    
    if workflow_id:
        # 手动触发 workflow
        print("\n手动触发 workflow...")
        success = _execute_workflow_manually(client, workflow_id)
        
        if success:
            print("✓ Workflow 触发成功")
            print("等待5秒让扫描完成...")
            time.sleep(5)
            
            # 查询 findings
            from app.services.opensearch.analysis import _get_latest_findings_timestamp
            timestamp_ms, count = _get_latest_findings_timestamp(client, detector_id)
            print(f"\n当前 Findings: {count} 个")
            if timestamp_ms > 0:
                print(f"最新 Finding 时间戳: {timestamp_ms}")
        else:
            print("✗ Workflow 触发失败")
    else:
        print("✗ 未找到 workflow ID")
else:
    print("✗ 未找到 detector ID")
EOF
```

**预期结果**：
- 成功获取 detector ID 和 workflow ID
- Workflow 触发成功
- 能看到 findings 数量

**完成状态**：⏳ 待测试

---

### 步骤 9：告警融合去重测试 (90%)

**目标**：验证 Raw Findings → Canonical Findings 的融合去重功能

**前置条件**：
- 需要有 Raw Findings 数据

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.analysis import deduplicate_findings

print("=" * 60)
print("告警融合去重测试")
print("=" * 60)

result = deduplicate_findings()

print("\n融合结果:")
print(f"  Raw Findings总数: {result['total']}")
print(f"  合并的Findings: {result['merged']}")
print(f"  生成的Canonical Findings: {result['canonical']}")
print(f"  错误数: {result['errors']}")

if result['canonical'] > 0:
    print("\n✓ 融合去重功能正常")
else:
    print("\n⚠ 没有生成 Canonical Findings")
    print("  可能原因: 没有 Raw Findings 或所有 Findings 都是唯一的")
EOF
```

**预期结果**：
- 能看到融合统计信息
- 如果有多个相同指纹的 Raw Findings，应该合并为 1 个 Canonical Finding

**完成状态**：⏳ 待测试

---

### 步骤 10：完整流程测试 (100%)

**目标**：测试完整的数据分析流程（检测 + 融合）

**指令**：
```bash
cd backend
uv run python << 'EOF'
import sys
sys.path.insert(0, 'app')
from app.services.opensearch.analysis import run_data_analysis

print("=" * 60)
print("完整数据分析流程测试")
print("=" * 60)

# 运行完整流程（检测 + 融合）
result = run_data_analysis(force_scan=True)

print("\n检测阶段结果:")
detection = result['detection']
print(f"  成功: {detection['success']}")
print(f"  Findings总数: {detection['findings_count']}")
print(f"  存储成功: {detection['stored']}")
print(f"  扫描触发: {detection['scan_requested']}")
print(f"  扫描完成: {detection['scan_completed']}")

print("\n融合阶段结果:")
dedup = result['deduplication']
print(f"  Raw Findings总数: {dedup['total']}")
print(f"  生成的Canonical Findings: {dedup['canonical']}")

print("\n" + "=" * 60)
if detection['success'] and dedup['canonical'] >= 0:
    print("✓ 完整流程测试通过")
else:
    print("⚠ 部分功能可能有问题，请检查上述输出")
print("=" * 60)
EOF
```

**预期结果**：
- 检测阶段成功
- 融合阶段成功
- 能看到完整的统计信息

**完成状态**：⏳ 待测试

---

## 测试完成检查清单

- [ ] 所有索引正常创建
- [ ] 数据写入和路由正常
- [ ] 三时间字段处理正确
- [ ] 幂等去重功能正常
- [ ] Security Analytics 检测正常
- [ ] 手动触发 workflow 正常
- [ ] 告警融合去重正常
- [ ] 完整流程测试通过

---

## 常见问题排查

### 连接失败
- 检查 OpenSearch 服务是否运行：`docker ps | grep opensearch`
- 检查环境变量：`echo $OPENSEARCH_NODE`
- 检查网络连接：`curl -k https://localhost:9200`

### 索引创建失败
- 检查权限：确保用户有创建索引的权限
- 检查索引名格式：确保日期格式为 `YYYY-MM-DD`

### Security Analytics 检测无结果
- 检查 detector 是否启用
- 检查是否有测试数据
- 检查规则是否匹配数据

### Workflow 触发失败
- 检查 workflow ID 是否正确
- 检查 Alerting 插件是否启用
- 查看 OpenSearch 日志

---

## 更新日志

- 2026-01-XX: 创建测试指南
