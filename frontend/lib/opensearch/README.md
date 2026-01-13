# OpenSearch 模块

## 📁 文件结构

```
lib/opensearch/
├── index.ts          # 统一对外接口（唯一导入入口）
├── client.ts         # 客户端配置和基础操作
├── storage.ts        # 存储功能（数据路由、批量存储）
├── analysis.ts       # 数据分析功能（检测和去重）
├── mappings.ts       # 索引映射定义
└── README.md         # 本文件
```

## 🎯 快速开始

### 标准导入

```typescript
import {
  // 存储功能
  storeEvents,
  
  // 数据分析
  runDataAnalysis,
  
  // 查询功能
  searchDocuments,
  getDocument,
  
  // 索引管理
  INDEX_PATTERNS,
  getIndexName,
  initializeIndices,
} from '@/lib/opensearch';
```

## 📚 核心功能

### 1. 存储事件（自动路由）

```typescript
import { storeEvents } from '@/lib/opensearch';

const result = await storeEvents([
  { event: { kind: 'event', id: 'evt-1', ... }, ... },
  { event: { kind: 'alert', dataset: 'finding.raw', ... }, ... },
]);

// 自动路由到对应索引：
// - event.kind='event' → ecs-events-*
// - event.kind='alert' + dataset='finding.raw' → raw-findings-*
// - event.kind='alert' + dataset='finding.canonical' → canonical-findings-*
```

### 2. 数据分析

```typescript
import { runDataAnalysis } from '@/lib/opensearch';

// 执行数据分析（检测 + 去重）
const result = await runDataAnalysis();
// {
//   detection: { success, message },
//   deduplication: { total, merged, canonical, errors }
// }
```

API 接口：`POST /api/v1/analysis/run`

### 3. 查询数据

```typescript
import { searchDocuments, getIndexName, INDEX_PATTERNS } from '@/lib/opensearch';

const indexName = getIndexName(INDEX_PATTERNS.ECS_EVENTS);
const results = await searchDocuments(indexName, { match_all: {} }, 100);
```

### 4. 初始化索引

```typescript
import { initializeIndices } from '@/lib/opensearch';

await initializeIndices(); // 自动创建所有需要的索引
```

## 📋 索引常量

```typescript
INDEX_PATTERNS.ECS_EVENTS          // 'ecs-events'
INDEX_PATTERNS.RAW_FINDINGS         // 'raw-findings'
INDEX_PATTERNS.CANONICAL_FINDINGS   // 'canonical-findings'
INDEX_PATTERNS.ATTACK_CHAINS        // 'attack-chains'
INDEX_PATTERNS.CLIENT_REGISTRY       // 'client-registry'
```

## ⚠️ 重要提示

1. **统一导入**：只从 `@/lib/opensearch` 导入，不要直接导入内部文件
2. **自动路由**：`storeEvents` 会根据 `event.kind` 和 `event.dataset` 自动路由
3. **数据分析**：使用 `runDataAnalysis()` 或 `/api/v1/analysis/run` API 接口

## 📖 详细文档

- **数据分析功能**：见 `ANALYSIS.md`
- **API 接口**：`POST /api/v1/events/store`、`POST /api/v1/analysis/run`
