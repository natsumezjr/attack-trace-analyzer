# OpenSearch 模块

## 📁 文件结构

```
lib/opensearch/
├── index.ts          # 统一对外接口（唯一导入入口）
├── client.ts         # 客户端配置和基础操作
├── storage.ts        # 存储功能（数据路由、批量存储）
├── mappings.ts       # 索引映射定义
└── README.md         # 本文件
```

## 🎯 使用方式

### 标准导入（推荐）

```typescript
// 只从这个文件导入
import {
  // 存储功能
  storeEvents,
  
  // 索引常量
  INDEX_PATTERNS,
  getIndexName,
  
  // 客户端操作
  search,
  getDocument,
  ensureIndex,
  
  // 初始化
  initializeIndices,
} from '@/lib/opensearch';
```

### 核心接口说明

#### 1. 存储事件（自动路由）

```typescript
import { storeEvents } from '@/lib/opensearch';

const result = await storeEvents([
  { event: { kind: 'event', id: 'evt-1', ... }, ... },
  { event: { kind: 'alert', dataset: 'finding.raw', ... }, ... },
]);

// 返回：
// {
//   total: 2,
//   success: 2,
//   failed: 0,
//   details: {
//     'ecs-events-2026.01.13': { success: 1, failed: 0 },
//     'raw-findings-2026.01.13': { success: 1, failed: 0 }
//   }
// }
```

#### 2. 查询数据

```typescript
import { search, getIndexName, INDEX_PATTERNS } from '@/lib/opensearch';

const indexName = getIndexName(INDEX_PATTERNS.ECS_EVENTS);
const results = await search(indexName, {
  query: { match_all: {} },
  size: 10
});
```

#### 3. 初始化索引

```typescript
import { initializeIndices } from '@/lib/opensearch';

await initializeIndices(); // 自动创建所有需要的索引
```

## 🔧 内部实现

- **client.ts**：OpenSearch 客户端连接、基础 CRUD 操作
- **storage.ts**：数据路由逻辑、批量存储
- **mappings.ts**：索引字段定义
- **index.ts**：统一导出，提供标准接口

## ⚠️ 重要提示

**外部代码应该只从 `index.ts` 导入**，不要直接导入 `client.ts`、`storage.ts` 等内部文件。

这样可以：
- 保持接口稳定
- 方便后续重构
- 统一管理依赖
