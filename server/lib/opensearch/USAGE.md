# OpenSearch 模块使用指南

## 🎯 快速开始

### 1. 导入（统一入口）

```typescript
import {
  // 核心功能
  storeEvents,
  initializeIndices,
  
  // 查询功能
  searchDocuments,
  getDocument,
  
  // 索引管理
  INDEX_PATTERNS,
  getIndexName,
  ensureIndex,
  
  // 工具函数
  hashToken,
} from '@/lib/opensearch';
```

## 📚 核心接口说明

### 存储数据（最常用）

```typescript
import { storeEvents } from '@/lib/opensearch';

// 存储事件数组（自动路由到对应索引）
const result = await storeEvents([
  {
    event: {
      id: 'evt-1',
      kind: 'event',  // 或 'alert'
      dataset: 'hostlog.auth',  // 或 'finding.raw', 'finding.canonical'
    },
    // ... 其他字段
  },
]);

// 返回：
// {
//   total: 1,
//   success: 1,
//   failed: 0,
//   details: {
//     'ecs-events-2026.01.13': { success: 1, failed: 0 }
//   }
// }
```

### 查询数据

```typescript
import { searchDocuments, getIndexName, INDEX_PATTERNS } from '@/lib/opensearch';

// 查询所有事件
const indexName = getIndexName(INDEX_PATTERNS.ECS_EVENTS);
const events = await searchDocuments(indexName, {
  query: { match_all: {} },
  size: 10
});

// 根据条件查询
const results = await searchDocuments(indexName, {
  query: {
    term: { 'event.id': 'evt-123' }
  }
});
```

### 初始化索引

```typescript
import { initializeIndices } from '@/lib/opensearch';

// 在应用启动时调用
await initializeIndices();
```

## 🔄 轮询器使用示例

```typescript
import { storeEvents } from '@/lib/opensearch';

async function pollClient(clientId: string, listenUrl: string, token: string) {
  // 1. 从客户端拉取数据
  const response = await fetch(`${listenUrl}/api/v1/pull`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      cursor: '0',
      limit: 500,
    }),
  });
  
  const data = await response.json();
  
  // 2. 存储到 OpenSearch（自动路由）
  if (data.items && data.items.length > 0) {
    const result = await storeEvents(data.items);
    console.log(`存储完成: ${result.success}/${result.total}`);
  }
  
  // 3. 更新 cursor
  // ...
}
```

## 📋 索引常量

```typescript
import { INDEX_PATTERNS } from '@/lib/opensearch';

// 可用的索引模式
INDEX_PATTERNS.ECS_EVENTS          // 'ecs-events'
INDEX_PATTERNS.RAW_FINDINGS         // 'raw-findings'
INDEX_PATTERNS.CANONICAL_FINDINGS   // 'canonical-findings'
INDEX_PATTERNS.ATTACK_CHAINS        // 'attack-chains'
INDEX_PATTERNS.CLIENT_REGISTRY       // 'client-registry'
```

## ⚠️ 注意事项

1. **统一导入**：只从 `@/lib/opensearch` 导入，不要直接导入内部文件
2. **自动路由**：`storeEvents` 会自动根据数据类型路由到正确索引
3. **索引初始化**：首次使用前需要调用 `initializeIndices()`
