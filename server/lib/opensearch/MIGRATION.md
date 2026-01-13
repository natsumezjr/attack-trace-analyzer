# OpenSearch 模块重构说明

## 📁 新的文件结构

```
lib/opensearch/
├── index.ts          # 统一对外接口（唯一导入入口）
├── client.ts         # 客户端配置和基础操作
├── storage.ts        # 存储功能（数据路由、批量存储）
├── mappings.ts       # 索引映射定义
├── README.md         # 使用文档
└── MIGRATION.md      # 本文件
```

## 🔄 迁移指南

### 旧的导入方式（已废弃）

```typescript
// ❌ 不要这样导入（旧文件已删除）
import { storeEvents } from '@/lib/opensearch';
import { getOpenSearchClient } from '@/lib/opensearch';
```

### 新的导入方式（推荐）

```typescript
// ✅ 统一从 index.ts 导入
import {
  storeEvents,
  getOpenSearchClient,
  searchDocuments,
  initializeIndices,
  INDEX_PATTERNS,
  getIndexName,
} from '@/lib/opensearch';
```

## ✅ 向后兼容

所有旧的导入路径仍然有效，因为 `index.ts` 会重新导出所有函数。

## 📝 标准接口列表

### 存储功能
- `storeEvents(events)` - 存储事件（自动路由）

### 客户端操作
- `getOpenSearchClient()` - 获取客户端实例
- `searchDocuments(indexName, query, size)` - 查询文档
- `getDocument(indexName, id)` - 根据ID获取文档
- `indexDocument(indexName, document, id?)` - 写入单个文档
- `updateDocument(indexName, id, document)` - 更新文档
- `bulkIndex(indexName, documents)` - 批量写入
- `ensureIndex(indexName, mapping)` - 创建索引
- `indexExists(indexName)` - 检查索引是否存在

### 工具函数
- `INDEX_PATTERNS` - 索引名称常量
- `getIndexName(pattern, date?)` - 生成索引名
- `hashToken(token)` - 生成token哈希
- `routeToIndex(item)` - 数据路由函数

### 初始化
- `initializeIndices()` - 初始化所有索引

### 索引映射
- `ecsEventsMapping`
- `rawFindingsMapping`
- `canonicalFindingsMapping`
- `attackChainsMapping`
- `clientRegistryMapping`

## 🎯 使用示例

### 存储数据

```typescript
import { storeEvents } from '@/lib/opensearch';

const result = await storeEvents([
  { event: { kind: 'event', id: 'evt-1', ... }, ... },
]);
```

### 查询数据

```typescript
import { searchDocuments, getIndexName, INDEX_PATTERNS } from '@/lib/opensearch';

const indexName = getIndexName(INDEX_PATTERNS.ECS_EVENTS);
const results = await searchDocuments(indexName, {
  query: { match_all: {} },
  size: 10
});
```

### 初始化

```typescript
import { initializeIndices } from '@/lib/opensearch';

await initializeIndices();
```
