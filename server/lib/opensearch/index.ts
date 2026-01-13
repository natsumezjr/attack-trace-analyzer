// OpenSearch 统一对外接口
// 这是唯一应该被外部代码导入的文件

// ========== 索引常量 ==========
export const INDEX_PATTERNS = {
  ECS_EVENTS: 'ecs-events',
  RAW_FINDINGS: 'raw-findings',
  CANONICAL_FINDINGS: 'canonical-findings',
  ATTACK_CHAINS: 'attack-chains',
  CLIENT_REGISTRY: 'client-registry',
} as const;

// ========== 工具函数 ==========
import { createHash } from 'crypto';

// 生成带日期的索引名（用于时间序列索引）
export function getIndexName(pattern: string, date?: Date): string {
  const dateStr = (date || new Date()).toISOString().split('T')[0].replace(/-/g, '.');
  return `${pattern}-${dateStr}`;
}

// 生成token哈希
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ========== 存储功能（核心接口）==========
export { storeEvents, routeToIndex } from './storage';

// ========== 客户端操作 ==========
export {
  getClient,
  indexExists,
  ensureIndex,
  search,
  getDocument,
  updateDocument,
  indexDocument,
  bulkIndex,
} from './client';

// 向后兼容：导出旧函数名
export { getClient as getOpenSearchClient } from './client';
export { search as searchDocuments } from './client';

// ========== 索引映射 ==========
export {
  ecsEventsMapping,
  rawFindingsMapping,
  canonicalFindingsMapping,
  attackChainsMapping,
  clientRegistryMapping,
} from './mappings';

// ========== 初始化 ==========
import { ensureIndex } from './client';
import {
  ecsEventsMapping,
  rawFindingsMapping,
  canonicalFindingsMapping,
  attackChainsMapping,
  clientRegistryMapping,
} from './mappings';

export async function initializeIndices(): Promise<void> {
  const today = new Date();
  
  // 创建今日索引
  await ensureIndex(
    getIndexName(INDEX_PATTERNS.ECS_EVENTS, today),
    ecsEventsMapping
  );
  
  await ensureIndex(
    getIndexName(INDEX_PATTERNS.RAW_FINDINGS, today),
    rawFindingsMapping
  );
  
  await ensureIndex(
    getIndexName(INDEX_PATTERNS.CANONICAL_FINDINGS, today),
    canonicalFindingsMapping
  );
  
  await ensureIndex(
    getIndexName(INDEX_PATTERNS.ATTACK_CHAINS, today),
    attackChainsMapping
  );
  
  // Client Registry不需要日期后缀
  await ensureIndex(INDEX_PATTERNS.CLIENT_REGISTRY, clientRegistryMapping);
  
  console.log('所有索引初始化完成');
}
