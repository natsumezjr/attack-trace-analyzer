// OpenSearch 存储相关功能（数据路由、批量存储）

import { bulkIndex } from './client';
import { INDEX_PATTERNS, getIndexName } from './index';

// 根据event.kind和event.dataset路由到对应索引
export function routeToIndex(item: any): string {
  const kind = item.event?.kind;
  const dataset = item.event?.dataset || '';
  
  const today = new Date();
  
  if (kind === 'event') {
    // Telemetry -> ecs-events-*
    return getIndexName(INDEX_PATTERNS.ECS_EVENTS, today);
  } else if (kind === 'alert') {
    if (dataset === 'finding.canonical') {
      // Canonical Findings -> canonical-findings-*
      return getIndexName(INDEX_PATTERNS.CANONICAL_FINDINGS, today);
    } else {
      // Raw Findings -> raw-findings-*
      return getIndexName(INDEX_PATTERNS.RAW_FINDINGS, today);
    }
  }
  
  // 默认路由到ecs-events
  return getIndexName(INDEX_PATTERNS.ECS_EVENTS, today);
}

// 存储数据到OpenSearch（自动路由到对应索引）
export async function storeEvents(events: any[]): Promise<{
  total: number;
  success: number;
  failed: number;
  details: Record<string, { success: number; failed: number }>;
}> {
  if (events.length === 0) {
    return { total: 0, success: 0, failed: 0, details: {} };
  }
  
  // 按索引分组
  const indexGroups: Record<string, Array<{ id?: string; document: any }>> = {};
  
  for (const event of events) {
    const indexName = routeToIndex(event);
    if (!indexGroups[indexName]) {
      indexGroups[indexName] = [];
    }
    indexGroups[indexName].push({
      id: event['event.id'] || event.event?.id,
      document: event,
    });
  }
  
  // 批量写入每个索引
  const details: Record<string, { success: number; failed: number }> = {};
  let totalSuccess = 0;
  let totalFailed = 0;
  
  for (const [indexName, documents] of Object.entries(indexGroups)) {
    try {
      const result = await bulkIndex(indexName, documents);
      details[indexName] = {
        success: result.success,
        failed: result.failed,
      };
      totalSuccess += result.success;
      totalFailed += result.failed;
    } catch (error) {
      console.error(`存储到索引 ${indexName} 失败:`, error);
      details[indexName] = {
        success: 0,
        failed: documents.length,
      };
      totalFailed += documents.length;
    }
  }
  
  return {
    total: events.length,
    success: totalSuccess,
    failed: totalFailed,
    details,
  };
}
