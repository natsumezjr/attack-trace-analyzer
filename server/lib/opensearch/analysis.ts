// OpenSearch 数据分析模块
// 包含 Security Analytics 检测调用和告警融合去重

import { createHash } from 'crypto';
import { getClient, search, bulkIndex } from './client';
import { INDEX_PATTERNS, getIndexName } from './index';

// 时间窗口（分钟），用于时间桶计算
const TIME_WINDOW_MINUTES = 3; // 实验规模小，建议偏小（1-5分钟）

/**
 * 生成告警指纹
 * 指纹 = technique_id + host + (process_entity_id | dst_ip/domain | file_hash) + time_bucket
 */
function generateFingerprint(finding: any): string {
  const techniqueId = finding.threat?.technique?.id || finding['threat.technique.id'] || 'unknown';
  const hostId = finding.host?.id || finding['host.id'] || 'unknown';
  
  // 实体标识符（优先级：process_entity_id > dst_ip/domain > file_hash）
  let entityId = 'unknown';
  if (finding.process?.entity_id || finding['process.entity_id']) {
    entityId = finding.process?.entity_id || finding['process.entity_id'];
  } else if (finding.destination?.ip || finding['destination.ip']) {
    entityId = finding.destination?.ip || finding['destination.ip'];
    if (finding.destination?.domain || finding['destination.domain']) {
      entityId += '|' + (finding.destination?.domain || finding['destination.domain']);
    }
  } else if (finding.file?.hash?.sha256 || finding['file.hash.sha256']) {
    entityId = finding.file?.hash?.sha256 || finding['file.hash.sha256'];
  }
  
  // 时间桶计算：time_bucket = floor(@timestamp / Δt)
  const timestamp = finding['@timestamp'] || finding.event?.created || new Date().toISOString();
  const timestampMs = new Date(timestamp).getTime();
  const timeBucketMs = TIME_WINDOW_MINUTES * 60 * 1000; // 转换为毫秒
  const timeBucket = Math.floor(timestampMs / timeBucketMs);
  
  return `${techniqueId}|${hostId}|${entityId}|${timeBucket}`;
}

/**
 * 从 Raw Finding 提取 provider（来源引擎）
 */
function extractProvider(finding: any): string {
  // 如果已经有 custom.finding.providers，取第一个
  if (finding.custom?.finding?.providers && Array.isArray(finding.custom.finding.providers) && finding.custom.finding.providers.length > 0) {
    return finding.custom.finding.providers[0];
  }
  
  // 根据规则来源推断
  const ruleId = finding.rule?.id || finding['rule.id'];
  if (ruleId) {
    if (ruleId.includes('wazuh') || ruleId.includes('wazuh')) return 'wazuh';
    if (ruleId.includes('falco')) return 'falco';
    if (ruleId.includes('suricata')) return 'suricata';
    if (ruleId.includes('sigma') || ruleId.includes('opensearch')) return 'opensearch-security-analytics';
  }
  
  return 'unknown';
}

/**
 * 合并多个 Raw Findings 为一条 Canonical Finding
 */
function mergeFindings(findings: any[]): any {
  if (findings.length === 0) {
    throw new Error('无法合并空数组');
  }
  
  // 使用第一个 finding 作为基础
  const base = JSON.parse(JSON.stringify(findings[0]));
  
  // 合并 providers
  const providers = new Set<string>();
  findings.forEach(f => {
    const provider = extractProvider(f);
    providers.add(provider);
    // 如果 finding 有 providers 数组，也添加进去
    if (f.custom?.finding?.providers && Array.isArray(f.custom.finding.providers)) {
      f.custom.finding.providers.forEach((p: string) => providers.add(p));
    }
  });
  
  // 合并 evidence.event_ids
  const eventIds = new Set<string>();
  findings.forEach(f => {
    if (f.event?.id) eventIds.add(f.event.id);
    if (f['event.id']) eventIds.add(f['event.id']);
    if (f.custom?.evidence?.event_ids && Array.isArray(f.custom.evidence.event_ids)) {
      f.custom.evidence.event_ids.forEach((id: string) => eventIds.add(id));
    }
  });
  
  // 合并 severity（取最大值）
  let maxSeverity = base.event?.severity || base['event.severity'] || 0;
  findings.forEach(f => {
    const severity = f.event?.severity || f['event.severity'] || 0;
    if (severity > maxSeverity) maxSeverity = severity;
  });
  
  // 构建 Canonical Finding
  if (!base.custom) base.custom = {};
  if (!base.custom.finding) base.custom.finding = {};
  
  base.custom.finding.stage = 'canonical';
  base.custom.finding.providers = Array.from(providers);
  
  if (!base.custom.evidence) base.custom.evidence = {};
  base.custom.evidence.event_ids = Array.from(eventIds);
  
  // 设置 severity
  if (base.event) {
    base.event.severity = maxSeverity;
  } else {
    base['event.severity'] = maxSeverity;
  }
  
  // 设置 dataset
  if (base.event) {
    base.event.dataset = 'finding.canonical';
    base.event.kind = 'alert';
  } else {
    base['event.dataset'] = 'finding.canonical';
    base['event.kind'] = 'alert';
  }
  
  // confidence 可按来源数量上调（来源越多，置信度越高）
  const confidence = Math.min(0.5 + (providers.size * 0.15), 1.0); // 基础 0.5，每个来源 +0.15，最高 1.0
  base.custom.confidence = confidence;
  
  // 生成新的 event.id（基于指纹）
  const fingerprint = generateFingerprint(base);
  const hash = createHash('sha256').update(fingerprint).digest('hex').substring(0, 16);
  base.event = base.event || {};
  base.event.id = `canonical-${hash}`;
  
  return base;
}

/**
 * 告警融合去重（Raw Findings → Canonical Findings）
 * 根据文档：在时间窗 Δt 内，将满足相同指纹的 Raw Finding 合并为一条 Canonical Finding
 */
export async function deduplicateFindings(): Promise<{
  total: number;
  merged: number;
  canonical: number;
  errors: number;
}> {
  const client = getClient();
  const today = new Date();
  const rawIndexName = getIndexName(INDEX_PATTERNS.RAW_FINDINGS, today);
  const canonicalIndexName = getIndexName(INDEX_PATTERNS.CANONICAL_FINDINGS, today);
  
  try {
    // 查询所有 Raw Findings
    const rawFindings = await search(
      rawIndexName,
      { match_all: {} },
      10000 // 可根据实际情况调整
    );
    
    if (rawFindings.length === 0) {
      return { total: 0, merged: 0, canonical: 0, errors: 0 };
    }
    
    // 按指纹分组
    const fingerprintGroups: Record<string, any[]> = {};
    rawFindings.forEach(finding => {
      const fingerprint = generateFingerprint(finding);
      if (!fingerprintGroups[fingerprint]) {
        fingerprintGroups[fingerprint] = [];
      }
      fingerprintGroups[fingerprint].push(finding);
    });
    
    // 合并每个分组
    const canonicalFindings: any[] = [];
    let mergedCount = 0;
    
    for (const [fingerprint, findings] of Object.entries(fingerprintGroups)) {
      if (findings.length > 1) {
        // 多个 findings 需要合并
        const merged = mergeFindings(findings);
        canonicalFindings.push(merged);
        mergedCount += findings.length;
      } else {
        // 单个 finding，直接转为 canonical（更新字段）
        const single = JSON.parse(JSON.stringify(findings[0]));
        if (!single.custom) single.custom = {};
        if (!single.custom.finding) single.custom.finding = {};
        single.custom.finding.stage = 'canonical';
        if (!single.custom.finding.providers) {
          single.custom.finding.providers = [extractProvider(single)];
        }
        
        if (single.event) {
          single.event.dataset = 'finding.canonical';
          single.event.kind = 'alert';
        } else {
          single['event.dataset'] = 'finding.canonical';
          single['event.kind'] = 'alert';
        }
        
        canonicalFindings.push(single);
      }
    }
    
    // 批量写入 Canonical Findings
    if (canonicalFindings.length > 0) {
      const documents = canonicalFindings.map(f => ({
        id: f.event?.id || f['event.id'],
        document: f,
      }));
      
      const result = await bulkIndex(canonicalIndexName, documents);
      
      return {
        total: rawFindings.length,
        merged: mergedCount,
        canonical: canonicalFindings.length,
        errors: result.failed || 0,
      };
    }
    
    return { total: rawFindings.length, merged: mergedCount, canonical: 0, errors: 0 };
  } catch (error) {
    console.error('告警融合去重失败:', error);
    throw error;
  }
}

/**
 * 触发 OpenSearch Security Analytics 检测
 * 注意：这需要 Security Analytics 插件已配置好 detector 和规则
 * 对于 MVP，可以先返回模拟结果或调用实际的 OSA API
 */
export async function runSecurityAnalytics(): Promise<{
  success: boolean;
  findingsCount?: number;
  message?: string;
}> {
  const client = getClient();
  
  try {
    // TODO: 实现实际的 OpenSearch Security Analytics API 调用
    // 1. 列出所有 detectors
    // 2. 触发检测（如果支持手动触发）
    // 3. 等待检测完成
    // 4. 读取检测结果并写入 raw-findings-*
    
    // 临时实现：返回提示信息
    console.warn('OpenSearch Security Analytics 检测功能需要配置 detector 和规则');
    console.warn('当前为 MVP 版本，建议先手动配置 Security Analytics，然后调用 deduplicateFindings');
    
    return {
      success: true,
      message: 'Security Analytics 检测需要先配置 detector（当前为 MVP 版本）',
    };
  } catch (error) {
    console.error('Security Analytics 检测失败:', error);
    return {
      success: false,
      message: error instanceof Error ? error.message : '检测失败',
    };
  }
}

/**
 * 数据分析主函数
 * 1. 运行 Security Analytics 检测（Store-first）
 * 2. 告警融合去重（Raw → Canonical）
 */
export async function runDataAnalysis(): Promise<{
  detection: {
    success: boolean;
    message?: string;
  };
  deduplication: {
    total: number;
    merged: number;
    canonical: number;
    errors: number;
  };
}> {
  // Step 1: 运行 Security Analytics 检测
  const detectionResult = await runSecurityAnalytics();
  
  // Step 2: 告警融合去重
  const deduplicationResult = await deduplicateFindings();
  
  return {
    detection: detectionResult,
    deduplication: deduplicationResult,
  };
}
