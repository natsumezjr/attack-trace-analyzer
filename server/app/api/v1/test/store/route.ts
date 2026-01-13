import { NextRequest, NextResponse } from 'next/server';
import { storeEvents } from '@/lib/opensearch';
import { initializeOpenSearch } from '@/lib/init';

// 测试存储接口 - 提供测试数据
export async function POST(request: NextRequest) {
  try {
    // 确保索引已初始化
    await initializeOpenSearch();
    
    // 生成测试数据
    const testEvents = [
      // 测试1: ECS Event (Telemetry)
      {
        'ecs': { 'version': '9.2.0' },
        '@timestamp': new Date().toISOString(),
        'event': {
          'id': `evt-test-${Date.now()}-1`,
          'kind': 'event',
          'created': new Date().toISOString(),
          'ingested': new Date().toISOString(),
          'category': ['authentication'],
          'type': ['start'],
          'action': 'user_login',
          'dataset': 'hostlog.auth',
          'outcome': 'success',
        },
        'host': {
          'id': 'h-test-victim-01',
          'name': 'victim-01',
        },
        'user': {
          'name': 'testuser',
        },
        'source': {
          'ip': '10.0.0.8',
        },
        'session': {
          'id': `sess-test-${Date.now()}`,
        },
        'message': '测试事件：用户登录',
      },
      // 测试2: Raw Finding (Alert)
      {
        'ecs': { 'version': '9.2.0' },
        '@timestamp': new Date().toISOString(),
        'event': {
          'id': `evt-test-${Date.now()}-2`,
          'kind': 'alert',
          'created': new Date().toISOString(),
          'ingested': new Date().toISOString(),
          'category': ['intrusion_detection'],
          'type': ['alert'],
          'action': 'suspicious_activity',
          'dataset': 'finding.raw',
          'severity': 70,
        },
        'rule': {
          'id': 'rule-test-001',
          'name': '测试规则：可疑活动',
          'version': '1.0',
          'ruleset': 'test',
        },
        'threat': {
          'tactic': {
            'id': 'TA0001',
            'name': 'Initial Access',
          },
          'technique': {
            'id': 'T1078',
            'name': 'Valid Accounts',
          },
        },
        'custom': {
          'finding': {
            'stage': 'raw',
            'providers': ['test'],
          },
          'confidence': 0.8,
          'evidence': {
            'event_ids': [`evt-test-${Date.now()}-1`],
          },
        },
        'host': {
          'id': 'h-test-victim-01',
          'name': 'victim-01',
        },
        'message': '测试告警：可疑活动检测',
      },
      // 测试3: Network Event
      {
        'ecs': { 'version': '9.2.0' },
        '@timestamp': new Date().toISOString(),
        'event': {
          'id': `evt-test-${Date.now()}-3`,
          'kind': 'event',
          'created': new Date().toISOString(),
          'ingested': new Date().toISOString(),
          'category': ['network'],
          'type': ['connection'],
          'action': 'network_flow',
          'dataset': 'netflow.tcp',
        },
        'host': {
          'id': 'h-test-victim-01',
          'name': 'victim-01',
        },
        'source': {
          'ip': '10.0.0.11',
          'port': 54321,
        },
        'destination': {
          'ip': '192.168.1.100',
          'port': 443,
        },
        'network': {
          'transport': 'tcp',
          'direction': 'outbound',
        },
        'message': '测试事件：网络连接',
      },
    ];
    
    // 存储到OpenSearch
    const result = await storeEvents(testEvents);
    
    // 返回结果
    return NextResponse.json({
      status: 'ok',
      message: '测试数据存储完成',
      result: {
        total: result.total,
        success: result.success,
        failed: result.failed,
        details: result.details,
      },
      test_events: testEvents.map((e) => ({
        id: e.event.id,
        kind: e.event.kind,
        dataset: e.event.dataset,
      })),
    });
  } catch (error: any) {
    console.error('测试存储失败:', error);
    return NextResponse.json(
      {
        status: 'error',
        error: {
          code: 'INTERNAL_ERROR',
          message: error.message || '测试存储失败',
          stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
        },
      },
      { status: 500 }
    );
  }
}
