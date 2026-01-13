import { NextRequest, NextResponse } from 'next/server';
import { runDataAnalysis } from '@/lib/opensearch/analysis';
import { initializeOpenSearch } from '@/lib/init';

/**
 * 数据分析接口
 * POST /api/v1/analysis/run
 * 
 * 功能：
 * 1. 触发 OpenSearch Security Analytics 检测（Store-first）
 * 2. 对 Raw Findings 进行融合去重，生成 Canonical Findings
 * 
 * 返回：
 * {
 *   status: 'ok',
 *   result: {
 *     detection: { success, message },
 *     deduplication: { total, merged, canonical, errors }
 *   }
 * }
 */
export async function POST(request: NextRequest) {
  // 确保索引已初始化
  await initializeOpenSearch();
  
  try {
    // 运行数据分析
    const result = await runDataAnalysis();
    
    return NextResponse.json({
      status: 'ok',
      message: '数据分析完成',
      result: {
        detection: result.detection,
        deduplication: result.deduplication,
      },
    });
  } catch (error: any) {
    console.error('数据分析失败:', error);
    return NextResponse.json(
      {
        status: 'error',
        error: {
          code: 'ANALYSIS_ERROR',
          message: error.message || '数据分析失败',
        },
      },
      { status: 500 }
    );
  }
}

// 也支持 GET 请求（方便测试）
export async function GET(request: NextRequest) {
  return POST(request);
}
