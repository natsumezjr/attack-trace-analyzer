import { NextRequest, NextResponse } from 'next/server';
import { storeEvents } from '@/lib/opensearch';
import { initializeOpenSearch } from '@/lib/init';

// 存储事件到OpenSearch的接口
// 这个接口可以被轮询器调用，也可以手动调用
export async function POST(request: NextRequest) {
  // 确保索引已初始化
  await initializeOpenSearch();
  
  try {
    const body = await request.json();
    
    // 验证请求格式
    if (!body.events || !Array.isArray(body.events)) {
      return NextResponse.json(
        {
          status: 'error',
          error: {
            code: 'BAD_REQUEST',
            message: '请求体必须包含 events 数组',
          },
        },
        { status: 400 }
      );
    }
    
    const events = body.events;
    
    // 验证事件格式（至少需要event.id和event.kind）
    for (const event of events) {
      if (!event.event || !event.event.id) {
        return NextResponse.json(
          {
            status: 'error',
            error: {
              code: 'BAD_REQUEST',
              message: '每个事件必须包含 event.id 字段',
            },
          },
          { status: 400 }
        );
      }
    }
    
    // 存储到OpenSearch
    const result = await storeEvents(events);
    
    // 返回结果
    return NextResponse.json({
      status: 'ok',
      message: '数据存储完成',
      result: {
        total: result.total,
        success: result.success,
        failed: result.failed,
        details: result.details,
      },
    });
  } catch (error: any) {
    console.error('存储事件失败:', error);
    return NextResponse.json(
      {
        status: 'error',
        error: {
          code: 'INTERNAL_ERROR',
          message: error.message || '存储事件失败',
        },
      },
      { status: 500 }
    );
  }
}
