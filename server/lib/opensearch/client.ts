// OpenSearch 客户端配置和基础操作

import { Client } from '@opensearch-project/opensearch';

// OpenSearch客户端配置
const opensearchConfig = {
  node: process.env.OPENSEARCH_NODE || 'https://localhost:9200',
  auth: {
    username: process.env.OPENSEARCH_USERNAME || 'admin',
    password: process.env.OPENSEARCH_PASSWORD || 'OpenSearch@2024!Dev',
  },
  ssl: {
    rejectUnauthorized: false, // 开发环境可关闭证书验证（OpenSearch 3.4.0 默认启用 HTTPS）
  },
};

// 创建OpenSearch客户端单例
let opensearchClient: Client | null = null;

export function getClient(): Client {
  if (!opensearchClient) {
    opensearchClient = new Client(opensearchConfig);
  }
  return opensearchClient;
}

// 检查索引是否存在
export async function indexExists(indexName: string): Promise<boolean> {
  const client = getClient();
  try {
    const response = await client.indices.exists({ index: indexName });
    return response.body as boolean;
  } catch (error) {
    console.error(`检查索引 ${indexName} 失败:`, error);
    return false;
  }
}

// 创建索引（如果不存在）
export async function ensureIndex(indexName: string, mapping: any): Promise<void> {
  const client = getClient();
  const exists = await indexExists(indexName);
  
  if (!exists) {
    try {
      await client.indices.create({
        index: indexName,
        body: {
          settings: {
            number_of_shards: 1,
            number_of_replicas: 0, // 开发环境可设为0
          },
          mappings: mapping,
        },
      });
      console.log(`索引 ${indexName} 创建成功`);
    } catch (error) {
      console.error(`创建索引 ${indexName} 失败:`, error);
      throw error;
    }
  }
}

// 查询文档
export async function search(
  indexName: string,
  query: any,
  size: number = 100
): Promise<any[]> {
  const client = getClient();
  
  try {
    const response = await client.search({
      index: indexName,
      body: {
        query,
        size,
      },
    });
    return response.body.hits.hits.map((hit: any) => hit._source);
  } catch (error) {
    console.error(`查询 ${indexName} 失败:`, error);
    throw error;
  }
}

// 根据ID获取文档
export async function getDocument(indexName: string, id: string): Promise<any | null> {
  const client = getClient();
  
  try {
    const response = await client.get({
      index: indexName,
      id,
    });
    return response.body._source;
  } catch (error: any) {
    if (error.statusCode === 404) {
      return null;
    }
    console.error(`获取文档 ${id} 从 ${indexName} 失败:`, error);
    throw error;
  }
}

// 更新文档
export async function updateDocument(
  indexName: string,
  id: string,
  document: any
): Promise<void> {
  const client = getClient();
  
  try {
    await client.update({
      index: indexName,
      id,
      body: { doc: document },
    });
  } catch (error) {
    console.error(`更新文档 ${id} 在 ${indexName} 失败:`, error);
    throw error;
  }
}

// 单个文档写入
export async function indexDocument(
  indexName: string,
  document: any,
  id?: string
): Promise<void> {
  const client = getClient();
  
  try {
    await client.index({
      index: indexName,
      id: id || document['event.id'] || document.event?.id || undefined,
      body: document,
    });
  } catch (error) {
    console.error(`写入文档到 ${indexName} 失败:`, error);
    throw error;
  }
}

// 批量写入文档
export async function bulkIndex(
  indexName: string,
  documents: Array<{ id?: string; document: any }>
): Promise<{ success: number; failed: number; errors?: any[] }> {
  const client = getClient();
  
  if (documents.length === 0) {
    return { success: 0, failed: 0 };
  }
  
  const body = documents.flatMap(({ id, document }) => [
    { index: { _index: indexName, _id: id || document['event.id'] || undefined } },
    document,
  ]);
  
  try {
    const response = await client.bulk({ body });
    
    let success = 0;
    let failed = 0;
    const errors: any[] = [];
    
    if (response.body.errors) {
      response.body.items.forEach((item: any) => {
        if (item.index?.error) {
          failed++;
          errors.push(item.index.error);
        } else {
          success++;
        }
      });
    } else {
      success = documents.length;
    }
    
    if (failed > 0) {
      console.error(`批量写入 ${indexName} 部分失败:`, errors);
    }
    
    return { success, failed, errors: failed > 0 ? errors : undefined };
  } catch (error) {
    console.error(`批量写入 ${indexName} 失败:`, error);
    throw error;
  }
}
