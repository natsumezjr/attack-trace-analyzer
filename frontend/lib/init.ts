// 初始化脚本：在应用启动时初始化OpenSearch索引

import { initializeIndices } from './opensearch';

let initialized = false;

export async function initializeOpenSearch() {
  if (initialized) {
    return;
  }
  
  try {
    console.log('开始初始化OpenSearch索引...');
    await initializeIndices();
    initialized = true;
    console.log('OpenSearch索引初始化完成');
  } catch (error) {
    console.error('OpenSearch索引初始化失败:', error);
    throw error;
  }
}
