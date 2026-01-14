# OpenSearch 客户端配置和基础操作

import os
from typing import Any, Optional

try:
    from opensearchpy import OpenSearch, RequestsHttpConnection
    from opensearchpy.helpers import bulk
except ImportError:
    raise ImportError(
        "请安装 opensearch-py: uv add opensearch-py 或 pip install opensearch-py"
    )

# OpenSearch客户端配置
def _get_opensearch_config():
    # 默认使用 HTTP（如果禁用了安全插件）
    # 如果启用了安全插件，请设置环境变量 OPENSEARCH_NODE=https://localhost:9200
    node_url = os.getenv("OPENSEARCH_NODE", "http://localhost:9200")
    # 解析URL，提取host和port
    from urllib.parse import urlparse
    parsed = urlparse(node_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 9200
    use_ssl = parsed.scheme == "https"
    
    config = {
        "hosts": [{"host": host, "port": port}],
        "use_ssl": use_ssl,
        "connection_class": RequestsHttpConnection,
    }
    
    # 只有在启用 SSL 时才设置 SSL 相关配置
    if use_ssl:
        config["verify_certs"] = False  # 开发环境可关闭证书验证
        config["ssl_show_warn"] = False
        # 只有在启用 SSL 时才需要认证（安全插件启用时）
        config["http_auth"] = (
            os.getenv("OPENSEARCH_USERNAME", "admin"),
            os.getenv("OPENSEARCH_PASSWORD", "OpenSearch@2024!Dev"),
        )
    
    return config


# 创建OpenSearch客户端单例
_opensearch_client: Optional[OpenSearch] = None


def get_client() -> OpenSearch:
    """获取OpenSearch客户端单例"""
    global _opensearch_client
    if _opensearch_client is None:
        config = _get_opensearch_config()
        # 添加超时设置
        config["timeout"] = 30  # 总超时30秒（包括连接和读取）
        config["max_retries"] = 2  # 最多重试2次
        config["retry_on_timeout"] = True  # 超时时重试
        config["retry_on_status"] = [502, 503, 504]  # 这些状态码时重试
        
        try:
            _opensearch_client = OpenSearch(**config)
            # 测试连接
            _opensearch_client.info()
        except Exception as e:
            error_msg = str(e)
            if 'connection' in error_msg.lower() or 'connect' in error_msg.lower():
                node_url = os.getenv("OPENSEARCH_NODE", "http://localhost:9200")
                raise ConnectionError(
                    f"无法连接到 OpenSearch ({node_url}): {error_msg}\n"
                    f"请检查：\n"
                    f"  1. OpenSearch 服务是否运行\n"
                    f"  2. OPENSEARCH_NODE 环境变量是否正确\n"
                    f"  3. 网络连接是否正常\n"
                    f"  4. 防火墙/SSL证书配置"
                ) from e
            raise
    return _opensearch_client


def reset_client():
    """
    重置OpenSearch客户端（清除缓存，强制重新连接）
    
    用途：
    - 权限配置更改后，需要重新连接以应用新权限
    - 配置更改后，需要重新连接以使用新配置
    
    使用方法：
        from app.services.opensearch.client import reset_client
        reset_client()  # 清除缓存
        # 下次调用 get_client() 时会重新创建连接
    """
    global _opensearch_client
    if _opensearch_client is not None:
        try:
            # 尝试关闭现有连接（如果有close方法）
            if hasattr(_opensearch_client, 'close'):
                _opensearch_client.close()
        except Exception:
            pass  # 忽略关闭错误
    _opensearch_client = None


def index_exists(index_name: str) -> bool:
    """检查索引是否存在"""
    client = get_client()
    try:
        return client.indices.exists(index=index_name)
    except Exception as error:
        print(f"检查索引 {index_name} 失败: {error}")
        return False


def ensure_index(index_name: str, mapping: dict[str, Any]) -> None:
    """创建索引（如果不存在）"""
    client = get_client()
    exists = index_exists(index_name)

    if not exists:
        try:
            client.indices.create(
                index=index_name,
                body={
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,  # 开发环境可设为0
                    },
                    "mappings": mapping,
                },
            )
            print(f"索引 {index_name} 创建成功")
        except Exception as error:
            print(f"创建索引 {index_name} 失败: {error}")
            raise


def search(
    index_name: str,
    query: dict[str, Any],
    size: int = 100,
) -> list[dict[str, Any]]:
    """查询文档"""
    client = get_client()

    try:
        response = client.search(
            index=index_name,
            body={"query": query, "size": size},
        )
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as error:
        print(f"查询 {index_name} 失败: {error}")
        raise


def get_document(index_name: str, doc_id: str) -> Optional[dict[str, Any]]:
    """根据ID获取文档"""
    client = get_client()

    try:
        response = client.get(index=index_name, id=doc_id)
        return response["_source"]
    except Exception as error:
        # 404 表示文档不存在
        if hasattr(error, "status_code") and error.status_code == 404:
            return None
        print(f"获取文档 {doc_id} 从 {index_name} 失败: {error}")
        raise


def update_document(
    index_name: str,
    doc_id: str,
    document: dict[str, Any],
) -> None:
    """更新文档"""
    client = get_client()

    try:
        client.update(
            index=index_name,
            id=doc_id,
            body={"doc": document},
        )
    except Exception as error:
        print(f"更新文档 {doc_id} 在 {index_name} 失败: {error}")
        raise


def index_document(
    index_name: str,
    document: dict[str, Any],
    doc_id: Optional[str] = None,
) -> None:
    """单个文档写入"""
    client = get_client()

    # 如果没有提供ID，尝试从document中提取
    if doc_id is None:
        doc_id = document.get("event.id") or document.get("event", {}).get("id")

    try:
        if doc_id:
            client.index(index=index_name, id=doc_id, body=document)
        else:
            client.index(index=index_name, body=document)
    except Exception as error:
        print(f"写入文档到 {index_name} 失败: {error}")
        raise


def refresh_index(index_name: str) -> None:
    """刷新索引，使新写入的文档立即可搜索"""
    client = get_client()
    try:
        client.indices.refresh(index=index_name)
    except Exception as error:
        print(f"刷新索引 {index_name} 失败: {error}")
        # 不抛出异常，刷新失败不影响主流程


def bulk_index(
    index_name: str,
    documents: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    批量写入文档
    
    Args:
        index_name: 索引名称
        documents: 文档列表，每个文档格式为 {"id": "xxx", "document": {...}} 或 {"document": {...}}
    
    Returns:
        {"success": int, "failed": int, "errors": list}
    """
    client = get_client()

    if len(documents) == 0:
        return {"success": 0, "failed": 0}

    # 准备批量操作
    actions = []
    for doc in documents:
        doc_id = doc.get("id")
        doc_body = doc.get("document", doc)
        
        action = {
            "_op_type": "index",
            "_index": index_name,
            "_source": doc_body,
        }
        if doc_id:
            action["_id"] = doc_id
        actions.append(action)

    try:
        # 使用bulk helper执行批量操作
        # bulk 返回 (success_count, failed_items)
        success_count, failed_items = bulk(client, actions, raise_on_error=False)
        failed_count = len(failed_items)
        errors = [item.get("error", {}) for item in failed_items] if failed_items else []

        if failed_count > 0:
            print(f"批量写入 {index_name} 部分失败: {errors}")

        return {
            "success": success_count,
            "failed": failed_count,
            "errors": errors if failed_count > 0 else None,
        }
    except Exception as error:
        print(f"批量写入 {index_name} 失败: {error}")
        raise
