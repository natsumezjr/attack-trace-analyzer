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
    node_url = os.getenv("OPENSEARCH_NODE", "https://localhost:9200")
    # 解析URL，提取host和port
    from urllib.parse import urlparse
    parsed = urlparse(node_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 9200
    use_ssl = parsed.scheme == "https"
    
    return {
        "hosts": [{"host": host, "port": port}],
        "http_auth": (
            os.getenv("OPENSEARCH_USERNAME", "admin"),
            os.getenv("OPENSEARCH_PASSWORD", "OpenSearch@2024!Dev"),
        ),
        "use_ssl": use_ssl,
        "verify_certs": False,  # 开发环境可关闭证书验证（OpenSearch 3.4.0 默认启用 HTTPS）
        "ssl_show_warn": False,
        "connection_class": RequestsHttpConnection,
    }


# 创建OpenSearch客户端单例
_opensearch_client: Optional[OpenSearch] = None


def get_client() -> OpenSearch:
    """获取OpenSearch客户端单例"""
    global _opensearch_client
    if _opensearch_client is None:
        _opensearch_client = OpenSearch(**_get_opensearch_config())
    return _opensearch_client


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
