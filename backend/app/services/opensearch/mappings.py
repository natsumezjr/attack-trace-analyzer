# OpenSearch索引映射定义
# 根据 docs/80-规范/82-OpenSearch索引与Mapping规范.md 与 docs/80-规范/81-ECS字段规范.md 中的规范

# ECS Events索引映射
ecs_events_mapping = {
    "properties": {
        "@timestamp": {"type": "date"},
        "ecs.version": {"type": "keyword"},
        "event.id": {"type": "keyword"},
        "event.kind": {"type": "keyword"},
        "event.category": {"type": "keyword"},
        "event.type": {"type": "keyword"},
        "event.action": {"type": "keyword"},
        "event.outcome": {"type": "keyword"},
        "event.module": {"type": "keyword"},
        "event.dataset": {"type": "keyword"},
        "event.created": {"type": "date"},
        "event.ingested": {"type": "date"},
        "event.original": {"type": "text", "index": False},
        "host.id": {"type": "keyword"},
        "host.name": {"type": "keyword"},
        "user.id": {"type": "keyword"},
        "user.name": {"type": "keyword"},
        "process.entity_id": {"type": "keyword"},
        "process.pid": {"type": "long"},
        "process.executable": {"type": "keyword"},
        "process.parent.pid": {"type": "long"},
        "process.parent.entity_id": {"type": "keyword"},
        "process.parent.executable": {"type": "keyword"},
        "process.parent.name": {"type": "keyword"},
        "process.name": {"type": "keyword"},
        "process.command_line": {
            "type": "text",
            "fields": {
                "keyword": {"type": "keyword", "ignore_above": 256}
            }
        },
        "source.ip": {"type": "ip"},
        "source.port": {"type": "long"},
        "destination.ip": {"type": "ip"},
        "destination.port": {"type": "long"},
        "network.transport": {"type": "keyword"},
        "network.direction": {"type": "keyword"},
        "dns.question.name": {
            "type": "text",
            "fields": {
                "keyword": {"type": "keyword", "ignore_above": 256}
            }
        },
        "dns.answers.data": {"type": "keyword"},
        "dns.answers.type": {"type": "keyword"},
        "file.path": {"type": "keyword"},
        "file.hash.sha256": {"type": "keyword"},
        "session.id": {"type": "keyword"},
        "message": {"type": "text"},
    },
}

# Raw Findings索引映射
raw_findings_mapping = {
    "properties": {
        "@timestamp": {"type": "date"},
        "ecs.version": {"type": "keyword"},
        "event.id": {"type": "keyword"},
        "event.kind": {"type": "keyword"},
        "event.category": {"type": "keyword"},
        "event.type": {"type": "keyword"},
        "event.action": {"type": "keyword"},
        "event.dataset": {"type": "keyword"},
        "event.severity": {"type": "integer"},
        "event.created": {"type": "date"},
        "event.ingested": {"type": "date"},
        "rule.id": {"type": "keyword"},
        "rule.name": {"type": "keyword"},
        "rule.version": {"type": "keyword"},
        "rule.ruleset": {"type": "keyword"},
        "threat.tactic.id": {"type": "keyword"},
        "threat.tactic.name": {"type": "keyword"},
        "threat.technique.id": {"type": "keyword"},
        "threat.technique.name": {"type": "keyword"},
        "custom.finding.stage": {"type": "keyword"},
        "custom.finding.detector_id": {"type": "keyword"},
        "custom.finding.providers": {"type": "keyword"},
        "custom.finding.fingerprint": {"type": "keyword"},
        "custom.confidence": {"type": "float"},
        "custom.evidence.event_ids": {"type": "keyword"},
        "host.id": {"type": "keyword"},
        "host.name": {"type": "keyword"},
        "user.id": {"type": "keyword"},
        "user.name": {"type": "keyword"},
        "process.entity_id": {"type": "keyword"},
        "source.ip": {"type": "ip"},
        "destination.ip": {"type": "ip"},
        "destination.port": {"type": "long"},
        "dns.question.name": {
            "type": "text",
            "fields": {
                "keyword": {"type": "keyword", "ignore_above": 256}
            }
        },
        "file.path": {"type": "keyword"},
        "file.hash.sha256": {"type": "keyword"},
        "message": {"type": "text"},
    },
}

# Canonical Findings索引映射
canonical_findings_mapping = {
    "properties": {
        "@timestamp": {"type": "date"},
        "ecs.version": {"type": "keyword"},
        "event.id": {"type": "keyword"},
        "event.kind": {"type": "keyword"},
        "event.category": {"type": "keyword"},
        "event.type": {"type": "keyword"},
        "event.action": {"type": "keyword"},
        "event.dataset": {"type": "keyword"},
        "event.severity": {"type": "integer"},
        "event.created": {"type": "date"},
        "event.ingested": {"type": "date"},
        "rule.id": {"type": "keyword"},
        "rule.name": {"type": "keyword"},
        "rule.version": {"type": "keyword"},
        "rule.ruleset": {"type": "keyword"},
        "threat.tactic.id": {"type": "keyword"},
        "threat.tactic.name": {"type": "keyword"},
        "threat.technique.id": {"type": "keyword"},
        "threat.technique.name": {"type": "keyword"},
        "custom.finding.stage": {"type": "keyword"},
        "custom.finding.detector_id": {"type": "keyword"},
        "custom.finding.providers": {"type": "keyword"},
        "custom.finding.fingerprint": {"type": "keyword"},
        "custom.confidence": {"type": "float"},
        "custom.evidence.event_ids": {"type": "keyword"},
        "host.id": {"type": "keyword"},
        "host.name": {"type": "keyword"},
        "user.id": {"type": "keyword"},
        "user.name": {"type": "keyword"},
        "process.entity_id": {"type": "keyword"},
        "source.ip": {"type": "ip"},
        "destination.ip": {"type": "ip"},
        "destination.port": {"type": "long"},
        "dns.question.name": {
            "type": "text",
            "fields": {
                "keyword": {"type": "keyword", "ignore_above": 256}
            }
        },
        "file.path": {"type": "keyword"},
        "file.hash.sha256": {"type": "keyword"},
        "message": {"type": "text"},
    },
}

# Client Registry 索引映射
# 固定索引名：client-registry（不按日滚动）
# 用于中心机维护“已注册客户机 + 轮询状态/游标”等元数据。
client_registry_mapping = {
    "properties": {
        "@timestamp": {"type": "date"},
        "client.id": {"type": "keyword"},
        "client.version": {"type": "keyword"},
        "client.token_hash": {"type": "keyword"},
        "client.listen_url": {"type": "keyword"},
        "client.capabilities.falco": {"type": "boolean"},
        "client.capabilities.suricata": {"type": "boolean"},
        "client.capabilities.filebeat": {"type": "boolean"},
        "host.id": {"type": "keyword"},
        "host.name": {"type": "keyword"},
        "poll.last_seen": {"type": "date"},
        "poll.status": {"type": "keyword"},
        "poll.last_error": {"type": "text"},
        "cursor.value": {"type": "keyword"},
    },
}

# Analysis Tasks 索引映射
# 按日滚动：analysis-tasks-YYYY-MM-DD
# 任务状态机与字段规范见 docs/33-Analysis模块规格说明书.md
analysis_tasks_mapping = {
    "properties": {
        "@timestamp": {"type": "date"},
        "task.id": {"type": "keyword"},
        "task.status": {"type": "keyword"},
        "task.progress": {"type": "integer"},
        "task.target.node_uid": {"type": "keyword"},
        "task.window.start_ts": {"type": "date"},
        "task.window.end_ts": {"type": "date"},
        "task.started_at": {"type": "date"},
        "task.finished_at": {"type": "date"},
        "task.error": {"type": "text"},
        "task.result.summary": {"type": "text"},
        # TTP 相似度（任务级结论）
        "task.result.ttp_similarity.attack_tactics": {"type": "keyword"},
        "task.result.ttp_similarity.attack_techniques": {"type": "keyword"},
        "task.result.ttp_similarity.similar_apts": {
            "type": "nested",
            "properties": {
                "intrusion_set.id": {"type": "keyword"},
                "intrusion_set.name": {"type": "keyword"},
                "similarity_score": {"type": "float"},
                "top_tactics": {"type": "keyword"},
                "top_techniques": {"type": "keyword"},
            },
        },
        # 回溯链条写回统计（便于展示/调试）
        "task.result.trace.updated_edges": {"type": "integer"},
        "task.result.trace.path_edges": {"type": "integer"},
    },
}
