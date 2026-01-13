# Falco -> ECS -> SQLite

本项目使用 Falco 采集主机行为日志，将 Falco JSON 转换为 ECS 格式并写入 SQLite，便于后端直接读取。

## 目录结构

- `docker-compose.yml`：一键启动 Falco 与 ECS 转换器
- `ecs-converter/falco_json_to_ecs.py`：转换脚本（Falco JSON -> ECS JSON -> SQLite）
- `ecs-converter/Dockerfile`：转换器镜像构建文件
- `data/`：运行时数据目录
  - `data/falco.jsonl`：Falco 原始 JSONL（输入）
  - `data/data.db`：SQLite 数据库（输出，表：falco）

## 使用方法

1) 启动

```bash
sudo docker compose up -d --build
```

2) 查看数据库

```bash
sqlite3 data/data.db "SELECT id, event_json FROM falco ORDER BY id DESC LIMIT 10;"
```

## 关键说明

- 转换器只写 SQLite，不再生成 ECS 的 JSONL 文件。
- `--reset` 已启用：每次启动会清空 `data/falco.jsonl` 和 `data/data.db`（含 WAL/SHM）。
- SQLite 表结构固定为：
  - 表名：`data`
  - 字段：`id`（自增主键）、`event_json`（完整 ECS JSON 字符串）
