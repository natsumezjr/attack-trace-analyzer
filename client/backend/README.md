# 客户端后端（Go + SQLite）

本目录计划实现 **Client Backend / Go**，职责来自：
- `docs/05-模块与数据流说明.md`（Step 2）
- `docs/06C-客户端中心机接口规范.md`（注册 + 拉取 + health）
- `docs/06A-ECS字段规范.md`（归一化口径）

## 目标能力（v1）

- 从采集层读入原始事件（Wazuh/Falco/Suricata）
- 映射为 ECS 子集（Telemetry + Findings）
- 写入本地 SQLite 缓冲（避免中心机拉取慢造成丢数据）
- 启动注册中心机，维护 `client_token`
- 对外提供：
  - `GET /api/v1/health`
  - `POST /api/v1/pull`（cursor + limit + want 过滤）

## 代码分区（约定）

- `cmd/`：可执行入口（未来放 `main.go`）
- `internal/`：内部实现（API/采集/归一化/存储/注册）
- `configs/`：配置模板与默认配置（后续补充）

