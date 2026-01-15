# BUG 修复报告：event.id 缺失导致数据全被丢弃

## 问题描述

所有事件数据都被丢弃，OpenSearch 索引为空（`docs.count = 0`）。

## 根本原因

**客户机 Go 后端的二进制文件版本过旧，缺少 `ensureEventID` 函数**

### 详细证据链

1. **OpenSearch 索引为空**
   ```bash
   ecs-events-2026-01-15: docs.count = 0
   raw-findings-2026-01-15: docs.count = 0
   canonical-findings-2026-01-15: docs.count = 0
   ```

2. **后端日志显示所有数据被丢弃**
   ```
   store_events result: {'total': 41, 'success': 0, 'dropped': 41}
   drop_reasons: {'no_required_fields': 41}
   ```

3. **客户机返回的数据缺少 event.id**
   ```json
   {
     "event": {
       "ingested": "...",
       "kind": "alert",
       "dataset": "finding.raw.filebeat_sigma"
       // ❌ 没有 "id" 字段！
     }
   }
   ```

4. **二进制文件版本对比**
   - 本地 `go-client`: `2026-01-15 23:06:04` (最新)
   - 靶机 `go-client`: `Jan 15 09:38` (旧版本)

5. **旧版本二进制文件不包含 ensureEventID 函数**
   ```bash
   strings /usr/local/bin/go-client | grep ensureEventID
   # 输出: (空) ← 函数不存在！
   ```

## BUG 触发流程

```
1. Filebeat 采集日志 → 发布到 RabbitMQ
2. 客户机 Go 后端从 RabbitMQ 拉取数据
3. ❌ 旧版本 Go 后端没有调用 ensureEventID
4. 数据中没有 event.id 字段
5. 中心机 Python 后端接收到数据
6. _ensure_required_fields 检查 event.id (storage.py:287-293)
7. ❌ event.id 缺失 → 返回 None → 数据被丢弃
8. OpenSearch 索引保持为空
```

## 修复方案

### 1. 在本地 Mac 上交叉编译 Linux 二进制文件

```bash
cd client/backend
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o go-client .
```

**验证编译结果**：
```bash
$ file go-client
go-client: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked

$ strings go-client | grep ensureEventID
go-client/queue.ensureEventID
go-client/queue.ensureEventID
```

### 2. 提交到 Git

```bash
git add client/backend/go-client
git commit -m "fix(backend): recompile go-client with ensureEventID function"
git push origin Huafucius/sync-main-docs
```

### 3. 在靶机上部署

使用提供的部署脚本 `deploy-new-backend.sh`：

```bash
# 在靶机上执行
chmod +x deploy-new-backend.sh
./deploy-new-backend.sh
```

或者手动部署：

```bash
# 1. 拉取最新代码
cd /home/ubuntu/attack-trace-analyzer/repo/attack-trace-analyzer
git pull origin main

# 2. 停止容器
cd /home/ubuntu/attack-trace-analyzer/run
docker-compose -f client/docker-compose.yml stop client-01_backend

# 3. 复制新二进制文件
docker cp /home/ubuntu/attack-trace-analyzer/repo/attack-trace-analyzer/client/backend/go-client \
  client-01_backend_1:/usr/local/bin/go-client

# 4. 重启容器
docker-compose -f client/docker-compose.yml start client-01_backend
```

### 4. 验证修复

```bash
# 检查 event.id 是否存在
curl http://localhost:18881/filebeat | jq '.data[0].event.id'
# 应该输出: "evt-xxxxxxxxxxxxxxxx"

# 检查 OpenSearch 数据
curl -k -s -u admin:OpenSearch@2024!Dev \
  'https://localhost:9200/_cat/indices?v' | grep ecs-events
# 应该看到 docs.count > 0
```

## 关键文件位置

| 组件 | 文件 | 行号 | 说明 |
|------|------|------|------|
| event.id 生成 | `client/backend/queue/client.go` | 39-70 | ensureEventID 函数 |
| event.id 调用 | `client/backend/queue/client.go` | 107 | FetchAll 中调用 |
| event.id 验证 | `backend/app/services/opensearch/storage.py` | 287-293 | 缺失则返回 None |
| 必需字段检查 | `backend/app/services/opensearch/storage.py` | 177-496 | _ensure_required_fields |

## 经验总结

1. ✅ **event.id 处理逻辑本身是正确的**
   - 客户机侧有生成逻辑 (`ensureEventID`)
   - 中心机侧有验证逻辑 (`storage.py:287-293`)

2. ❌ **部署问题导致逻辑未生效**
   - 靶机上运行的是旧版本二进制文件
   - 旧版本缺少 `ensureEventID` 函数

3. ⚠️ **缺少版本管理**
   - 二进制文件没有版本号或构建时间戳
   - 难以发现代码和二进制不匹配的问题

## 改进建议

1. **添加版本管理**
   - 在 Go 二进制文件中嵌入构建时间戳和 Git commit hash
   - 使用 `ldflags` 在编译时注入版本信息

2. **添加健康检查**
   - 在客户机 API 中添加 `/version` 端点
   - 显示二进制文件的版本和构建时间

3. **改进日志**
   - 在 `ensureEventID` 函数中添加日志
   - 记录生成的 event.id（前几个字符即可）

4. **自动化部署**
   - 使用 CI/CD 确保代码更新后自动重新构建和部署
   - 添加版本检查，防止部署旧版本

## 附录：交叉编译参考

### macOS (arm64) → Linux (amd64)

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o go-client .
```

### 其他平台

```bash
# macOS (arm64) → Linux (arm64)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o go-client .

# macOS (amd64) → Linux (amd64)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o go-client .

# 查看所有支持的平台
go tool dist list
```

## 参考资料

- Go 交叉编译官方文档: https://go.dev/doc/install/source#environment
- ECS 字段规范: `docs/80-规范/81-ECS字段规范.md`
- 客户机架构: `docs/50-详细设计/客户机/50-总体.md`
