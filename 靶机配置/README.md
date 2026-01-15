# 靶机配置

本目录包含攻击溯源分析系统的靶场配置文件和脚本，用于项目演示和汇报。

## 目录结构

```
靶机配置/
├── README.md          # 本文件：靶场配置说明
├── start.sh           # 靶场一键启动脚本
├── close.sh           # 靶场一键关闭脚本
├── attack.sh          # APT攻击模拟脚本（良性行为）
└── 常用命令.md         # 常用运维命令清单
```

## 文件说明

### 1. start.sh - 靶场一键启动脚本

**功能**：一键启动整个靶场环境，支持模块化启动

**支持的模块**：
- `center` - 中心机依赖（OpenSearch、Neo4j）
- `c2` - C2服务（DNS+HTTP）
- `client` - 客户机采集栈（4个实例）
- `backend` - 中心机后端（FastAPI）
- `frontend` - 中心机前端（Next.js）
- `register` - 注册客户机到中心机
- `all` - 启动所有模块（默认）

**使用示例**：
```bash
# 启动所有模块
./start.sh

# 只启动中心机和C2
./start.sh -m center,c2

# 启动前清空数据库
./start.sh -c
```

### 2. close.sh - 靶场一键关闭脚本

**功能**：一键关闭靶场环境，支持模块化关闭和数据库清空

**支持的模块**：
- `frontend` - 中心机前端
- `backend` - 中心机后端
- `client` - 客户机采集栈
- `c2` - C2服务
- `center` - 中心机依赖（OpenSearch、Neo4j）
- `db` - 仅清空数据库（不停止服务）
- `all` - 关闭所有模块（默认）

**使用示例**：
```bash
# 关闭所有模块
./close.sh

# 只关闭客户机
./close.sh -m client

# 关闭所有模块并清空数据库
./close.sh -c

# 只清空数据库（不停止服务）
./close.sh -m db
```

### 3. attack.sh - APT攻击模拟脚本

**功能**：模拟APT攻击链（良性行为），用于生成可观测的安全事件证据

**攻击链步骤**：
1. **Step A**: C2解析与连通（DNS查询、HTTP请求）
2. **Step B**: 下载载荷到受害机
3. **Step C**: 执行良性脚本
4. **Step D**: SSH会话模拟横向移动
5. **Step E**: 只读发现与收集

**预期证据**：
- Suricata: DNS和HTTP流量
- Falco: 文件写入、进程执行
- Filebeat: SSH认证日志

**使用示例**：
```bash
# 在受害机（10.92.35.13）上执行
./attack.sh
```

### 4. 常用命令.md

**功能**：项目开发和演示过程中的常用运维命令清单

**内容包括**：
- 代码更新命令
- 仓库地址
- 日志查看命令
- 远程连接信息
- 脚本权限设置

## 架构概述

本系统采用分布式架构：

```
┌──────────────────────┐
│ 客户机（4节点）       │
│  - Falco (主机行为)   │
│  - Filebeat (系统日志)│
│  - Suricata (网络流量)│
│  - RabbitMQ (消息队列)│
│  - Go Backend (拉取接口)│
└─────────┬────────────┘
          │ 定时拉取
          ▼
┌─────────────────────────────────────┐
│ 中心机                              │
│  - FastAPI (轮询调度、检测融合)      │
│  - OpenSearch (事件/告警检索)        │
│  - Neo4j (实体关系图谱)              │
│  - Analysis (溯源分析)               │
│  - Next.js (前端可视化)              │
└─────────────────────────────────────┘
```

## 数据流水线

中心机采用"单定时器四步流水线"：

1. **Step 1**: 轮询客户机，拉取增量数据
2. **Step 2**: 写入OpenSearch，字段处理+幂等去重
3. **Step 3**: Store-first检测，Raw Findings → Canonical Findings
4. **Step 4**: ECS → Graph，写入Neo4j图谱

## 演示流程建议

### 标准演示流程

1. **启动靶场**：
   ```bash
   ./start.sh
   ```

2. **验证服务状态**：
   ```bash
   docker ps | grep -E '(opensearch|neo4j|c2|client)'
   ss -lntup | grep -E ':(9200|9600|7474|7687|8001|3000)'
   ```

3. **执行攻击模拟**：
   ```bash
   ./attack.sh
   ```

4. **验证数据采集**：
   ```bash
   curl -s http://10.92.35.13:18881/filebeat | python3 -c "import sys,json; print('filebeat total=', json.load(sys.stdin).get('total'))"
   curl -s http://10.92.35.13:18881/falco | python3 -c "import sys,json; print('falco total=', json.load(sys.stdin).get('total'))"
   curl -s http://10.92.35.13:18881/suricata | python3 -c "import sys,json; print('suricata total=', json.load(sys.stdin).get('total'))"
   ```

5. **前端可视化**：
   - 访问 http://10.92.35.13:3000
   - 查看事件和告警
   - 执行图谱溯源分析

6. **关闭靶场**：
   ```bash
   ./close.sh
   ```

### 重置演示环境

如需清空数据库重新演示：
```bash
./close.sh -c  # 关闭并清空数据库
./start.sh     # 重新启动
```

## 网络配置

靶场网络规划：

| 组件 | IP地址 | 端口 | 说明 |
|------|--------|------|------|
| 中心机前端 | 10.92.35.13 | 3000 | Next.js |
| 中心机后端 | 10.92.35.13 | 8001 | FastAPI |
| OpenSearch | 10.92.35.13 | 9200 | 数据存储 |
| OpenSearch Dashboards | 10.92.35.13 | 5601 | 可视化 |
| Neo4j | 10.92.35.13 | 7474/7687 | 图数据库 |
| C2 DNS | 10.92.35.50 | 53 | 恶意DNS |
| C2 HTTP | 10.92.35.51 | 80 | 恶意HTTP |
| 客户机01-04 | 10.92.35.13 | 18881-18884 | 采集栈 |

## 注意事项

1. **脚本权限**：首次使用前需要设置可执行权限
   ```bash
   chmod +x ./*.sh
   ```

2. **环境变量**：确保 `BASE` 和 `REPO` 路径正确配置在脚本中

3. **数据库清空**：生产环境慎用 `-c` 选项，会清空所有数据

4. **日志查看**：后端和前端日志分别位于 `~/attack-trace-analyzer/run/backend.log` 和 `frontend.log`

## 相关文档

- 详细设计：`../docs/50-详细设计/`
- 部署指南：`../docs/90-运维与靶场/91-靶场部署.md`
- 一键编排：`../docs/90-运维与靶场/92-一键编排.md`
- 验证清单：`../docs/90-运维与靶场/94-验证清单.md`
