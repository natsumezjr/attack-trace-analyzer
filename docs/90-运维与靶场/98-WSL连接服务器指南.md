# WSL连接服务器指南

本文面向使用WSL环境的用户，提供从WSL连接到靶场服务器`10.92.35.13`的完整步骤。

## 重要说明

- **网卡`ens5f1`是服务器端的配置**，你的WSL本地环境不需要这个网卡
- 你只需要能SSH连接到服务器即可，所有靶场配置都在服务器端完成
- 服务器IP `10.92.35.13` 是内网地址，需要通过VPN或内网路由访问

## 1. 检查网络连通性

### 1.1 检查是否能ping通服务器

在WSL中执行：

```bash
ping -c 3 10.92.35.13
```

### 1.2 检查SSH端口是否开放

```bash
# 方法1：使用nc（如果已安装）
nc -zv 10.92.35.13 22

# 方法2：使用ssh测试（推荐）
ssh -v ubuntu@10.92.35.13
```

### 1.3 检查WSL网络配置（可选）

```bash
# 查看WSL IP和路由
ip addr show
ip route
```

## 2. SSH连接服务器

### 2.1 基本连接命令

```bash
ssh ubuntu@10.92.35.13
```

**密码**：通过线下渠道分发

### 2.2 如果连接失败，尝试以下方案

#### 方案A：指定SSH端口（如果不是22）

```bash
ssh -p <端口号> ubuntu@10.92.35.13
```

#### 方案B：使用跳板机（如果需要）

```bash
ssh -J jump_user@jump_host ubuntu@10.92.35.13
```

#### 方案C：使用SSH密钥（如果提供了密钥文件）

```bash
ssh -i /path/to/private_key ubuntu@10.92.35.13
```

#### 方案D：详细调试模式（查看连接过程）

```bash
ssh -v ubuntu@10.92.35.13
```

## 3. 连接成功后的验证

连接成功后，在服务器上依次执行以下命令：

### 3.1 确认工作目录

```bash
export BASE=/home/ubuntu/attack-trace-analyzer
export REPO="$BASE"/repo/attack-trace-analyzer

cd "$BASE"
pwd
ls -la
```

### 3.2 检查Docker配置

```bash
docker --version
docker-compose --version
docker ps
```

### 3.3 检查服务器网卡（这是服务器端的，你本地不需要）

```bash
ip -br a | grep ens5f1
ip route
```

### 3.4 检查项目文件结构

```bash
cd "$REPO"
ls -la
```

### 3.5 检查已运行的服务（如果有）

```bash
ss -lntup | grep -E ':(9200|7474|7687|18881|18882|18883|18884)\b'
```

## 4. 如果无法连接，排查步骤

### 4.1 检查Windows防火墙

在Windows PowerShell中执行：

```powershell
# 检查防火墙状态
Get-NetFirewallProfile | Select-Object Name, Enabled
```

### 4.2 检查WSL网络模式

在WSL中执行：

```bash
# 查看WSL IP
hostname -I

# 查看路由
ip route

# 测试DNS解析
nslookup 10.92.35.13
```

### 4.3 检查是否需要VPN

- 询问交付人是否需要连接VPN才能访问内网`10.92.35.0/24`
- 如果需要VPN，先连接VPN再尝试SSH

### 4.4 询问交付人的问题清单

如果以上步骤都无法连接，请向交付人确认：

1. 是否需要VPN或特殊网络配置？
2. 是否需要跳板机？如果有，跳板机地址和用户名是什么？
3. SSH端口是否为22？如果不是，端口号是多少？
4. 是否需要SSH密钥？如果需要，密钥文件在哪里？
5. WSL是否能访问`10.92.35.0/24`网段？
6. 是否有其他网络限制或配置要求？

## 5. 连接成功后的下一步

连接成功后，按照以下文档进行部署：

1. **完整部署步骤**：`97-单机靶场落地步骤.md`
2. **一键编排**：`92-一键编排.md`
3. **C2部署**：`93-C2部署与证据点.md`
4. **验证清单**：`94-验证清单.md`
5. **重置与排障**：`95-重置复现与排障.md`

## 6. 快速参考

### 服务器信息

- **IP**：`10.92.35.13`
- **用户名**：`ubuntu`
- **工作目录**：`/home/ubuntu/attack-trace-analyzer`
- **固定变量**：
  ```bash
  export BASE=/home/ubuntu/attack-trace-analyzer
  export REPO="$BASE"/repo/attack-trace-analyzer
  ```

### 常用端口（服务器端）

- OpenSearch：`9200`
- Neo4j Browser：`7474`
- Neo4j Bolt：`7687`
- 后端：`8001`
- 前端：`3000`
- Client-01 API：`18881`
- Client-02 API：`18882`
- Client-03 API：`18883`
- Client-04 API：`18884`
