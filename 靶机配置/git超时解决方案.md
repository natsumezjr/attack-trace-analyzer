# Git 连接 GitHub 超时问题解决方案

## 问题描述
在远程服务器上执行 `git fetch origin` 时出现超时错误：
```
error: RPC failed; curl 28 Failed to connect to github.com port 443 after 134232 ms: Couldn't connect to server
fatal: expected flush after ref listing
```

## 解决方案

### 方案1：将 HTTPS 改为 SSH（推荐）

如果服务器可以访问 SSH 端口（22），使用 SSH 协议连接 GitHub：

```bash
cd ~/attack-trace-analyzer/repo/attack-trace-analyzer

# 查看当前远程地址
git remote -v

# 将 HTTPS 改为 SSH（需要先配置 SSH 密钥）
git remote set-url origin git@github.com:你的用户名/attack-trace-analyzer.git

# 测试连接
ssh -T git@github.com

# 如果测试成功，执行拉取
git fetch origin
git reset --hard origin/main
```

**配置 SSH 密钥（如果还没有）：**
```bash
# 生成 SSH 密钥（如果还没有）
ssh-keygen -t ed25519 -C "your_email@example.com"

# 查看公钥
cat ~/.ssh/id_ed25519.pub

# 将公钥添加到 GitHub: Settings -> SSH and GPG keys -> New SSH key
```

### 方案2：配置 Git 使用代理

如果服务器有可用的 HTTP/HTTPS 代理：

```bash
# 设置 HTTP 代理（根据实际情况修改代理地址和端口）
git config --global http.proxy http://proxy.example.com:8080
git config --global https.proxy http://proxy.example.com:8080

# 如果需要认证
git config --global http.proxy http://username:password@proxy.example.com:8080

# 测试
git fetch origin

# 如果不再需要代理，可以取消
git config --global --unset http.proxy
git config --global --unset https.proxy
```

### 方案3：增加超时时间和缓冲区大小

```bash
# 增加超时时间（单位：秒）
git config --global http.postBuffer 524288000
git config --global http.lowSpeedLimit 0
git config --global http.lowSpeedTime 999999

# 或者只对当前仓库设置
cd ~/attack-trace-analyzer/repo/attack-trace-analyzer
git config http.postBuffer 524288000
git config http.lowSpeedLimit 0
git config http.lowSpeedTime 999999

# 再次尝试
git fetch origin
git reset --hard origin/main
```

### 方案4：使用 GitHub 镜像或加速

如果在中国大陆，可以使用 GitHub 镜像（注意：镜像服务可能不稳定，建议优先使用 SSH）：

```bash
# 首先查看当前远程地址，获取正确的用户名和仓库名
git remote -v

# 使用 ghproxy 镜像（格式：https://ghproxy.com/https://github.com/用户名/仓库名.git）
# 注意：将下面的 natsumezjr 替换为你的实际 GitHub 用户名
git remote set-url origin https://ghproxy.com/https://github.com/natsumezjr/attack-trace-analyzer.git

# 如果 ghproxy 不可用，可以尝试其他镜像：
# git remote set-url origin https://mirror.ghproxy.com/https://github.com/natsumezjr/attack-trace-analyzer.git
# git remote set-url origin https://github.com.cnpmjs.org/natsumezjr/attack-trace-analyzer.git

# 测试连接
git fetch origin
```

### 方案5：使用本地主机作为中转（如果本地可以访问 GitHub）

如果本地主机可以正常访问 GitHub，可以在本地拉取后传输到服务器：

**在本地主机执行：**
```bash
cd /path/to/attack-trace-analyzer
git fetch origin
git reset --hard origin/main
```

**然后传输到服务器：**
```bash
# 使用 rsync 同步（从本地到服务器）
rsync -avz --exclude='.git' /path/to/attack-trace-analyzer/ ubuntu@10.92.35.13:~/attack-trace-analyzer/repo/attack-trace-analyzer/

# 或者使用 scp
scp -r /path/to/attack-trace-analyzer ubuntu@10.92.35.13:~/attack-trace-analyzer/repo/
```

## 快速诊断命令

```bash
# 测试 GitHub HTTPS 连接
curl -I https://github.com

# 测试 GitHub SSH 连接
ssh -T git@github.com

# 测试 DNS 解析
nslookup github.com
ping -c 3 github.com

# 检查 Git 配置
git config --list | grep -E "(proxy|http|url)"
git remote -v
```

## 快速修复（推荐顺序）

### 第一步：尝试 SSH（最稳定）

```bash
cd ~/attack-trace-analyzer/repo/attack-trace-analyzer

# 查看当前远程地址
git remote -v

# 改为 SSH（将 natsumezjr 替换为你的实际 GitHub 用户名）
git remote set-url origin git@github.com:natsumezjr/attack-trace-analyzer.git

# 测试 SSH 连接（如果提示需要配置密钥，参考下面的说明）
ssh -T git@github.com

# 如果 SSH 连接成功，执行拉取
git fetch origin
git reset --hard origin/main
```

**如果 SSH 未配置，快速配置：**
```bash
# 生成 SSH 密钥
ssh-keygen -t ed25519 -C "2682910849@qq.com"
# 按回车使用默认路径，设置密码（可选）

# 查看公钥并复制
cat ~/.ssh/id_ed25519.pub

# 将公钥添加到 GitHub:
# 1. 访问 https://github.com/settings/keys
# 2. 点击 "New SSH key"
# 3. 粘贴公钥内容
```

### 第二步：如果 SSH 不可用，增加超时时间

```bash
cd ~/attack-trace-analyzer/repo/attack-trace-analyzer
git config http.postBuffer 524288000
git config http.lowSpeedLimit 0
git config http.lowSpeedTime 999999

# 恢复原始 GitHub URL（如果之前改过镜像）
git remote set-url origin https://github.com/natsumezjr/attack-trace-analyzer.git

# 再次尝试
git fetch origin
git reset --hard origin/main
```

### 第三步：如果仍然失败，尝试镜像（不稳定）

```bash
# 注意：镜像服务可能不稳定，建议优先使用 SSH
git remote set-url origin https://ghproxy.com/https://github.com/natsumezjr/attack-trace-analyzer.git
git fetch origin
```

## 推荐执行顺序

1. **首先尝试方案1（SSH）**：最稳定，不受 HTTPS 端口限制，推荐长期使用
2. **如果 SSH 不可用，尝试方案3（增加超时）**：简单快速，可能解决临时网络问题
3. **如果有代理，使用方案2**：需要知道代理地址
4. **最后考虑方案4或方案5**：作为备选方案，镜像服务可能不稳定

## 注意事项

- 修改远程 URL 后，确保有相应的访问权限（SSH 密钥或 HTTPS 凭证）
- 如果使用代理，确保代理服务器可以访问 GitHub
- 某些网络环境可能同时限制 HTTPS 和 SSH，需要联系网络管理员
