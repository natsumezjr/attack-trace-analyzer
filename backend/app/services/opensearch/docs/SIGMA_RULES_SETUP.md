# Sigma规则库设置指南

## 📋 概述

Sigma规则库包含4000+个安全检测规则，**已配置为Git Submodule**，不直接提交到git仓库（文件太多，会增大仓库体积）。

## ✅ 当前状态

**Git Submodule已配置完成！**

- ✅ Submodule已添加：`backend/opensearch/sigma-rules`
- ✅ 指向仓库：`https://github.com/SigmaHQ/sigma.git`
- ✅ 当前版本：`r2025-12-01-26-g6fe7343bf`
- ⏳ 等待提交：需要提交 `.gitmodules` 和 `backend/opensearch/sigma-rules` 到git仓库

## 🎯 推荐方案：Git Submodule

### 为什么使用Git Submodule？

1. **不占用主仓库空间**：规则库作为独立仓库，不增加主仓库体积
2. **版本控制**：可以跟踪特定版本的规则库
3. **易于更新**：可以独立更新规则库
4. **团队协作**：所有成员使用相同版本的规则库

### 设置步骤

#### 1. 添加Submodule（项目维护者）

**如果sigma-rules目录已存在（当前情况）**：

```powershell
cd d:\Coding\Project\attack-trace-analyzer

# 方法1：删除现有目录，重新添加为submodule（推荐）
cd backend\opensearch
Remove-Item -Recurse -Force sigma-rules
cd ..\..
git submodule add https://github.com/SigmaHQ/sigma.git backend/opensearch/sigma-rules
git add .gitmodules backend/opensearch/sigma-rules
git commit -m "添加sigma规则库作为git submodule"
```

**如果sigma-rules目录不存在**：

```bash
cd d:\Coding\Project\attack-trace-analyzer
git submodule add https://github.com/SigmaHQ/sigma.git backend/opensearch/sigma-rules
git add .gitmodules backend/opensearch/sigma-rules
git commit -m "添加sigma规则库作为git submodule"
```

#### 2. 克隆项目（团队成员）

```bash
# 克隆项目（包含submodule）
git clone --recurse-submodules <repository-url>

# 或者先克隆项目，再初始化submodule
git clone <repository-url>
cd attack-trace-analyzer
git submodule update --init --recursive
```

#### 3. 更新规则库

```bash
cd backend/opensearch/sigma-rules
git pull origin master
cd ../../..
git add backend/opensearch/sigma-rules
git commit -m "更新sigma规则库到最新版本"
git push
```

#### 4. 切换到特定版本（可选）

如果需要使用特定版本的规则库：

```bash
cd backend/opensearch/sigma-rules
git checkout <tag或commit-hash>
cd ../../..
git add backend/opensearch/sigma-rules
git commit -m "锁定sigma规则库版本"
```

## 🚀 常用操作

### 克隆包含Submodule的项目

```bash
# 方式1：克隆时自动初始化（推荐）
git clone --recurse-submodules <repository-url>

# 方式2：先克隆，再初始化
git clone <repository-url>
cd attack-trace-analyzer
git submodule update --init --recursive
```

### 更新规则库

```bash
cd backend/opensearch/sigma-rules
git pull origin master
cd ../../..
git add backend/opensearch/sigma-rules
git commit -m "更新sigma规则库到最新版本"
git push
```

### 切换到特定版本

```bash
cd backend/opensearch/sigma-rules
git checkout <tag或commit-hash>
cd ../../..
git add backend/opensearch/sigma-rules
git commit -m "锁定sigma规则库版本"
```

### 查看Submodule状态

```bash
git submodule status
cat .gitmodules
```

## 🔧 故障排除

### Submodule显示为未初始化

```bash
git submodule update --init --recursive
```

### Submodule显示为已修改

```bash
cd backend/opensearch/sigma-rules
git status
# 如果有未提交的更改，提交或丢弃
```

## 📚 相关文档

- [部署指南](./DEPLOYMENT.md) - 完整的部署步骤
- [API参考文档](./API_REFERENCE.md) - API使用说明

## 📝 当前状态

当前 `sigma-rules` 目录：
- ✅ **已配置为Git Submodule**
- ✅ `.gitmodules` 文件已创建
- ✅ Submodule已克隆并初始化
- ⏳ 等待提交到git仓库

## ✅ 配置完成

Git Submodule已成功配置！当前状态：

```bash
$ git submodule status
6fe7343bf79306884b05837d5e03bcbcb141ce50 backend/opensearch/sigma-rules (r2025-12-01-26-g6fe7343bf)
```

## 🚀 下一步操作

### 提交Submodule配置

```powershell
cd d:\Coding\Project\attack-trace-analyzer
git add .gitmodules backend/opensearch/sigma-rules
git commit -m "添加sigma规则库作为git submodule"
git push
```

### 验证配置

```bash
# 查看submodule状态
git submodule status

# 查看.gitmodules配置
cat .gitmodules
```

## ✅ 验证配置

配置完成后，验证：

```bash
# 检查submodule状态
git submodule status

# 应该看到类似输出：
# abc1234... backend/opensearch/sigma-rules (heads/master)
```

## 📚 常用命令

### 更新Submodule到最新版本

```bash
cd backend/opensearch/sigma-rules
git pull origin master
cd ../../..
git add backend/opensearch/sigma-rules
git commit -m "更新sigma规则库"
```

### 克隆包含Submodule的项目

```bash
git clone --recurse-submodules <repository-url>
```

### 初始化已存在的Submodule

```bash
git submodule update --init --recursive
```

### 查看Submodule信息

```bash
git submodule status
cat .gitmodules
```

## 📚 相关文档

- [部署指南](./DEPLOYMENT.md) - 完整的部署步骤
- [Sigma规则库README](../sigma-rules/README.md) - 规则库使用说明
- [Git Submodule文档](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
