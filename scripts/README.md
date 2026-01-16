# Scripts 目录说明

本目录包含 Attack Trace Analyzer 的所有脚本和工具。

## 📁 目录结构

### 1. 靶场编排/
**用途**：快速启动和管理靶场环境

**包含**：
- `start.sh` - 一键启动靶场（支持模块化启动）
- `close.sh` - 一键关闭靶场（支持模块化关闭）
- `attack_basic.sh` - 基础 6 步攻击剧本（与 `docs/20-需求与验收/22-攻击场景与复现剧本.md` 一致）
- `check_ports.sh` - 端口检查工具
- `c2_config/` - C2 服务配置文件（DNS+HTTP）

**使用场景**：
- 快速演示（2-3 分钟完成攻击模拟）
- 验收测试
- 日常开发调试

**快速开始**：
```bash
cd 靶场编排
./start.sh          # 启动靶场
./attack_basic.sh   # 执行攻击
./close.sh          # 关闭靶场
```

---

### 2. apt_simulation/
**用途**：详细的 APT 攻击模拟工具包（基于 Atomic Red Team）

**包含**：
- `README.md` - 工具包总览
- `quick_start.md` - 5 分钟快速上手
- `detailed_guide.md` - 完整教程
- `USAGE_GUIDE.md` - 文件说明与使用指南
- `scripts/` - 可执行脚本
  - `apt_atomic_manual.sh` - 12 阶段完整 APT 攻击
  - `setup_ssh.sh` - SSH 免密配置
  - `verify_detection.sh` - 检测验证
- `attack_scenarios/` - 攻击剧本详细说明

**使用场景**：
- 深入教学演示（10-15 分钟完成完整攻击链）
- 完整 APT 模拟
- 课程答辩展示

**快速开始**：
```bash
cd apt_simulation
cat README.md
cat quick_start.md
cd scripts
./setup_ssh.sh              # 首次使用：配置 SSH
./apt_atomic_manual.sh      # 执行攻击
./verify_detection.sh       # 验证结果
```

---

## 🧪 其他工具

### 测试工具：`../tests/e2e/mock_cli/`
**用途**：端到端测试的模拟客户机（Python FastAPI）

**说明**：
- 提供 4 个模拟客户机，生成预定义的 APT 攻击数据
- 用于开发阶段快速验证系统功能
- 不需要真实攻击环境，适合本地测试

**使用场景**：
- 开发过程中快速测试数据流
- 验证中心机轮询、入库、分析功能
- 不需要启动完整的靶场环境

**快速开始**：
```bash
cd ../tests/e2e/mock_cli
./start_clients.sh   # 启动 4 个模拟客户机
# 数据会自动轮询到中心机
# 在前端查看结果
```

**区别对比**：
| 工具 | 数据来源 | 环境要求 | 主要用途 |
|------|---------|---------|---------|
| `靶场编排/attack_basic.sh` | 真实攻击命令 | 靶场环境（Linux + Falco/Suricata） | 演示答辩 |
| `apt_simulation/` | 真实攻击命令 | 靶场环境 + SSH 多机 | 深入教学 |
| `tests/e2e/mock_cli/` | Python 模拟数据 | 本地 Python 环境 | 开发测试 |

---

## 🎯 如何选择使用哪个工具？

### 使用 `靶场编排/attack_basic.sh` 当：
- ✅ 需要快速演示（2-3 分钟）
- ✅ 执行验收测试
- ✅ 验证基础功能
- ✅ 与官方文档完全对齐

**攻击步骤**：
- Step A: C2 解析与连通
- Step B: 下载载荷到受害机
- Step C: 执行良性脚本
- Step D: SSH 会话模拟横向移动
- Step E: 只读发现与收集
- Step F: 清理回滚

### 使用 `apt_simulation/` 当：
- ✅ 需要详细讲解 APT 攻击链
- ✅ 展示完整的安全事件
- ✅ 课程答辩演示
- ✅ 需要更丰富的攻击场景

**攻击阶段**（12 阶段）：
- 初始访问（Initial Access）
- 执行（Execution）
- 持久化（Persistence）
- 权限提升（Privilege Escalation）
- 防御规避（Defense Evasion）
- 凭证访问（Credential Access）
- 发现（Discovery）
- 横向移动（Lateral Movement）
- 收集（Collection）
- 命令与控制（Command and Control）
- 渗出（Exfiltration）
- 影响（Impact）

---

## 📚 相关文档

### 攻击剧本定义
- 基础剧本（6 步）：`docs/20-需求与验收/22-攻击场景与复现剧本.md`
- 详细剧本（12 阶段）：`scripts/apt_simulation/attack_scenarios/scenario_overview.md`

### 靶场部署
- 部署指南：`docs/90-运维与靶场/91-靶场部署.md`
- 一键编排：`docs/90-运维与靶场/92-一键编排.md`
- C2 部署：`docs/90-运维与靶场/93-C2部署与证据点.md`

### 验证与排障
- 验证清单：`docs/90-运维与靶场/94-验证清单.md`
- 重置复现：`docs/90-运维与靶场/95-重置复现与排障.md`

---

## 📊 工具对比

| 维度 | 靶场编排/attack_basic.sh | apt_simulation/ |
|------|------------------------|-----------------|
| **复杂度** | 简单 6 步（Step A-F） | 复杂 12 阶段 |
| **文档完整性** | 基础 README | 完整文档体系 |
| **与官方文档对齐** | ✅ 完全对齐 | ❌ 需要映射 |
| **使用场景** | 快速演示、验收 | 深入教学、完整模拟 |
| **执行时间** | 2-3 分钟 | 10-15 分钟 |
| **依赖** | 仅需靶场环境 | 需要 SSH 配置、多机协同 |

---

## 🚀 典型使用流程

### 场景 1：日常开发调试

```bash
cd scripts/靶场编排
./start.sh              # 启动靶场
./attack_basic.sh       # 执行基础攻击
# 在前端查看结果：http://localhost:3000
./close.sh              # 关闭靶场
```

### 场景 2：课程答辩演示

```bash
cd scripts/apt_simulation
cat README.md                          # 理解攻击剧本
cd scripts
./setup_ssh.sh                         # 配置 SSH（首次）
./apt_atomic_manual.sh                 # 执行完整攻击
./verify_detection.sh                  # 验证结果
# 在前端展示图谱和溯源分析
```

### 场景 3：验收测试

```bash
cd scripts/靶场编排
./start.sh              # 启动靶场
./check_ports.sh        # 验证端口
./attack_basic.sh       # 执行攻击
# 按照 docs/90-运维与靶场/94-验证清单.md 验证
./close.sh              # 关闭靶场
```

---

## ⚠️ 注意事项

1. **脚本权限**：首次使用前需要设置可执行权限
   ```bash
   chmod +x scripts/靶场编排/*.sh
   chmod +x scripts/apt_simulation/scripts/*.sh
   ```

2. **环境变量**：确保靶场脚本中的 `BASE` 和 `REPO` 路径正确配置

3. **SSH 配置**：使用 `apt_simulation/` 前需要先配置 SSH 免密登录

4. **网络连通**：确保中心机与客户机网络互通

5. **数据库清空**：生产环境慎用 `./close.sh -c`，会清空所有数据

---

## 📞 需要帮助？

### 问题 1：不知道从哪里开始
**解决**：
- 快速演示 → 使用 `靶场编排/`
- 深入教学 → 使用 `apt_simulation/`

### 问题 2：执行脚本出错
**解决**：
- 检查脚本权限：`chmod +x *.sh`
- 查看错误日志
- 参考 `docs/90-运维与靶场/95-重置复现与排障.md`

### 问题 3：不理解攻击剧本
**解决**：
- 基础剧本：`docs/20-需求与验收/22-攻击场景与复现剧本.md`
- 详细剧本：`scripts/apt_simulation/attack_scenarios/scenario_overview.md`

---

**祝你使用愉快！** 🎉
