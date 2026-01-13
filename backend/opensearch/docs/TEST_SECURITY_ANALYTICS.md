# Security Analytics 完整测试文档

> 本文档提供完整的测试流程，帮助您一步步测试 Security Analytics 集成功能。
> 每一步都有详细说明、预期结果和检查点，可以追踪测试进度。
> 
> **重要提示**：本文档中的所有命令都是**单个命令**，使用 `curl.exe` 格式，可以在 PowerShell 中**逐个执行**，方便您理解每一步的作用。

## 📋 测试进度追踪

使用以下标记追踪测试进度：
- ⬜ 未开始
- 🔄 进行中
- ✅ 已完成
- ❌ 失败
- ⚠️ 跳过（可选步骤）

---

## 阶段 0：准备工作

### 0.1 检查 OpenSearch 运行状态 ✅

**测试目的**：确保 OpenSearch 服务正常运行

**怎么做**（PowerShell 命令，逐个执行）：

**命令 1：检查 OpenSearch 运行状态**
```powershell
curl.exe -k -u admin:OpenSearch@2024!Dev https://localhost:9200/_cluster/health
```

**说明**：
- 这个命令检查 OpenSearch 服务是否正常运行
- 返回 JSON 格式的健康状态信息
- `status: "green"` 或 `"yellow"` 表示服务正常
- 使用 `curl.exe` 命令，简单直接

**预期结果**：
- 返回 JSON，包含 `"status": "green"` 或 `"status": "yellow"`
- HTTP 状态码 200

**检查点**：
- [x] OpenSearch 服务正常运行（状态：green）
- [x] 可以访问 API

**人话解释**：
- 就像看病前先量体温，确保 OpenSearch 这个"服务器"还活着
- 如果这里就失败了，后面的测试都不用做了

---

### 0.2 检查 Security Analytics 插件 ✅

**测试目的**：确认 Security Analytics 插件已安装

**怎么做**（PowerShell 命令，逐个执行）：

**命令 2：检查 Security Analytics 插件**
```powershell
curl.exe -k -u admin:OpenSearch@2024!Dev https://localhost:9200/_cat/plugins?v
```

**说明**：
- 这个命令列出所有已安装的插件
- 在返回结果中查找 `opensearch-security-analytics`
- 如果看到这个插件，说明已安装
- 使用 `curl.exe` 命令，简单直接

**预期结果**：
- 插件列表中包含 `opensearch-security-analytics`

**检查点**：
- [x] Security Analytics 插件已安装（版本：3.4.0.0）

**人话解释**：
- Security Analytics 是一个插件，需要先安装才能用
- 就像手机要装 APP 才能用，OpenSearch 要装插件才能检测

**如果失败**：
- Docker 镜像通常已包含，如果确实没有，需要安装插件
- 参考：本文档的"阶段 1：配置 Security Analytics"部分

---

## 阶段 1：配置 Security Analytics

### 1.1 运行自动配置脚本 ⚠️

**测试目的**：自动创建 detector（检测器）

**怎么做**（PowerShell 命令，逐个执行）：

**命令 5：运行自动配置脚本**
```powershell
cd backend
```
```powershell
uv run python opensearch/setup_security_analytics.py
```

**说明**：
- 第一个命令：切换到 backend 目录
- 第二个命令：运行配置脚本，自动创建 detector
- 这个脚本会检查插件、创建 detector（如果找到规则）

**预期结果**：
- 显示 "Security Analytics 插件可用"
- 显示 "Detector 创建成功" 或 "未找到预打包规则"

**检查点**：
- [x] 脚本可以正常运行
- [x] Security Analytics 插件可用
- [ ] Detector 创建成功（需要先导入规则）

**人话解释**：
- Detector 就像"扫描任务"的配置
- 告诉 Security Analytics："你要扫描哪个索引、用什么规则、多久扫一次"
- 这个脚本会自动创建一个默认的 detector

**如果提示"未找到预打包规则"**：
- 这是正常的，说明需要手动配置规则
- 继续下一步：导入 Sigma 规则

---

### 1.2 导入 Sigma 规则 ⬜

**测试目的**：导入检测规则，让 Security Analytics 知道要检测什么

**为什么需要 Sigma 规则？**
- Security Analytics 需要规则才能检测
- 规则就像"检查清单"：遇到什么情况要报警
- Sigma 是一个通用的规则格式，可以转换成各种检测引擎的规则

**方式1：通过 OpenSearch Dashboards（推荐，图形界面）**

1. 打开 OpenSearch Dashboards: http://localhost:5601
2. 登录（admin / OpenSearch@2024!Dev）
3. 进入 Security Analytics 模块（点击左侧导航栏的 "Security Analytics"）
4. 在左侧导航栏中找到 **"Detectors"（检测器）**，点击展开
5. 在 Detectors 子菜单中点击 **"Detection rules"（检测规则）**
6. 在规则列表页面，点击 **"Import" 或 "导入"** 按钮
7. 上传 Sigma 规则文件（.yml 格式）

**注意**：
- "Detection rules" 在 "Detectors" 子菜单下，不是顶级菜单项
- 如果找不到，确保已经点击 "Detectors" 展开子菜单
- 导航路径：Security Analytics → Detectors → Detection rules

**方式2：通过 API（命令行）**

**步骤 1：准备 Sigma 规则文件**

可以使用项目中的测试规则文件 `backend/opensearch/test-rule.yml`，或者使用 `sigma-rules` 目录中的规则文件。

**步骤 2：使用 API 导入规则（PowerShell 命令）**

**命令 3：导入测试规则文件**
```powershell
cd backend\opensearch
curl.exe -k -u admin:OpenSearch@2024!Dev -X POST https://localhost:9200/_plugins/_security_analytics/rules/_upload -F "file=@test-rule.yml"
```

**说明**：
- `-k`: 跳过 SSL 证书验证
- `-u admin:OpenSearch@2024!Dev`: 用户名和密码
- `-X POST`: POST 请求
- `-F "file=@test-rule.yml"`: 上传文件（multipart/form-data 格式）
- 路径 `@test-rule.yml` 是相对于当前目录的路径

**如果要导入 sigma-rules 目录中的规则**（如果有）：
```powershell
cd backend\opensearch
curl.exe -k -u admin:OpenSearch@2024!Dev -X POST https://localhost:9200/_plugins/_security_analytics/rules/_upload -F "file=@sigma-rules/rules/windows/process_creation/win_susp_powershell_enc_cmd.yml"
```

**说明**：
- 确保规则文件路径正确（使用相对路径或绝对路径）
- 规则文件必须是有效的 YAML 格式
- OpenSearch Security Analytics 会验证规则格式

**方式3：使用预打包规则（如果有）**

**命令 4：搜索可用的预打包规则**
```powershell
curl.exe -k -u admin:OpenSearch@2024!Dev -X POST https://localhost:9200/_plugins/_security_analytics/rules/_search -H "Content-Type: application/json" -d "{\"query\":{\"match_all\":{}},\"size\":10}"
```

**说明**：
- 这个命令搜索所有可用的规则（包括预打包规则）
- 返回结果中会列出所有规则及其 ID
- 如果找到规则，可以记录规则 ID，用于创建 detector

**预期结果**：
- 规则成功导入或找到可用规则
- 可以在规则列表中看到规则

**检查点**：
- [ ] 至少有一个规则可用
- [ ] 规则已启用（enabled: true）

**人话解释**：
- 规则就是"检测清单"
- 比如："如果看到 PowerShell 执行可疑命令，就报警"
- 没有规则，Security Analytics 不知道要检测什么，所以必须有规则

**如果找不到 "Detection rules"**：
- 确保点击了左侧导航栏的 "Detectors"（检测器）来展开子菜单
- "Detection rules" 在 "Detectors" 子菜单下，不在顶级菜单
- 如果仍然找不到，可能是插件版本问题，可以尝试通过 API 导入规则

**如果失败**：
- 可以先跳过这一步，使用测试数据验证其他功能
- Security Analytics 在没有规则的情况下也能运行，只是不会生成 findings

---

### 1.3 创建或更新 Detector ⬜

**测试目的**：配置 detector，让它使用导入的规则

**如果 1.1 步骤成功创建了 detector**：
- 可以跳过这一步，或者更新 detector 添加规则

**如果 1.1 步骤失败（未找到规则）**：
- 现在有了规则，需要创建 detector 或更新现有 detector

**怎么做**：

**方式1：使用脚本（推荐）**

**命令 6：运行配置脚本创建 detector**
```powershell
cd backend
```
```powershell
uv run python opensearch/setup_security_analytics.py
```

**说明**：
- 第一个命令：切换到 backend 目录（如果还没切换）
- 第二个命令：运行脚本创建或更新 detector

**方式2：手动创建（通过 API 或 Dashboards）**

参考本文档的"阶段 1：配置 Security Analytics"部分中的手动配置方法。

**预期结果**：
- Detector 创建成功
- Detector 包含至少一个规则
- Detector 已启用（enabled: true）

**检查点**：
- [ ] Detector 创建成功
- [ ] Detector 包含规则
- [ ] Detector 已启用

**人话解释**：
- Detector = 扫描任务配置
- 规则 = 检测清单
- 现在把规则"装进"detector 里，detector 就知道要用哪些规则来扫描了

---

## 阶段 2：准备测试数据

### 2.1 初始化索引 ⬜

**测试目的**：确保所有需要的索引都已创建

**怎么做**（Python 命令，可选）：
```python
from opensearch import initialize_indices

initialize_indices()
```

**或使用测试脚本（推荐，PowerShell 命令）**：

**命令 7：使用测试脚本初始化索引**
```powershell
cd backend
```
```powershell
uv run python generate_test_data.py
```

**说明**：
- 这个脚本会初始化索引并创建测试数据
- 如果已经切换到了 backend 目录，只需执行第二个命令

**预期结果**：
- 显示 "所有索引初始化完成"
- 没有错误信息

**检查点**：
- [ ] 索引初始化成功
- [ ] 可以查询索引是否存在

**人话解释**：
- 索引就像数据库的表
- 需要先建好表，才能往里存数据
- 这一步确保所有需要的"表"都已经建好了

---

### 2.2 创建测试事件数据 ⬜

**测试目的**：创建一些测试数据，让 Security Analytics 有东西可以检测

**怎么做**：
```bash
cd backend
uv run python generate_test_data.py
```

**预期结果**：
- 显示 "存储了 X 条测试事件"
- 数据写入 `ecs-events-*` 索引

**检查点**：
- [ ] 测试数据创建成功
- [ ] 可以在 `ecs-events-*` 索引中查询到数据

**验证数据**（Python 命令，可选）：
```python
from opensearch import search, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
events = search(index_name, {"match_all": {}}, size=10)
print(f"找到 {len(events)} 条事件")
```

**或者使用 PowerShell 查询（命令 12）**：
```powershell
cd backend
```
```powershell
uv run python query_canonical_findings.py
```

**人话解释**：
- Security Analytics 需要扫描数据才能检测
- 就像警察需要有人犯罪才能抓，检测引擎需要有数据才能检测
- 这一步创建一些"模拟数据"，用来测试检测功能

---

## 阶段 3：测试 Security Analytics 检测

### 3.1 等待 Security Analytics 扫描 ⬜

**测试目的**：给 Security Analytics 时间扫描数据

**为什么需要等待？**
- Security Analytics 是按照 schedule（每1分钟）自动扫描的
- 不是立即扫描，需要等待下一个扫描周期

**怎么做**：
- 等待 1-2 分钟
- 或者查看 Security Analytics 的日志，确认扫描已完成

**检查点**：
- [ ] 等待足够的时间（1-2 分钟）
- [ ] Security Analytics 已完成扫描（可选：查看日志）

**人话解释**：
- Security Analytics 是"定时扫描"，不是"立即扫描"
- 就像闹钟，设置了每1分钟响一次
- 需要等它"响"了（完成扫描），才能看到检测结果

---

### 3.2 运行 Security Analytics 检测函数 ⬜

**测试目的**：测试 `run_security_analytics()` 函数是否能正确读取 findings

**怎么做**：
```python
from opensearch import run_security_analytics

result = run_security_analytics()
print(result)
```

或使用测试脚本（PowerShell 命令，见命令 9）：

**预期结果**：
```python
{
    "success": True,
    "findings_count": X,  # Security Analytics 返回的 findings 数量
    "converted_count": X,  # 成功转换的数量
    "stored": X,          # 成功写入 raw-findings-* 的数量
    "failed": 0,
    "duplicated": 0
}
```

**检查点**：
- [ ] 函数可以正常运行（没有报错）
- [ ] 返回 `success: True`
- [ ] 如果有 findings，`stored` > 0

**人话解释**：
- 这个函数的作用是"读取"Security Analytics 的检测结果
- Security Analytics 检测到可疑行为后，会生成 findings
- 这个函数把这些 findings 读取出来，转换成我们的格式，写入数据库

**如果没有 findings（stored = 0）**：
- 可能是正常的：测试数据没有触发规则
- 或者 Security Analytics 还在扫描中
- 或者没有配置规则
- **可以继续下一步测试**，验证其他功能

---

### 3.3 验证 findings 已写入 raw-findings-* ⬜

**测试目的**：确认 Security Analytics 的 findings 已成功写入 `raw-findings-*` 索引

**怎么做**：
```python
from opensearch import search, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"])
findings = search(index_name, {
    "term": {"custom.finding.providers": "security-analytics"}
}, size=100)

print(f"找到 {len(findings)} 条 Security Analytics findings")

# 查看第一条 finding 的结构
if findings:
    import json
    print(json.dumps(findings[0], indent=2, ensure_ascii=False, default=str))
```

**预期结果**：
- 如果 Security Analytics 生成了 findings，应该能在 `raw-findings-*` 中查询到
- Finding 的 `custom.finding.providers` 应该包含 `"security-analytics"`

**检查点**：
- [ ] 可以查询 `raw-findings-*` 索引
- [ ] 如果有 findings，格式正确
- [ ] Finding 包含 `providers: ["security-analytics"]`

**人话解释**：
- Security Analytics 的 findings 应该写入 `raw-findings-*`
- 就像把"检测报告"存到"原始告警文件夹"
- 这一步确认"报告"确实存进去了，而且格式正确

**如果没有 findings**：
- 这可能是正常的（测试数据没有触发规则）
- 可以继续下一步，测试去重功能（使用其他测试数据）

---

## 阶段 4：测试告警去重

### 4.1 创建混合告警数据 ⬜

**测试目的**：创建端侧告警和 Security Analytics 告警的混合数据，测试去重功能

**怎么做**（PowerShell 命令）：

**命令 10：创建混合告警数据**
```powershell
cd backend
```
```powershell
uv run python generate_test_data.py
```

**说明**：
这会创建：
- 端侧告警（wazuh/falco/suricata）
- 如果 Security Analytics 有 findings，也会在 `raw-findings-*` 中

**检查点**：
- [ ] `raw-findings-*` 中有多条告警
- [ ] 告警来自不同来源（端侧 + Security Analytics）

**人话解释**：
- 去重功能的作用是：把"同一个事件"的多个告警合并成一个
- 比如：Wazuh 和 Security Analytics 都检测到了同一个可疑行为
- 去重后，应该合并成一条告警，但标记来源为 `["wazuh", "security-analytics"]`

---

### 4.2 运行去重函数 ⬜

**测试目的**：测试 `deduplicate_findings()` 函数是否能正确去重

**怎么做**（Python 命令，可选）：
```python
from opensearch import deduplicate_findings

result = deduplicate_findings()
print(result)
```

**或使用测试脚本（推荐，见命令 11）**：

**预期结果**：
```python
{
    "total": X,      # Raw Findings 总数
    "merged": X,     # 被合并的告警数
    "canonical": X,  # 生成的 Canonical Findings 数量
    "errors": 0
}
```

**检查点**：
- [ ] 函数可以正常运行
- [ ] 如果有重复告警，`canonical` < `total`（说明去重了）
- [ ] 没有错误（errors = 0）

**人话解释**：
- 去重就是"合并重复的告警"
- 如果多个检测引擎都发现了同一件事，合并成一条
- 合并后的告警会标记所有来源，置信度也会提高

---

### 4.3 验证 Canonical Findings ⬜

**测试目的**：确认去重后的 Canonical Findings 格式正确

**怎么做**（Python 命令，可选）：
```python
from opensearch import search, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"])
findings = search(index_name, {"match_all": {}}, size=100)

print(f"找到 {len(findings)} 条 Canonical Findings")

# 查看是否有包含多个 providers 的 finding
for finding in findings:
    providers = finding.get("custom", {}).get("finding", {}).get("providers", [])
    if len(providers) > 1:
        print(f"Finding {finding['event']['id']} 包含多个来源: {providers}")
```

**或使用查询脚本（推荐，PowerShell 命令）**：

**命令 12：查询 Canonical Findings**
```powershell
cd backend
```
```powershell
uv run python query_canonical_findings.py
```

**说明**：
- 这个脚本会查询并显示所有规范化的 finding 数据
- 以 JSON 格式输出，方便查看结果

**预期结果**：
- Canonical Findings 格式正确
- 如果有合并的告警，`providers` 应该包含多个来源
- `stage` 应该是 `"canonical"`

**检查点**：
- [ ] Canonical Findings 格式正确
- [ ] 如果有合并，`providers` 包含多个来源
- [ ] `stage` 为 `"canonical"`

**人话解释**：
- Canonical Findings 就是"去重后的规范告警"
- 如果 Security Analytics 和端侧都检测到了，合并后的告警应该标记所有来源
- 这样就能知道"多个引擎都发现了这个问题"，置信度更高

---

## 阶段 5：完整流程测试

### 5.1 运行完整数据分析流程 ⬜

**测试目的**：测试 `run_data_analysis()` 函数（包含 Security Analytics 检测 + 去重）

**怎么做**（Python 命令，可选）：
```python
from opensearch import run_data_analysis

result = run_data_analysis()
print(result)
```

**或使用测试脚本（推荐，见命令 11 或 13）**：

**预期结果**：
```python
{
    "detection": {
        "success": True,
        "findings_count": X,
        "stored": X
    },
    "deduplication": {
        "total": X,
        "merged": X,
        "canonical": X
    }
}
```

**检查点**：
- [ ] 函数可以正常运行
- [ ] 包含两个步骤的结果（detection + deduplication）
- [ ] 没有错误

**人话解释**：
- 这个函数是"一键运行"完整流程
- 1. 读取 Security Analytics 的 findings
- 2. 去重合并所有告警
- 适合在定时任务或 API 中调用

---

### 5.2 使用测试脚本（推荐） ⬜

**测试目的**：使用完整的测试脚本，验证所有功能

**怎么做**（PowerShell 命令）：

**命令 11：运行完整测试流程**
```powershell
cd backend
```
```powershell
uv run python test_security_analytics.py
```

**说明**：
- 这个脚本运行完整的测试流程
- 包括 Security Analytics 检测、去重、验证结果

**预期结果**：
- 脚本运行完成，没有错误
- 显示各个步骤的结果
- 显示最终的 Canonical Findings 数量

**检查点**：
- [ ] 脚本可以正常运行
- [ ] 所有步骤都执行了
- [ ] 最终有结果输出

**人话解释**：
- 这个脚本是"一键测试"所有功能
- 从配置到数据到检测到去重，全流程测试
- 适合快速验证功能是否正常

---

## 阶段 6：问题排查

### 6.1 常见问题检查清单 ⬜

如果测试失败，按照以下清单排查：

**问题1：Security Analytics 插件不可用**
- [ ] OpenSearch 版本是否支持 Security Analytics？
- [ ] 插件是否已安装？（检查 `_cat/plugins`）
- [ ] OpenSearch 服务是否正常运行？

**问题2：无法创建 Detector**
- [ ] 是否有可用的规则？（至少需要一个规则）
- [ ] Detector 配置是否正确？（`detector_type` 必须小写）
- [ ] 是否有权限创建 detector？

**问题3：没有 findings**
- [ ] Security Analytics 是否已扫描数据？（等待 1-2 分钟）
- [ ] 是否有规则配置？
- [ ] 测试数据是否触发了规则？
- [ ] Detector 是否已启用？

**问题4：findings 格式不对**
- [ ] Security Analytics API 返回的格式是什么？
- [ ] 转换函数 `_convert_security_analytics_finding_to_ecs()` 是否需要调整？
- [ ] 查看实际的 finding 结构，对比预期格式

**问题5：去重不工作**
- [ ] `raw-findings-*` 中是否有数据？
- [ ] 是否有重复的告警？（相同指纹）
- [ ] 去重函数是否报错？

---

## 阶段 7：测试总结

### 7.1 记录测试结果 ⬜

**测试日期**：___________

**测试环境**：
- OpenSearch 版本：___________
- Security Analytics 插件版本：___________
- Python 版本：___________

**测试结果**：
- 阶段 0（准备工作）：✅ / ❌
- 阶段 1（配置）：✅ / ❌
- 阶段 2（测试数据）：✅ / ❌
- 阶段 3（Security Analytics 检测）：✅ / ❌
- 阶段 4（告警去重）：✅ / ❌
- 阶段 5（完整流程）：✅ / ❌

**遇到的问题**：
1. ___________
2. ___________
3. ___________

**解决方案**：
1. ___________
2. ___________
3. ___________

**备注**：
___________

---

## 下一步

测试完成后，可以：
1. 集成到生产环境（在定时任务中调用 `run_data_analysis()`）
2. 配置更多的 Sigma 规则
3. 优化检测规则，减少误报
4. 监控 Security Analytics 的性能

---

## 相关文档

- `POWERSHELL_COMMANDS.md` - PowerShell 命令快速参考（所有命令汇总）
- `API_REFERENCE.md` - API 文档
- `README.md` - 模块主文档
