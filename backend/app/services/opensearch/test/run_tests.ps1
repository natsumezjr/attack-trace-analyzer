# PowerShell 测试运行脚本
# 用于Windows环境统一运行所有测试并生成报告

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Green
Write-Host "OpenSearch 模块测试套件" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# 获取脚本目录
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# 检查OpenSearch服务
Write-Host "检查OpenSearch服务..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "https://localhost:9200" `
        -Method Get `
        -Headers @{Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:OpenSearch@2024!Dev"))} `
        -SkipCertificateCheck `
        -TimeoutSec 5 `
        -ErrorAction SilentlyContinue
    
    if ($response.StatusCode -eq 200) {
        Write-Host "✓ OpenSearch服务运行正常" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ OpenSearch服务不可用" -ForegroundColor Red
    Write-Host "请先启动OpenSearch服务："
    Write-Host "  docker-compose up -d opensearch"
    exit 1
}

# 进入项目目录
Set-Location "$ProjectRoot\backend"

# 运行单元测试
Write-Host ""
Write-Host "运行单元测试..." -ForegroundColor Yellow
uv run pytest opensearch/test/test_unit_opensearch.py `
    opensearch/test/test_analysis_incremental.py `
    -v --tb=short -m "unit"
if ($LASTEXITCODE -ne 0) {
    Write-Host "单元测试失败" -ForegroundColor Red
    exit 1
}

# 运行集成测试
Write-Host ""
Write-Host "运行集成测试..." -ForegroundColor Yellow
uv run pytest opensearch/test/test_system_opensearch.py `
    opensearch/test/test_integration_full.py `
    -v --tb=short -m "integration"
if ($LASTEXITCODE -ne 0) {
    Write-Host "集成测试失败" -ForegroundColor Red
    exit 1
}

# 生成测试报告
Write-Host ""
Write-Host "生成测试报告..." -ForegroundColor Yellow
uv run pytest opensearch/test/ `
    --html=test_report.html `
    --self-contained-html `
    --cov=opensearch `
    --cov-report=html `
    --cov-report=term

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "测试完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "测试报告已生成："
Write-Host "  - HTML报告: backend\test_report.html"
Write-Host "  - 覆盖率报告: backend\htmlcov\index.html"
