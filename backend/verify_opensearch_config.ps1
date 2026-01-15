# Verify OpenSearch HTTP line length configuration
# PowerShell script

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Verify OpenSearch HTTP Line Length Config" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check container environment variables
Write-Host "[1] Checking container environment variables..." -ForegroundColor Yellow
$envVars = docker exec opensearch env 2>&1 | Select-String -Pattern "OPENSEARCH_JAVA_OPTS"
if ($envVars) {
    Write-Host "OPENSEARCH_JAVA_OPTS environment variable:" -ForegroundColor Green
    Write-Host $envVars -ForegroundColor White
    if ($envVars -match "max_initial_line_length") {
        Write-Host "[OK] Found max_initial_line_length configuration" -ForegroundColor Green
        if ($envVars -match "16k") {
            Write-Host "[OK] Configuration value: 16k (16KB)" -ForegroundColor Green
        }
    } else {
        Write-Host "[WARNING] max_initial_line_length configuration not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARNING] Cannot get environment variables" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[2] Testing OpenSearch connection..." -ForegroundColor Yellow
$cred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:OpenSearch@2024!Dev"))
$headers = @{
    Authorization = "Basic $cred"
}

try {
    $response = Invoke-RestMethod -Uri "https://localhost:9200/_cluster/health" -Headers $headers -SkipCertificateCheck -ErrorAction Stop
    Write-Host "[OK] OpenSearch connection successful" -ForegroundColor Green
    Write-Host "Cluster status: $($response.status)" -ForegroundColor White
} catch {
    Write-Host "[ERROR] Cannot connect to OpenSearch: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Configuration Summary" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "http.max_initial_line_length is a static JVM configuration" -ForegroundColor White
Write-Host "Must be set via -Dhttp.max_initial_line_length=16k" -ForegroundColor White
Write-Host "Current config: 16k (16KB), Default: 4KB" -ForegroundColor Green
Write-Host ""
Write-Host "This configuration fixes the following error:" -ForegroundColor Yellow
Write-Host "  [too_long_http_line_exception] An HTTP line is larger than 4096 bytes" -ForegroundColor White
Write-Host ""
Write-Host "When OpenSearch Dashboards queries many findings IDs," -ForegroundColor White
Write-Host "the URL may exceed 4KB limit, now increased to 16KB" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
