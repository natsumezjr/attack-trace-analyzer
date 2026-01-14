# Graph module test runner (Windows / PowerShell)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)

Set-Location $BackendDir

Write-Host "Running graph module tests..." -ForegroundColor Green
uv run pytest tests/graph -v --tb=short
