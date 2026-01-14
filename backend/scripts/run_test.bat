@echo off
REM 便捷测试脚本 - 依次执行数据导入和分析 (Windows)

echo ==========================================
echo KillChain 测试流程
echo ==========================================
echo.

REM 步骤 1: 导入测试数据
echo [步骤 1/2] 导入测试数据到 Neo4j...
echo ----------------------------------------
python scripts\import_test_data.py

if errorlevel 1 (
    echo.
    echo 错误: 数据导入失败
    exit /b 1
)

echo.
echo ----------------------------------------
echo.

REM 步骤 2: 运行分析
echo [步骤 2/2] 运行 KillChain 分析...
echo ----------------------------------------
python scripts\test_analyze.py

if errorlevel 1 (
    echo.
    echo 错误: 分析失败
    exit /b 1
)

echo.
echo ==========================================
echo 测试流程完成！
echo ==========================================
pause
