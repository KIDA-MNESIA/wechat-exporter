@echo off
chcp 65001 >nul
echo =========================================
echo 微信聊天记录导出工具 - 环境安装
echo =========================================
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
)
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
echo 安装完成！运行方式：
echo   Web 界面: .venv\Scripts\python.exe main.py
echo   MCP 服务: .venv\Scripts\python.exe mcp_server.py
pause
