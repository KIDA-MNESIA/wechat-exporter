#!/usr/bin/env bash
set -e
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
echo "安装完成！运行: .venv/bin/python main.py"
