#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 2：索引初始化测试"""
import sys
import os

# 添加项目路径：从 scripts/ 目录向上找到 backend/ 目录
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

# 将 backend/ 目录添加到路径，这样就可以导入 app.services.opensearch
sys.path.insert(0, backend_dir)

from app.services.opensearch.index import initialize_indices

if __name__ == '__main__':
    print("=" * 60)
    print("步骤 2：索引初始化测试")
    print("=" * 60)
    initialize_indices()
    print("\n[OK] 索引初始化完成")
