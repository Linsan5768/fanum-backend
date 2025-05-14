#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
更新数据库结构，添加user_role列到audit_logs表
"""

import os
import sys
import sqlite3

# 计算当前脚本所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "accounting.db")

def update_db_structure():
    """更新数据库结构，增加user_role列"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 检查audit_logs表是否存在user_role列
        cursor.execute("PRAGMA table_info(audit_logs)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'user_role' not in columns:
            print("添加user_role列到audit_logs表...")
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN user_role TEXT")
            conn.commit()
            print("✅ 数据库更新成功！")
        else:
            print("user_role列已存在，无需更新。")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ 更新数据库结构失败: {e}")
        return False

if __name__ == "__main__":
    update_db_structure() 