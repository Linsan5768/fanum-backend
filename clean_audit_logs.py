#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
清理AuditLog表中的中文details，转换为英文
"""

import os
import sys
import sqlite3
import re

# 计算当前脚本所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "accounting.db")

# 中英文消息映射
message_map = {
    # 登录登出相关
    "用户登录 Email:": "User login - Email:",
    "用户登出 Email:": "User logout - Email:",
    
    # 表单相关
    "查看表单历史，共": "Viewed form history -",
    "条记录": "records",
    "保存草稿表单 ID:": "Saved draft form - ID:",
    "更新草稿表单 ID:": "Updated draft form - ID:",
    "提交表单 ID:": "Submitted form - ID:",
    "提交新表单 ID:": "Submitted new form - ID:",
    "类型:": "Type:",
    "金额:": "Amount:",
    "日期:": "Date:",
    
    # 其他
    "查看审计日志": "Viewed audit logs",
    "查看用户列表": "Viewed all users list"
}

def clean_audit_logs():
    """清理审计日志中的中文消息"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 获取所有日志
        cursor.execute("SELECT id, details FROM audit_logs WHERE details IS NOT NULL")
        logs = cursor.fetchall()
        
        updated_count = 0
        
        for log_id, details in logs:
            if not details:
                continue
                
            # 检查是否包含中文
            has_chinese = bool(re.search('[\u4e00-\u9fff]', details))
            if not has_chinese:
                continue
                
            # 替换中文消息
            new_details = details
            for cn, en in message_map.items():
                if cn in new_details:
                    new_details = new_details.replace(cn, en)
            
            # 如果有变化，更新数据库
            if new_details != details:
                cursor.execute("UPDATE audit_logs SET details = ? WHERE id = ?", (new_details, log_id))
                updated_count += 1
        
        conn.commit()
        print(f"✅ 成功更新 {updated_count} 条日志消息")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ 清理日志失败: {e}")
        return False

if __name__ == "__main__":
    clean_audit_logs() 