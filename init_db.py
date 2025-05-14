#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# backend/init_db.py
from models import engine, Base, init_db
# 运行这个脚本后，SQLite 数据库文件 accounting.db 应该会被创建
Base.metadata.create_all(engine)
print("数据库已初始化！")

if __name__ == "__main__":
    print("正在初始化数据库...")
    init_db()
    print("数据库初始化完成! 已创建默认分类和管理员账户(用户名: admin, 密码: admin123)")
