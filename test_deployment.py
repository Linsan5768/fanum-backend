#!/usr/bin/env python
"""
简单测试脚本，用于验证后端部署是否成功。
运行方式： python test_deployment.py [URL]
如果不提供URL，默认使用 http://127.0.0.1:5002
"""

import sys
import requests
import json

def test_backend(base_url):
    print(f"测试后端 API: {base_url}")
    
    # 测试连接
    try:
        print("\n1. 测试服务器连接...")
        response = requests.get(f"{base_url}/api/get_categories")
        print(f"✅ 服务器响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ 获取到 {len(data)} 个类别")
        else:
            print(f"❌ API 返回错误: {response.text}")
            return False
    except Exception as e:
        print(f"❌ 连接失败: {str(e)}")
        return False
        
    # 测试记录获取
    try:
        print("\n2. 测试获取记账记录...")
        response = requests.get(f"{base_url}/api/get_records")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ 获取到 {len(data)} 条记录")
        else:
            print(f"❌ 获取记录失败: {response.text}")
            return False
    except Exception as e:
        print(f"❌ 获取记录失败: {str(e)}")
        return False
    
    # 测试静态文件服务
    try:
        print("\n3. 测试前端文件服务...")
        response = requests.get(f"{base_url}/")
        if response.status_code == 200 and "text/html" in response.headers.get('Content-Type', ''):
            print("✅ 前端HTML文件正常服务")
        else:
            print(f"❌ 前端文件服务异常: 状态码 {response.status_code}, 内容类型 {response.headers.get('Content-Type')}")
            return False
    except Exception as e:
        print(f"❌ 前端文件服务失败: {str(e)}")
        return False
    
    print("\n✅ 所有测试通过！后端部署成功。")
    return True

if __name__ == "__main__":
    # 获取命令行参数，如果没有提供，则使用默认值
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5002"
    
    # 运行测试
    test_backend(base_url) 