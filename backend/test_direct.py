# test_direct.py
import sys
import requests
import uuid
import json

# 远程后端地址
BACKEND_URL = "http://10.92.35.13:8001"

def test_killchain_api():
    """通过 API 调用远程 killchain 分析"""
    url = f"{BACKEND_URL}/api/v1/analysis/killchain/test"
    
    print(f"连接到后端: {BACKEND_URL}")
    print(f"调用 API: {url}")
    
    try:
        response = requests.post(url, timeout=300)  # 5分钟超时
        response.raise_for_status()
        
        result = response.json()
        
        if result.get("success"):
            data = result.get("result", {})
            kc_uuid = data.get("kc_uuid")
            killchain_count = data.get("killchain_count", 0)
            killchains = data.get("killchains", [])
            
            print(f"\n✅ KillChain 分析完成！")
            print(f"UUID: {kc_uuid}")
            print(f"生成了 {killchain_count} 个 killchain\n")
            
            for i, kc in enumerate(killchains, 1):
                print(f"KillChain #{i}:")
                print(f"  UUID: {kc.get('kc_uuid')}")
                print(f"  可信度: {kc.get('confidence', 0):.2f}")
                print(f"  段数: {kc.get('segment_count', 0)}")
                print(f"  路径数: {kc.get('selected_path_count', 0)}")
                print(f"  解释: {kc.get('explanation', '')[:100]}...")
                print()
            
            # 显示 Neo4j 查询命令
            if killchains:
                best_kc_uuid = killchains[0].get('kc_uuid', kc_uuid)
                print("=" * 60)
                print("Neo4j 查询命令（复制到 Neo4j Browser）:")
                print("=" * 60)
                print(f"""
MATCH (n)-[r]->(m)
WHERE r.\`custom.killchain.uuid\` = '{best_kc_uuid}'
RETURN n, r, m
LIMIT 200
""")
        else:
            print(f"❌ 分析失败: {result.get('message', 'Unknown error')}")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
    except requests.exceptions.RequestException as e:
        print(f"❌ 连接失败: {e}")
        print(f"请确认后端服务正在运行: {BACKEND_URL}")
        sys.exit(1)

if __name__ == "__main__":
    test_killchain_api()