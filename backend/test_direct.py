# test_direct.py
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from app.services.analyze import analyze_killchain
import uuid

if __name__ == "__main__":
    kc_uuid = str(uuid.uuid4())
    print(f"运行 killchain 分析，UUID: {kc_uuid}")
    
    killchains = analyze_killchain(kc_uuid)
    
    print(f"\n生成了 {len(killchains)} 个 killchain")
    for i, kc in enumerate(killchains, 1):
        print(f"\nKillChain #{i}:")
        print(f"  UUID: {kc.kc_uuid}")
        print(f"  可信度: {kc.confidence:.2f}")
        print(f"  路径数: {len(kc.selected_paths)}")
        print(f"  解释文本: {kc.explanation}")