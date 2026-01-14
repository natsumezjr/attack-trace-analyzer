from .killchain import run_killchain_pipeline
from .killchain_llm import create_llm_client

def main():
    # 示例：使用 LLM client（如果配置了 OPENAI_API_KEY 环境变量）
    # 否则自动回退到 MockChooser
    try:
        llm_client = create_llm_client()
    except Exception as e:
        print(f"[killchain] 无法创建 LLM client: {e}，使用 fallback")
        llm_client = None

    kcs = run_killchain_pipeline(llm_client=llm_client, persist=False)
    print(f"[killchain] produced killchains: {len(kcs)}")
    for i, kc in enumerate(kcs[:3]):
        print(f"--- kc #{i} ---")
        print(f"kc_uuid={kc.kc_uuid}")
        print(f"segments={len(kc.segments)} selected_paths={len(kc.selected_paths)}")
        print(f"explanation={kc.explanation[:120]}")