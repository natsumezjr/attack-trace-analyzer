from .killchain import KillChain, run_killchain_pipeline
from .killchain_llm import create_llm_client
from typing import List

def analyze_killchain(kc_uuid: str) -> List[KillChain]:
    import os
    llm_provider = os.getenv("LLM_PROVIDER", "not_set")
    has_api_key = bool(os.getenv("DEEPSEEK_API_KEY"))
    print(f"[DEBUG] analyze_killchain: LLM_PROVIDER={llm_provider}, has_api_key={has_api_key}")
    
    try:
        llm_client = create_llm_client()
        client_type = type(llm_client).__name__
        print(f"[DEBUG] LLM client created: {client_type}")
        
        # 检查 client 是否有 choose 方法
        if hasattr(llm_client, "choose"):
            print(f"[DEBUG] LLM client has choose method")
        else:
            print(f"[DEBUG] WARNING: LLM client does NOT have choose method")
            
        # 如果是 MockChooser，说明使用了 mock 模式
        if client_type == "MockChooser":
            print(f"[DEBUG] Using MockChooser (mock mode)")
        elif client_type == "LLMChooser":
            print(f"[DEBUG] Using LLMChooser (real LLM mode)")
            # 检查 chat_complete 是否设置
            if hasattr(llm_client, "chat_complete"):
                if llm_client.chat_complete is None:
                    print(f"[DEBUG] WARNING: LLMChooser.chat_complete is None")
                else:
                    print(f"[DEBUG] LLMChooser.chat_complete is set")
    except Exception as e:
        print(f"[killchain] 无法创建 LLM client: {e}，使用 fallback")
        import traceback
        traceback.print_exc()
        llm_client = None
    
    kcs = run_killchain_pipeline(kc_uuid=kc_uuid, llm_client=llm_client, persist=True)
    return kcs

__all__ = ["analyze_killchain"]
