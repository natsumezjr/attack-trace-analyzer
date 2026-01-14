from .killchain import KillChain, run_killchain_pipeline
from .killchain_llm import create_llm_client
from typing import List

def analyze_killchain(kc_uuid: str) -> List[KillChain]:
    try:
        llm_client = create_llm_client()
    except Exception as e:
        print(f"[killchain] 无法创建 LLM client: {e}，使用 fallback")
        llm_client = None
        kcs = run_killchain_pipeline(kc_uuid, llm_client=llm_client, persist=False)
        return kcs

__all__ = ["analyze_killchain"]
