from dataclasses import dataclass
import os
from pathlib import Path

# 加载 .env 文件（如果存在）
try:
    from dotenv import load_dotenv
    # 从 backend/app/core/config.py 向上3层到 backend 目录
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)  # override=False: 环境变量优先于 .env
except ImportError:
    # 如果没有安装 python-dotenv，尝试手动解析 .env 文件
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key and value and key not in os.environ:
                            os.environ[key] = value
        except Exception:
            pass


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Attack Trace Analyzer API")
    app_env: str = os.getenv("APP_ENV", "dev")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
    # LLM 配置（DeepSeek）
    llm_provider: str = os.getenv("LLM_PROVIDER", "deepseek")  # deepseek, mock
    llm_api_key: str = os.getenv("DEEPSEEK_API_KEY", "")
    llm_base_url: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    llm_model: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    llm_timeout: float = float(os.getenv("LLM_TIMEOUT", "120.0"))  # 增加到 120 秒，killchain 分析需要更长时间
    llm_max_retries: int = int(os.getenv("LLM_MAX_RETRIES", "2"))


settings = Settings()
