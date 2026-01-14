from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Attack Trace Analyzer API")
    app_env: str = os.getenv("APP_ENV", "dev")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
    # LLM 配置
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai")  # openai, mock
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
    openai_timeout: float = float(os.getenv("OPENAI_TIMEOUT", "30.0"))
    openai_max_retries: int = int(os.getenv("OPENAI_MAX_RETRIES", "2"))


settings = Settings()
