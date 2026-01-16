from dataclasses import dataclass
import os
from pathlib import Path

# 加载 .env 文件（如果存在）
try:
    from dotenv import load_dotenv
    # 从 backend/app/core/config.py 向上3层到 backend 目录
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        # 读取文件内容用于调试（不包含敏感信息）
        with open(env_path, "r", encoding="utf-8") as f:
            env_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        print(f"[INFO] 已加载环境变量文件: {env_path}")
        print(f"[INFO] .env 文件包含 {len(env_lines)} 行配置")
        # 检查关键配置是否存在
        has_llm_provider = any("LLM_PROVIDER" in line for line in env_lines)
        has_api_key = any("DEEPSEEK_API_KEY" in line for line in env_lines)
        print(f"[INFO] .env 文件检查: LLM_PROVIDER={'存在' if has_llm_provider else '不存在'}, DEEPSEEK_API_KEY={'存在' if has_api_key else '不存在'}")
        load_dotenv(env_path, override=False)  # override=False: 环境变量优先于 .env
    else:
        print(f"[INFO] 未找到 .env 文件: {env_path}，使用系统环境变量")
        print(f"[INFO] 请确认 .env 文件路径是否正确")
except ImportError:
    # 如果没有安装 python-dotenv，尝试手动解析 .env 文件
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        print(f"[WARN] 未安装 python-dotenv，尝试手动解析 .env 文件: {env_path}")
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
            print(f"[INFO] 手动加载 .env 文件成功")
        except Exception as e:
            print(f"[WARN] 手动加载 .env 文件失败: {e}")


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
