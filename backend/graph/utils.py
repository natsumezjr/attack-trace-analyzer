# 时间解析工具
from datetime import datetime
def _parse_ts_to_float(ts: str | None) -> float:
    """
    将 UTC 时间字符串 (ISO 8601) 或 数字字符串 转换为 Unix 时间戳 (float)
    例如: "2023-10-27T10:00:00Z" -> 1698400800.0
    """
    if not ts:
        return 0.0
    # 1. 尝试直接转换为 float (兼容数据库里存的已经是秒数的情况)
    try:
        return float(ts)
    except ValueError:
        pass

    # 2. 解析 ISO 8601 格式字符串
    try:
        # 处理 'Z' 后缀：Python 3.11 以前的 fromisoformat 不支持 'Z' 结尾，
        # 需要将其替换为 '+00:00' 来表示 UTC 时区。
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
            
        # 解析字符串为 datetime 对象
        dt = datetime.fromisoformat(ts)
        
        # 转换为 Unix 时间戳 (float 秒数)
        return dt.timestamp()
        
    except (ValueError, TypeError):
        # 如果格式依然无法解析，返回 0.0 作为兜底，防止程序崩溃
        return 0.0