"""
Detector触发锁机制（防止并发冲突）
"""
import threading
from typing import Optional
from datetime import datetime, timedelta

# 单进程锁（适合单机后端）
_detector_locks: dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()  # 保护_detector_locks的锁


def get_detector_lock(detector_id: str) -> threading.Lock:
    """获取指定detector的锁（线程安全）"""
    with _locks_lock:
        if detector_id not in _detector_locks:
            _detector_locks[detector_id] = threading.Lock()
        return _detector_locks[detector_id]


# 记录正在进行的触发操作（用于单飞模式）
_active_triggers: dict[str, tuple[datetime, threading.Event]] = {}
_active_triggers_lock = threading.Lock()


def register_trigger(detector_id: str, timeout_seconds: int = 60) -> tuple[bool, Optional[threading.Event]]:
    """
    注册一个触发操作（单飞模式）
    
    返回：
    - (True, None): 当前线程负责执行触发
    - (False, event): 其他线程正在触发，等待event信号
    """
    with _active_triggers_lock:
        now = datetime.now()
        
        # 清理过期的触发记录
        expired_ids = [
            did for did, (start_time, _) in _active_triggers.items()
            if (now - start_time).total_seconds() > timeout_seconds
        ]
        for did in expired_ids:
            del _active_triggers[did]
        
        # 检查是否已有活跃触发
        if detector_id in _active_triggers:
            _, event = _active_triggers[detector_id]
            return False, event
        
        # 注册新的触发
        event = threading.Event()
        _active_triggers[detector_id] = (now, event)
        return True, None


def complete_trigger(detector_id: str):
    """标记触发完成，通知等待的线程"""
    with _active_triggers_lock:
        if detector_id in _active_triggers:
            _, event = _active_triggers[detector_id]
            del _active_triggers[detector_id]
            event.set()  # 通知等待的线程
