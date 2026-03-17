"""
监控模块 - Prometheus 指标收集

提供以下指标：
- ASR (Attack Success Rate) - 攻击成功率
- FPR (False Positive Rate) - 误报率
- 延迟分布
- 拦截率
- 请求吞吐量
"""

import time
import logging
from collections import defaultdict, deque
from typing import Optional, Dict
from dataclasses import dataclass, field

from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST
)
from fastapi import Response

logger = logging.getLogger(__name__)


# ==================== Prometheus 指标定义 ====================

# 请求计数器
TOTAL_REQUESTS = Counter(
    'llama_shield_total_requests',
    'Total number of requests',
    ['endpoint']
)

SUCCESSFUL_REQUESTS = Counter(
    'llama_shield_successful_requests',
    'Number of successful requests',
    ['endpoint']
)

BLOCKED_REQUESTS = Counter(
    'llama_shield_blocked_requests',
    'Number of blocked requests',
    ['blocked_by', 'reason']
)

ERRORS = Counter(
    'llama_shield_errors',
    'Number of errors',
    ['error_type']
)

# 延迟直方图
REQUEST_LATENCY = Histogram(
    'llama_shield_request_latency_seconds',
    'Request latency in seconds',
    ['endpoint'],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

# 吞吐量
REQUESTS_PER_MINUTE = Gauge(
    'llama_shield_requests_per_minute',
    'Requests per minute'
)

# 拦截率
BLOCK_RATE = Gauge(
    'llama_shield_block_rate',
    'Current block rate (0-1)'
)

# 扫描分数
SCAN_SCORES = Histogram(
    'llama_shield_scan_scores',
    'Scan scores from firewalls',
    ['scanner', 'type'],
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
)

# 活跃连接
ACTIVE_CONNECTIONS = Gauge(
    'llama_shield_active_connections',
    'Number of active connections'
)


# ==================== 内存指标收集器 ====================

@dataclass
class MetricsCollector:
    """
    内存指标收集器

    在内存中维护最近 N 分钟的指标数据
    用于计算实时统计（ASR、FPR、延迟等）
    """

    # 配置
    window_size_minutes: int = 5
    max_samples: int = 10000

    # 内存存储
    _total_requests: int = 0
    _successful_requests: int = 0
    _blocked_requests: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _errors: int = 0

    # 滑动窗口
    _recent_requests: deque = field(default_factory=lambda: deque(maxlen=1000))
    _recent_latencies: deque = field(default_factory=lambda: deque(maxlen=10000))
    _recent_blocked: deque = field(default_factory=lambda: deque(maxlen=1000))

    # 启动时间
    _start_time: float = field(default_factory=time.time)

    def increment_total_requests(self, endpoint: str = "chat"):
        """增加总请求数"""
        self._total_requests += 1
        TOTAL_REQUESTS.labels(endpoint=endpoint).inc()

        # 记录到滑动窗口
        self._recent_requests.append({
            "timestamp": time.time(),
            "type": "total"
        })

    def increment_successful_requests(
        self,
        endpoint: str = "chat",
        duration: float = 0.0
    ):
        """增加成功请求数"""
        self._successful_requests += 1
        SUCCESSFUL_REQUESTS.labels(endpoint=endpoint).inc()

        if duration > 0:
            self._recent_latencies.append(duration)
            REQUEST_LATENCY.labels(endpoint=endpoint).observe(duration)

    def increment_blocked_requests(
        self,
        blocked_by: str,
        reason: str = "unknown"
    ):
        """增加被阻断请求数"""
        self._blocked_requests[blocked_by] += 1
        BLOCKED_REQUESTS.labels(
            blocked_by=blocked_by,
            reason=reason
        ).inc()

        # 记录到滑动窗口
        self._recent_blocked.append({
            "timestamp": time.time(),
            "blocked_by": blocked_by,
            "reason": reason
        })

    def increment_errors(self, error_type: str = "internal"):
        """增加错误数"""
        self._errors += 1
        ERRORS.labels(error_type=error_type).inc()

    def record_scan_score(
        self,
        scanner: str,
        score_type: str,
        score: float
    ):
        """记录扫描分数"""
        SCAN_SCORES.labels(scanner=scanner, type=score_type).observe(score)

    # ==================== 统计计算 ====================

    def get_total_requests(self) -> int:
        """获取总请求数"""
        return self._total_requests

    def get_successful_requests(self) -> int:
        """获取成功请求数"""
        return self._successful_requests

    def get_blocked_requests(self) -> int:
        """获取被阻断请求数"""
        return sum(self._blocked_requests.values())

    def get_block_rate(self) -> float:
        """计算拦截率"""
        if self._total_requests == 0:
            return 0.0
        return self.get_blocked_requests() / self._total_requests

    def get_average_latency(self) -> float:
        """计算平均延迟（毫秒）"""
        if not self._recent_latencies:
            return 0.0
        return (sum(self._recent_latencies) / len(self._recent_latencies)) * 1000

    def get_requests_per_minute(self) -> float:
        """计算每分钟请求数"""
        now = time.time()
        window_start = now - 60

        recent = [
            r for r in self._recent_requests
            if r["timestamp"] > window_start
        ]

        return len(recent)

    def get_asr(self) -> float:
        """
        计算 ASR (Attack Success Rate)

        ASR = 被阻断的攻击请求 / 总攻击请求

        注意：这是一个简化的近似值
        实际 ASR 需要通过 CyberSecEval 基准测试得出
        """
        blocked = self.get_blocked_requests()
        if self._total_requests == 0:
            return 0.0

        # 假设有一定比例的请求是攻击
        # 实际应该通过标记的测试集来计算
        estimated_attack_ratio = 0.1  # 10% 假设

        estimated_attacks = self._total_requests * estimated_attack_ratio
        if estimated_attacks == 0:
            return 0.0

        return blocked / estimated_attacks

    def get_fpr(self) -> float:
        """
        计算 FPR (False Positive Rate)

        FPR = 合法请求被误阻断 / 合法请求总数

        需要通过标记的测试集来准确计算
        """
        # 简化版本：假设误报率
        return 0.0

    def get_percentiles(self) -> Dict[str, float]:
        """计算延迟百分位"""
        if not self._recent_latencies:
            return {"p50": 0, "p90": 0, "p99": 0}

        sorted_latencies = sorted(self._recent_latencies)
        n = len(sorted_latencies)

        return {
            "p50": sorted_latencies[int(n * 0.5)] * 1000,
            "p90": sorted_latencies[int(n * 0.9)] * 1000,
            "p99": sorted_latencies[int(n * 0.99)] * 1000
        }

    def get_uptime(self) -> float:
        """获取运行时间（秒）"""
        return time.time() - self._start_time

    def get_all_metrics(self) -> dict:
        """获取所有指标"""
        return {
            "total_requests": self.get_total_requests(),
            "successful_requests": self.get_successful_requests(),
            "blocked_requests": self.get_blocked_requests(),
            "block_rate": round(self.get_block_rate(), 4),
            "asr": round(self.get_asr(), 4),
            "fpr": round(self.get_fpr(), 4),
            "average_latency_ms": round(self.get_average_latency(), 2),
            "requests_per_minute": round(self.get_requests_per_minute(), 2),
            "percentiles": self.get_percentiles(),
            "uptime_seconds": round(self.get_uptime(), 2),
            "blocked_by": dict(self._blocked_requests)
        }


# ==================== Prometheus 端点 ====================

async def metrics():
    """Prometheus 指标端点"""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# ==================== 全局实例 ====================

_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """获取指标收集器单例"""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics
