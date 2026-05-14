from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import time


@dataclass(slots=True)
class TimingResult:
    name: str
    latency_s: float
    throughput_per_s: float


@contextmanager
def measure_latency(name: str):
    start = time.perf_counter()
    result = {"value": None}
    try:
        yield result
    finally:
        latency = time.perf_counter() - start
        result["value"] = TimingResult(
            name=name,
            latency_s=latency,
            throughput_per_s=1.0 / latency if latency > 0 else 0.0,
        )
