"""Small in-process request monitor; no request bodies, credentials, or IPs are retained."""
from collections import deque
from threading import Lock
import time

_lock = Lock()
_started = time.monotonic()
_samples = deque(maxlen=5000)


def record(status_code: int, elapsed_ms: float) -> None:
    with _lock:
        _samples.append((time.time(), int(status_code), float(elapsed_ms)))


def snapshot(window_seconds: int = 3600) -> dict:
    cutoff = time.time() - window_seconds
    with _lock:
        rows = [row for row in _samples if row[0] >= cutoff]
    latencies = sorted(row[2] for row in rows)
    percentile = lambda p: latencies[min(len(latencies) - 1, int(len(latencies) * p))] if latencies else 0
    server_errors = sum(1 for row in rows if row[1] >= 500)
    return {
        "uptime_seconds": int(time.monotonic() - _started),
        "requests": len(rows),
        "errors": server_errors,
        "server_errors": server_errors,
        "error_rate_percent": round(100 * server_errors / len(rows), 2) if rows else 0,
        "client_errors": sum(1 for row in rows if 400 <= row[1] < 500),
        "average_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "p95_latency_ms": round(percentile(.95), 2),
        "p99_latency_ms": round(percentile(.99), 2),
    }
