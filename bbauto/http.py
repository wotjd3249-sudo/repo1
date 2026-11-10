"""레이트리밋이 적용된 HTTP 세션 + 동시성 제어."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

import requests


class RateLimiter:
    """간단한 토큰 간격 기반 레이트리밋 (스레드 안전)."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                time.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + self.min_interval


class HttpClient:
    def __init__(self, user_agent: str, timeout: int, rps: float):
        self.timeout = timeout
        self.limiter = RateLimiter(rps)
        self._local = threading.local()
        self.user_agent = user_agent

    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"User-Agent": self.user_agent})
            self._local.session = s
        return s

    def get(self, url: str, **kw) -> requests.Response | None:
        self.limiter.wait()
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        kw.setdefault("verify", True)
        try:
            return self._session().get(url, **kw)
        except requests.RequestException:
            return None


def run_parallel(items: Iterable, fn: Callable, concurrency: int):
    """items 각각에 fn 을 병렬 적용, 결과 리스트 반환 (None 제외)."""
    results = []
    items = list(items)
    if not items:
        return results
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception:
                r = None
            if r is not None:
                if isinstance(r, list):
                    results.extend(r)
                else:
                    results.append(r)
    return results
