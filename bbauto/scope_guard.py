"""Scope Guard — 모든 요청 대상이 권한 범위 내인지 강제."""
from __future__ import annotations

from urllib.parse import urlparse

from .config import Scope


def _normalize_host(host: str) -> str:
    host = host.strip().lower()
    if "://" in host:
        host = urlparse(host).hostname or ""
    # 포트 제거
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def _match_domain(host: str, pattern: str) -> bool:
    host = _normalize_host(host)
    pattern = pattern.strip().lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        # 와일드카드는 서브도메인만 매칭 (apex 는 별도 등록 필요)
        return host.endswith("." + base)
    return host == pattern


class ScopeGuard:
    """in-scope 와 일치하고 out-of-scope 가 아닌 대상만 허용."""

    def __init__(self, scope: Scope):
        self.scope = scope

    def host_in_scope(self, host: str) -> bool:
        host = _normalize_host(host)
        if not host:
            return False
        # out-of-scope 우선
        for pat in self.scope.out_domains:
            if _match_domain(host, pat):
                return False
        for pat in self.scope.in_domains:
            if _match_domain(host, pat):
                return True
        return False

    def url_in_scope(self, url: str) -> bool:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.hostname or ""
        # out-of-scope URL 명시 차단
        for u in self.scope.out_urls:
            if url.startswith(u):
                return False
        # in-scope URL 명시 허용
        for u in self.scope.in_urls:
            if url.startswith(u):
                return True
        return self.host_in_scope(host)

    def filter_hosts(self, hosts) -> list[str]:
        seen, out = set(), []
        for h in hosts:
            nh = _normalize_host(h)
            if nh and nh not in seen and self.host_in_scope(nh):
                seen.add(nh)
                out.append(nh)
        return sorted(out)
