"""HackerOne Hacker API 연동 — 참여 중인 프로그램의 in-scope 자산을 자동 수집.

HackerOne API 는 Basic 인증(사용자명 + API 토큰)을 사용합니다.
토큰은 https://hackerone.com/settings/api_token/edit 에서 발급.
토큰은 코드/설정에 직접 넣지 말고 환경변수로 주입하는 것을 권장합니다.
"""
from __future__ import annotations

import os

import requests

from .config import Config, Scope

API_BASE = "https://api.hackerone.com/v1"

# 웹 스캔에 사용할 자산 유형(그 외 모바일앱/소스코드 등은 이 도구 대상 아님)
DEFAULT_WEB_ASSET_TYPES = ["URL", "DOMAIN", "WILDCARD"]


class HackerOneError(Exception):
    pass


def _dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


class HackerOneClient:
    def __init__(self, username: str, token: str, timeout: int = 15,
                 user_agent: str = "bbauto/1.0"):
        if not username or not token:
            raise HackerOneError("HackerOne username 또는 API 토큰이 비어 있습니다.")
        self.s = requests.Session()
        self.s.auth = (username, token)  # HTTP Basic
        self.s.headers.update({"Accept": "application/json", "User-Agent": user_agent})
        self.timeout = timeout

    def _get_paginated(self, url: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        guard = 0
        while url and guard < 200:  # 안전 상한
            guard += 1
            try:
                r = self.s.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                raise HackerOneError(f"요청 실패: {e}") from e
            if r.status_code == 401:
                raise HackerOneError("인증 실패(401) — 사용자명/API 토큰을 확인하세요.")
            if r.status_code == 403:
                raise HackerOneError("접근 거부(403) — 토큰 권한 또는 프로그램 접근 확인.")
            if r.status_code != 200:
                raise HackerOneError(f"API 오류 {r.status_code}: {r.text[:200]}")
            data = r.json()
            out.extend(data.get("data", []))
            url = (data.get("links") or {}).get("next")
            params = None  # next 링크에 쿼리가 이미 포함됨
        return out

    def programs(self) -> list[dict]:
        """참여(멤버) 중인 프로그램 목록."""
        return self._get_paginated(f"{API_BASE}/hackers/programs")

    def structured_scopes(self, handle: str) -> list[dict]:
        """프로그램의 구조화된 스코프 목록."""
        return self._get_paginated(
            f"{API_BASE}/hackers/programs/{handle}/structured_scopes")


def _classify(identifier: str, eligible: bool,
              in_d, in_u, out_d, out_u) -> None:
    ident = identifier.strip()
    if not ident:
        return
    dom_bucket = in_d if eligible else out_d
    url_bucket = in_u if eligible else out_u
    if "://" in ident:
        url_bucket.append(ident)
    elif "/" in ident:
        url_bucket.append("https://" + ident)
    else:
        # "example.com" 또는 와일드카드 "*.example.com"
        dom_bucket.append(ident.lower())


def scopes_to_scope(program_label: str, scopes: list[dict],
                    only_bounty: bool = False,
                    web_asset_types: list[str] | None = None) -> Scope:
    """HackerOne structured_scopes → 내부 Scope 로 변환.

    - eligible_for_submission=False 자산은 out_of_scope 로 분류
    - only_bounty=True 면 bounty 대상이 아닌 자산은 수집하지 않음
    """
    types = {t.upper() for t in (web_asset_types or DEFAULT_WEB_ASSET_TYPES)}
    in_d, in_u, out_d, out_u = [], [], [], []
    for s in scopes:
        a = s.get("attributes", {}) if isinstance(s, dict) else {}
        atype = str(a.get("asset_type", "")).upper()
        if atype not in types:
            continue
        ident = str(a.get("asset_identifier", "")).strip()
        if not ident:
            continue
        if only_bounty and not a.get("eligible_for_bounty", False):
            continue
        eligible = bool(a.get("eligible_for_submission", True))
        _classify(ident, eligible, in_d, in_u, out_d, out_u)
    return Scope(
        program=program_label,
        in_domains=_dedup(in_d), in_urls=_dedup(in_u),
        out_domains=_dedup(out_d), out_urls=_dedup(out_u),
    )


def _resolve_token(h1cfg: dict) -> tuple[str, str]:
    username = (h1cfg.get("username") or "").strip()
    token = (h1cfg.get("api_token") or "").strip()
    if not token:
        env = h1cfg.get("api_token_env") or "H1_API_TOKEN"
        token = (os.environ.get(env) or "").strip()
    if not username:
        username = (os.environ.get("H1_USERNAME") or "").strip()
    return username, token


def build_scope_from_config(cfg: Config) -> Scope:
    """config.yaml 의 hackerone 설정으로부터 Scope 를 구성."""
    h1 = cfg.hackerone or {}
    username, token = _resolve_token(h1)
    if not token:
        raise HackerOneError(
            "HackerOne API 토큰이 없습니다. config.hackerone.api_token 또는 "
            f"환경변수 {h1.get('api_token_env', 'H1_API_TOKEN')} 를 설정하세요.")
    client = HackerOneClient(username, token, timeout=cfg.timeout,
                             user_agent=cfg.user_agent)

    handles = [h.strip() for h in (h1.get("handles") or []) if h.strip()]
    if not handles:
        progs = client.programs()
        handles = [p.get("attributes", {}).get("handle") for p in progs]
        handles = [h for h in handles if h]
    if not handles:
        raise HackerOneError("참여 중인 프로그램이 없거나 handle 을 찾지 못했습니다.")

    only_bounty = bool(h1.get("only_bounty_eligible", False))
    web_types = h1.get("web_asset_types") or DEFAULT_WEB_ASSET_TYPES

    merged_in_d, merged_in_u, merged_out_d, merged_out_u = [], [], [], []
    for handle in handles:
        scopes = client.structured_scopes(handle)
        sc = scopes_to_scope(handle, scopes, only_bounty, web_types)
        merged_in_d += sc.in_domains
        merged_in_u += sc.in_urls
        merged_out_d += sc.out_domains
        merged_out_u += sc.out_urls

    label = handles[0] if len(handles) == 1 else f"HackerOne ({len(handles)} programs)"
    scope = Scope(
        program=label,
        in_domains=_dedup(merged_in_d), in_urls=_dedup(merged_in_u),
        out_domains=_dedup(merged_out_d), out_urls=_dedup(merged_out_u),
    )
    if not scope.in_domains and not scope.in_urls:
        raise HackerOneError(
            "수집된 in-scope 웹 자산이 없습니다. web_asset_types/handles 설정을 확인하세요.")
    return scope
