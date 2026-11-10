"""설정 및 스코프 로딩 + 권한 게이트."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any

import yaml


class ConfigError(Exception):
    pass


@dataclass
class Scope:
    program: str
    in_domains: list[str] = field(default_factory=list)
    in_urls: list[str] = field(default_factory=list)
    out_domains: list[str] = field(default_factory=list)
    out_urls: list[str] = field(default_factory=list)

    @property
    def seed_domains(self) -> list[str]:
        """와일드카드/apex 를 정리한 시드 도메인(서브도메인 수집 출발점)."""
        seeds = set()
        for d in self.in_domains:
            seeds.add(d[2:] if d.startswith("*.") else d)
        return sorted(seeds)


@dataclass
class Config:
    authorized: bool
    rate_limit_rps: float
    concurrency: int
    timeout: int
    user_agent: str
    output_dir: str
    state_file: str
    modules: dict[str, bool]
    nuclei: dict[str, Any]
    notify: dict[str, Any]
    github: dict[str, Any]
    scope_source: str = "file"            # "file" | "hackerone"
    hackerone: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def _load_yaml(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise ConfigError(f"파일을 찾을 수 없습니다: {path}")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"잘못된 YAML 형식: {path}")
    return data


def load_scope(path: str = "scope.yaml") -> Scope:
    d = _load_yaml(path)
    in_scope = d.get("in_scope") or {}
    out_scope = d.get("out_of_scope") or {}
    scope = Scope(
        program=d.get("program", "unknown"),
        in_domains=[s.strip().lower() for s in (in_scope.get("domains") or [])],
        in_urls=[s.strip() for s in (in_scope.get("urls") or [])],
        out_domains=[s.strip().lower() for s in (out_scope.get("domains") or [])],
        out_urls=[s.strip() for s in (out_scope.get("urls") or [])],
    )
    if not scope.in_domains and not scope.in_urls:
        raise ConfigError("scope.yaml 에 in_scope 자산이 하나도 없습니다.")
    return scope


def load_config(path: str = "config.yaml") -> Config:
    d = _load_yaml(path)
    cfg = Config(
        authorized=bool(d.get("authorized", False)),
        rate_limit_rps=float(d.get("rate_limit_rps", 2)),
        concurrency=int(d.get("concurrency", 5)),
        timeout=int(d.get("timeout", 10)),
        user_agent=str(d.get("user_agent", "bbauto/1.0")),
        output_dir=str(d.get("output_dir", "./reports")),
        state_file=str(d.get("state_file", "./state/findings.json")),
        modules=dict(d.get("modules") or {}),
        nuclei=dict(d.get("nuclei") or {}),
        notify=dict(d.get("notify") or {}),
        github=dict(d.get("github") or {}),
        scope_source=str(d.get("scope_source", "file")).lower(),
        hackerone=dict(d.get("hackerone") or {}),
        raw=d,
    )
    return cfg


def assert_authorized(cfg: Config) -> None:
    """권한 게이트. authorized:true 가 아니면 즉시 중단."""
    if not cfg.authorized:
        print(
            "\n[권한 게이트] 실행이 차단되었습니다.\n"
            "  config.yaml 의 'authorized' 가 false 입니다.\n"
            "  scope.yaml 의 모든 대상에 대해 테스트 권한이 있음을 확인한 경우에만\n"
            "  authorized: true 로 설정하세요. 권한 없는 스캔은 불법입니다.\n",
            file=sys.stderr,
        )
        raise SystemExit(2)
