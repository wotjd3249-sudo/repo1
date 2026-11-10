"""정찰: 서브도메인 수집, HTTP 프로빙, 기술 핑거프린팅."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from .http import HttpClient, run_parallel
from .scope_guard import ScopeGuard

# 아주 가벼운 핑거프린트 규칙 (헤더/바디 기반). 필요시 확장.
FINGERPRINTS = [
    # (name, header_regex or None, body_regex or None, header_name)
    ("nginx", r"nginx", None, "Server"),
    ("apache", r"apache", None, "Server"),
    ("iis", r"microsoft-iis", None, "Server"),
    ("cloudflare", r"cloudflare", None, "Server"),
    ("php", r"php/?([\d.]+)?", None, "X-Powered-By"),
    ("express", r"express", None, "X-Powered-By"),
    ("wordpress", None, r"wp-content|wp-includes", None),
    ("drupal", None, r"Drupal.settings|/sites/default/files", None),
    ("joomla", None, r"/media/jui/|Joomla!", None),
    ("jenkins", r"jenkins", None, "X-Jenkins"),
    ("tomcat", None, r"Apache Tomcat", None),
    ("gitlab", None, r"GitLab|gitlab-", None),
]

VERSION_RE = re.compile(r"([a-zA-Z\-]+)[/ ]?([\d]+(?:\.[\d]+){1,3})")


@dataclass
class Host:
    host: str
    url: str = ""
    status: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    tech: dict[str, str] = field(default_factory=dict)  # name -> version("" 가능)


# ── 서브도메인 수집 ────────────────────────────────────────────────

def _crtsh(domain: str, http: HttpClient) -> set[str]:
    out: set[str] = set()
    r = http.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if r is None or r.status_code != 200:
        return out
    try:
        for row in r.json():
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    out.add(name)
    except (json.JSONDecodeError, ValueError):
        pass
    return out


def _subfinder(domain: str) -> set[str]:
    if not shutil.which("subfinder"):
        return set()
    try:
        p = subprocess.run(
            ["subfinder", "-silent", "-d", domain],
            capture_output=True, text=True, timeout=180,
        )
        return {l.strip().lower() for l in p.stdout.splitlines() if l.strip()}
    except (subprocess.SubprocessError, OSError):
        return set()


def enumerate_subdomains(seeds: list[str], guard: ScopeGuard, http: HttpClient) -> list[str]:
    found: set[str] = set(seeds)
    for d in seeds:
        found |= _crtsh(d, http)
        found |= _subfinder(d)
    return guard.filter_hosts(found)


# ── HTTP 프로빙 + 핑거프린팅 ────────────────────────────────────────

def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def _fingerprint(resp) -> dict[str, str]:
    tech: dict[str, str] = {}
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:200_000] if resp.text else ""
    for name, hdr_re, body_re, hdr_name in FINGERPRINTS:
        hit = False
        version = ""
        if hdr_re and hdr_name:
            val = headers.get(hdr_name.lower(), "")
            if val and re.search(hdr_re, val, re.I):
                hit = True
                vm = VERSION_RE.search(val)
                if vm:
                    version = vm.group(2)
        if not hit and body_re and re.search(body_re, body, re.I):
            hit = True
        if hit:
            tech[name] = version
    # Server 헤더에서 직접 버전 추출
    server = headers.get("server", "")
    vm = VERSION_RE.search(server)
    if vm and vm.group(1).lower() not in tech:
        tech[vm.group(1).lower()] = vm.group(2)

    # ── 세부 버전 추출(CVE 매칭 입력 품질 향상) ──
    # WordPress / Drupal generator 메타태그
    m = re.search(r'name=["\']generator["\'][^>]*content=["\']WordPress\s+([\d.]+)',
                  body, re.I)
    if m:
        tech["wordpress"] = m.group(1)
    m = re.search(r'name=["\']generator["\'][^>]*content=["\']Drupal\s+([\d.]+)',
                  body, re.I)
    if m:
        tech["drupal"] = m.group(1)
    # Drupal 은 X-Generator 헤더로도 버전 노출
    m = re.search(r"Drupal\s+([\d.]+)", headers.get("x-generator", ""), re.I)
    if m:
        tech["drupal"] = m.group(1)
    # Jenkins: X-Jenkins 헤더 존재 자체가 지표(값은 버전)
    if "x-jenkins" in headers:
        jm = re.search(r"([\d]+(?:\.[\d]+)+)", headers.get("x-jenkins", ""))
        tech["jenkins"] = jm.group(1) if jm else tech.get("jenkins", "")
    # Tomcat 버전(바디/헤더)
    m = re.search(r"Apache Tomcat/?\s*([\d.]+)", body, re.I)
    if m:
        tech["tomcat"] = m.group(1)
    return tech


def probe_host(host: str, guard: ScopeGuard, http: HttpClient) -> Host | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        if not guard.url_in_scope(url):
            return None
        r = http.get(url)
        if r is None:
            continue
        h = Host(host=host, url=str(r.url), status=r.status_code)
        headers = {k.lower(): v for k, v in r.headers.items()}
        h.server = headers.get("server", "")
        h.powered_by = headers.get("x-powered-by", "")
        h.title = _title(r.text or "")
        h.tech = _fingerprint(r)
        return h
    return None


def probe_all(hosts: list[str], guard: ScopeGuard, http: HttpClient, concurrency: int) -> list[Host]:
    return run_parallel(hosts, lambda h: probe_host(h, guard, http), concurrency)
