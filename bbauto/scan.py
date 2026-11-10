"""탐지: 노출 경로/시크릿, 기술→CVE 매칭, nuclei(경량 능동)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess

from .findings import Finding
from .http import HttpClient, run_parallel
from .recon import Host
from .scope_guard import ScopeGuard

# ── 노출된 민감 경로 (GET, 비파괴적) ────────────────────────────────
# (path, 설명, severity, 노출로 판단할 바디 시그니처 regex)
EXPOSED_PATHS = [
    ("/.env", "환경변수 파일 노출", "high", r"(?i)(APP_KEY|DB_PASSWORD|SECRET|AWS_)"),
    ("/.git/config", "Git 설정 노출(소스 유출 가능)", "high", r"\[core\]|\[remote"),
    ("/.git/HEAD", "Git 디렉터리 노출", "high", r"ref:\s*refs/"),
    ("/config.json", "설정 파일 노출", "medium", r"(?i)(password|secret|token|apikey)"),
    ("/.aws/credentials", "AWS 자격증명 노출", "critical", r"aws_access_key_id"),
    ("/server-status", "Apache status 노출", "low", r"Apache Server Status"),
    ("/actuator/env", "Spring actuator env 노출", "high", r"(?i)(systemProperties|activeProfiles|spring)"),
    ("/actuator/health", "Spring actuator 노출", "low", r"(?i)\"status\"\s*:"),
    ("/phpinfo.php", "phpinfo 노출", "medium", r"PHP Version"),
    ("/.DS_Store", "DS_Store 노출(디렉터리 구조 유출)", "low", r"\x00\x00\x00"),
    ("/wp-config.php.bak", "WordPress 설정 백업 노출", "critical", r"DB_PASSWORD|DB_NAME"),
    ("/.svn/entries", "SVN 디렉터리 노출", "medium", r"^\d+|svn"),
    ("/debug", "디버그 엔드포인트 노출", "low", r"(?i)(debug|trace|stack)"),
]

# ── 기술 버전 → 알려진 CVE 로컬 매칭 (예시 DB; 확장 가능) ─────────────
# {tech: [(version_regex, cve, severity, desc), ...]}
CVE_DB: dict[str, list[tuple[str, str, str, str]]] = {
    "apache": [
        (r"^2\.4\.(4[0-9])$", "CVE-2021-41773", "critical",
         "Apache 2.4.49/50 path traversal & RCE (요구 설정 확인 필요)"),
    ],
    "nginx": [
        (r"^1\.(1[0-9]|20)\.", "CVE-2019-20372", "medium",
         "nginx error_page request smuggling (설정 의존)"),
    ],
    "php": [
        (r"^(7\.|8\.0\.)", "EOL", "low", "지원 종료(EOL) PHP 버전 사용 가능성"),
    ],
    "jenkins": [
        (r".*", "CVE-2024-23897", "critical",
         "Jenkins CLI arbitrary file read (버전 확인 필요)"),
    ],
}


# ── 노출 경로 탐지 ──────────────────────────────────────────────────

def _check_path(base_url: str, path: str, desc: str, sev: str, sig: str,
                guard: ScopeGuard, http: HttpClient) -> Finding | None:
    url = base_url.rstrip("/") + path
    if not guard.url_in_scope(url):
        return None
    r = http.get(url)
    if r is None or r.status_code != 200:
        return None
    body = r.text or ""
    if not re.search(sig, body):
        return None
    return Finding(
        type="exposed-path",
        title=desc,
        severity=sev,
        target=url,
        source="secrets",
        evidence=f"HTTP {r.status_code}, 시그니처 매칭: {sig[:40]}",
    )


def scan_exposed(hosts: list[Host], guard: ScopeGuard, http: HttpClient, concurrency: int) -> list[Finding]:
    jobs = []
    for h in hosts:
        if not h.url or h.status == 0:
            continue
        for path, desc, sev, sig in EXPOSED_PATHS:
            jobs.append((h.url, path, desc, sev, sig))
    return run_parallel(
        jobs,
        lambda j: _check_path(j[0], j[1], j[2], j[3], j[4], guard, http),
        concurrency,
    )


# ── CVE 매칭 ────────────────────────────────────────────────────────

def scan_cves(hosts: list[Host]) -> list[Finding]:
    out: list[Finding] = []
    for h in hosts:
        for tech, version in h.tech.items():
            rules = CVE_DB.get(tech)
            if not rules:
                continue
            for ver_re, cve, sev, desc in rules:
                if version and not re.search(ver_re, version):
                    continue
                if not version and ver_re != r".*":
                    # 버전 불명 + 특정 버전 규칙이면 보류(오탐 방지)
                    continue
                out.append(Finding(
                    type="cve-match",
                    title=f"{tech} {version or '?'} — {cve}",
                    severity=sev,
                    target=h.url or h.host,
                    source="cve_match",
                    evidence=desc,
                    reference=(f"https://nvd.nist.gov/vuln/detail/{cve}"
                               if cve.startswith("CVE-") else ""),
                ))
    return out


# ── nuclei (경량 능동 탐지) ─────────────────────────────────────────

def scan_nuclei(hosts: list[Host], guard: ScopeGuard, cfg_nuclei: dict) -> list[Finding]:
    if not shutil.which("nuclei"):
        return []
    urls = [h.url for h in hosts if h.url and guard.url_in_scope(h.url)]
    if not urls:
        return []
    cmd = [
        "nuclei", "-silent", "-jsonl",
        "-severity", str(cfg_nuclei.get("severity", "low,medium,high,critical")),
        "-rate-limit", str(cfg_nuclei.get("rate_limit", 10)),
    ]
    excl = cfg_nuclei.get("exclude_tags")
    if excl:
        cmd += ["-exclude-tags", str(excl)]
    cmd += list(cfg_nuclei.get("extra_args", []))
    out: list[Finding] = []
    try:
        p = subprocess.run(
            cmd, input="\n".join(urls),
            capture_output=True, text=True, timeout=1800,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        matched = d.get("matched-at") or d.get("host") or ""
        # 이중 안전장치: nuclei 결과도 스코프 재확인
        if matched and not guard.url_in_scope(matched):
            continue
        out.append(Finding(
            type="nuclei",
            title=info.get("name", d.get("template-id", "nuclei finding")),
            severity=str(info.get("severity", "info")).lower(),
            target=matched,
            source="nuclei",
            evidence=d.get("template-id", ""),
            reference=(info.get("reference") or [""])[0]
            if isinstance(info.get("reference"), list) else str(info.get("reference", "")),
        ))
    return out
