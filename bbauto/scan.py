"""탐지: 노출 경로/시크릿, 기술→CVE 매칭, nuclei(경량 능동).

모든 탐지는 비파괴적 GET 위주이며, Scope Guard 로 범위를 강제한다.
각 노출 경로는 '시그니처'가 바디에 매칭될 때만 finding 으로 올려 오탐을 줄인다.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess

from .findings import Finding
from .http import HttpClient, run_parallel
from .recon import Host
from .scope_guard import ScopeGuard

# ───────────────────────────────────────────────────────────────────
# 노출된 민감 경로 (path, 설명, severity, 시그니처 regex, deep)
#   deep=False : 기본(standard) 레벨에서도 검사
#   deep=True  : secrets.level == "deep" 일 때만 검사(요청량↑)
# 시그니처는 '그 파일이 실제로 노출됐을 때만' 나타나는 패턴으로 선정.
# ───────────────────────────────────────────────────────────────────
EXPOSED_PATHS = [
    # ── 소스/버전관리 노출 ──
    ("/.env", "환경변수(.env) 노출", "high",
     r"(?im)^\s*(APP_KEY|APP_SECRET|DB_PASSWORD|DB_USERNAME|AWS_SECRET|AWS_ACCESS|SECRET_KEY|JWT_SECRET)\s*=", False),
    ("/.env.local", ".env.local 노출", "high",
     r"(?im)^\s*(APP_KEY|DB_PASSWORD|SECRET|AWS_)", True),
    ("/.env.production", ".env.production 노출", "high",
     r"(?im)^\s*(APP_KEY|DB_PASSWORD|SECRET|AWS_)", True),
    ("/.git/config", "Git 설정 노출(소스 유출 가능)", "high",
     r"\[core\]|\[remote\s", False),
    ("/.git/HEAD", "Git 디렉터리 노출", "high", r"ref:\s*refs/", False),
    ("/.svn/entries", "SVN 디렉터리 노출", "medium", r"(?m)^\d+$|svn://", True),
    ("/.hg/requires", "Mercurial 디렉터리 노출", "medium", r"revlogv|dotencode|store", True),
    ("/.bzr/README", "Bazaar 디렉터리 노출", "low", r"Bazaar", True),

    # ── 백업/덤프 ──
    ("/.env.bak", ".env 백업 노출", "high", r"(?im)(APP_KEY|DB_PASSWORD|SECRET)", True),
    ("/backup.sql", "SQL 백업 노출", "high", r"(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)", True),
    ("/dump.sql", "SQL 덤프 노출", "high", r"(?i)(CREATE TABLE|INSERT INTO)", True),
    ("/database.sql", "DB 덤프 노출", "high", r"(?i)(CREATE TABLE|INSERT INTO)", True),
    ("/backup.zip", "백업 아카이브 노출", "medium", r"PK\x03\x04", True),
    ("/wp-config.php.bak", "WordPress 설정 백업 노출", "critical", r"DB_PASSWORD|DB_NAME", True),
    ("/config.php.bak", "PHP 설정 백업 노출", "high", r"(?i)(password|secret|db_)", True),
    ("/web.config.bak", "web.config 백업 노출", "high", r"<configuration|connectionStrings", True),

    # ── 클라우드/인프라 자격 ──
    ("/.aws/credentials", "AWS 자격증명 노출", "critical", r"aws_access_key_id", True),
    ("/.aws/config", "AWS 설정 노출", "medium", r"\[profile|region\s*=", True),
    ("/.s3cfg", "s3cmd 설정 노출", "high", r"access_key|secret_key", True),
    ("/.npmrc", "npm 토큰 노출", "high", r"_authToken|//registry\.", True),
    ("/.dockercfg", "Docker 자격 노출", "high", r'"auth"\s*:', True),
    ("/.docker/config.json", "Docker config 노출", "high", r'"auths"\s*:', True),
    ("/.kube/config", "Kubernetes config 노출", "high", r"apiVersion:|clusters:|client-key-data", True),
    ("/terraform.tfstate", "Terraform state 노출(시크릿 포함 가능)", "critical",
     r'"terraform_version"|"outputs"', True),
    ("/docker-compose.yml", "docker-compose 노출", "medium",
     r"(?im)^\s*(services|image|environment)\s*:", True),
    ("/.ssh/id_rsa", "SSH 개인키 노출", "critical", r"BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY", True),
    ("/id_rsa", "SSH 개인키 노출", "critical", r"BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY", True),

    # ── 프레임워크/앱 설정 ──
    ("/config.json", "설정 파일 노출", "medium", r"(?i)(password|secret|token|apikey)", False),
    ("/config.yml", "YAML 설정 노출", "medium", r"(?im)(password|secret|token):", True),
    ("/application.properties", "Spring 설정 노출", "high",
     r"(?i)(spring\.|datasource|password=|secret)", True),
    ("/application.yml", "Spring YAML 설정 노출", "high",
     r"(?im)(datasource|password|spring):", True),
    ("/settings.py", "Django settings 노출", "high", r"SECRET_KEY|DATABASES\s*=", True),
    ("/.htpasswd", "htpasswd 노출", "medium", r":\$(?:apr1|2y|2a|1|6)\$", True),
    ("/credentials.json", "자격 JSON 노출", "high", r"(?i)(private_key|client_secret|password)", True),
    ("/secrets.json", "secrets.json 노출", "high", r"(?i)(secret|password|token|key)", True),
    ("/storage/logs/laravel.log", "Laravel 로그 노출", "medium",
     r"(?i)(production\.ERROR|stack trace|vendor/laravel)", True),

    # ── 상태/정보 노출 ──
    ("/server-status", "Apache server-status 노출", "low", r"Apache Server Status", True),
    ("/nginx_status", "nginx stub_status 노출", "low", r"Active connections:", True),
    ("/phpinfo.php", "phpinfo 노출", "medium", r"phpinfo\(\)|PHP Version", True),
    ("/info.php", "phpinfo 노출", "medium", r"phpinfo\(\)|PHP Version", True),

    # ── Spring Boot Actuator ──
    ("/actuator", "Actuator 인덱스 노출", "low", r'"_links"|"self"', True),
    ("/actuator/health", "Actuator health 노출", "low", r'(?i)"status"\s*:', True),
    ("/actuator/env", "Actuator env 노출(설정/시크릿)", "high",
     r"(?i)(systemProperties|activeProfiles|spring)", False),
    ("/actuator/heapdump", "Actuator heapdump 노출(메모리 덤프)", "critical",
     r"JAVA PROFILE|HPROF|\x0ajava", True),
    ("/actuator/configprops", "Actuator configprops 노출", "high", r'"contexts"|"beans"', True),

    # ── API/문서 표면 노출 ──
    ("/swagger.json", "Swagger 스펙 노출(API 표면)", "low", r'"swagger"|"openapi"', True),
    ("/openapi.json", "OpenAPI 스펙 노출", "low", r'"openapi"\s*:', True),
    ("/.well-known/openid-configuration", "OIDC 구성 노출", "info", r'"issuer"\s*:', True),

    # ── IDE/메타 ──
    ("/.vscode/settings.json", "VSCode 설정 노출", "low", r"[{]", True),
    ("/.idea/workspace.xml", "IntelliJ 설정 노출", "low", r"<project", True),
    ("/.DS_Store", "DS_Store 노출(디렉터리 구조 유출)", "low", r"Bud1|\x00\x00\x00\x01", True),
]


def _check_path(base_url: str, path: str, desc: str, sev: str, sig: str,
                guard: ScopeGuard, http: HttpClient) -> Finding | None:
    url = base_url.rstrip("/") + path
    if not guard.url_in_scope(url):
        return None
    r = http.get(url)
    if r is None or r.status_code != 200:
        return None
    body = r.text or ""
    try:
        if not re.search(sig, body):
            return None
    except re.error:
        return None
    return Finding(
        type="exposed-path", title=desc, severity=sev, target=url, source="secrets",
        evidence=f"HTTP {r.status_code}, 시그니처 매칭됨",
    )


def scan_exposed(hosts: list[Host], guard: ScopeGuard, http: HttpClient,
                 concurrency: int, level: str = "standard",
                 extra_paths: list | None = None) -> list[Finding]:
    deep = str(level).lower() == "deep"
    paths = [p for p in EXPOSED_PATHS if deep or not p[4]]
    # 사용자 정의 추가 경로: [path, desc, severity, signature]
    for ep in (extra_paths or []):
        try:
            paths.append((ep["path"], ep.get("desc", ep["path"]),
                          ep.get("severity", "info"), ep.get("signature", r".?"), True))
        except (TypeError, KeyError):
            continue
    jobs = []
    for h in hosts:
        if not h.url or h.status == 0:
            continue
        for p in paths:
            jobs.append((h.url, p[0], p[1], p[2], p[3]))
    return run_parallel(
        jobs,
        lambda j: _check_path(j[0], j[1], j[2], j[3], j[4], guard, http),
        concurrency,
    )


# ───────────────────────────────────────────────────────────────────
# 버전 비교 유틸
# ───────────────────────────────────────────────────────────────────
def _parse_ver(v: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:4]) or (0,)


def _cmp(a: str, b: str) -> int:
    pa, pb = list(_parse_ver(a)), list(_parse_ver(b))
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def _match_spec(version: str, spec: dict) -> bool:
    if spec.get("any"):
        return True
    if not version:          # 버전 기반 규칙은 버전 없으면 보류(오탐 방지)
        return False
    if "regex" in spec:
        return re.search(spec["regex"], version) is not None
    if "eq" in spec:
        return _cmp(version, spec["eq"]) == 0
    if "lt" in spec:
        return _cmp(version, spec["lt"]) < 0
    if "le" in spec:
        return _cmp(version, spec["le"]) <= 0
    if "gt" in spec:
        return _cmp(version, spec["gt"]) > 0
    if "ge" in spec:
        return _cmp(version, spec["ge"]) >= 0
    if "range" in spec:
        lo, hi = spec["range"]
        return _cmp(version, lo) >= 0 and _cmp(version, hi) <= 0
    return False


def _nvd(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else ""


# ───────────────────────────────────────────────────────────────────
# 기술 버전 → 알려진 CVE 로컬 매칭 DB
#   각 규칙: {"match": <spec>, "cve", "severity", "desc"}
#   * 배너 버전 기반 추정이므로 반드시 수동 검증 필요(백포트 패치 가능).
# ───────────────────────────────────────────────────────────────────
CVE_DB: dict[str, list[dict]] = {
    "apache": [
        {"match": {"eq": "2.4.49"}, "cve": "CVE-2021-41773", "severity": "critical",
         "desc": "Apache 2.4.49 Path Traversal/RCE"},
        {"match": {"eq": "2.4.50"}, "cve": "CVE-2021-42013", "severity": "critical",
         "desc": "Apache 2.4.50 Path Traversal/RCE (41773 불완전 패치)"},
        {"match": {"lt": "2.4.54"}, "cve": "CVE-2022-31813", "severity": "medium",
         "desc": "구버전 Apache(<2.4.54): mod_proxy X-Forwarded 등 다수 취약점"},
    ],
    "nginx": [
        {"match": {"lt": "1.21.0"}, "cve": "CVE-2021-23017", "severity": "high",
         "desc": "nginx resolver off-by-one(<1.21.0) — 조건부 RCE 가능"},
        {"match": {"lt": "1.17.7"}, "cve": "CVE-2019-20372", "severity": "medium",
         "desc": "nginx error_page 요청 스머글링(설정 의존)"},
    ],
    "php": [
        {"match": {"lt": "7.4.0"}, "cve": "EOL", "severity": "medium",
         "desc": "PHP <7.4 — 지원 종료(EOL), 보안 패치 없음"},
        {"match": {"range": ("8.1.0", "8.1.27")}, "cve": "CVE-2024-4577", "severity": "critical",
         "desc": "PHP-CGI Argument Injection(Windows) — 환경 의존"},
    ],
    "drupal": [
        {"match": {"lt": "7.58"}, "cve": "CVE-2018-7600", "severity": "critical",
         "desc": "Drupalgeddon2 — 비인증 RCE"},
        {"match": {"range": ("8.0.0", "8.5.0")}, "cve": "CVE-2018-7600", "severity": "critical",
         "desc": "Drupalgeddon2 — 비인증 RCE(8.x)"},
        {"match": {"lt": "7.59"}, "cve": "CVE-2018-7602", "severity": "critical",
         "desc": "Drupalgeddon3 — 비인증 RCE"},
    ],
    "joomla": [
        {"match": {"lt": "3.4.6"}, "cve": "CVE-2015-8562", "severity": "critical",
         "desc": "Joomla 객체 주입 — 비인증 RCE"},
    ],
    "jenkins": [
        {"match": {"le": "2.441"}, "cve": "CVE-2024-23897", "severity": "critical",
         "desc": "Jenkins CLI 임의 파일 읽기(<=2.441, LTS<=2.426.2)"},
    ],
    "tomcat": [
        {"match": {"range": ("9.0.0", "9.0.30")}, "cve": "CVE-2020-1938", "severity": "high",
         "desc": "Ghostcat — AJP 파일 읽기/인클루전(AJP 노출 시)"},
        {"match": {"range": ("8.5.0", "8.5.50")}, "cve": "CVE-2020-1938", "severity": "high",
         "desc": "Ghostcat — AJP 파일 읽기/인클루전(AJP 노출 시)"},
    ],
    "wordpress": [
        {"match": {"lt": "5.8.3"}, "cve": "CVE-2022-21661", "severity": "medium",
         "desc": "WP core SQLi(WP_Query, <5.8.3) — 구버전 코어"},
    ],
}


def scan_cves(hosts: list[Host]) -> list[Finding]:
    out: list[Finding] = []
    for h in hosts:
        for tech, version in h.tech.items():
            for rule in CVE_DB.get(tech, []):
                if not _match_spec(version, rule["match"]):
                    continue
                cve = rule["cve"]
                out.append(Finding(
                    type="cve-match",
                    title=f"{tech} {version or '?'} — {cve}",
                    severity=rule["severity"],
                    target=h.url or h.host,
                    source="cve_match",
                    evidence=rule["desc"] + " (배너 기반 추정 — 수동 검증 필요)",
                    reference=_nvd(cve),
                ))
    return out


# ───────────────────────────────────────────────────────────────────
# nuclei (경량 능동 탐지) — 안전 프리셋, 스코프 재확인
# ───────────────────────────────────────────────────────────────────
def _first_ref(info: dict) -> str:
    ref = info.get("reference")
    if isinstance(ref, list):
        return next((r for r in ref if r), "")
    return str(ref or "")


def _cve_ref(d: dict) -> str:
    cls = d.get("info", {}).get("classification") or {}
    ids = cls.get("cve-id")
    if isinstance(ids, list) and ids:
        return _nvd(str(ids[0]).upper())
    if isinstance(ids, str) and ids:
        return _nvd(ids.upper())
    return ""


def scan_nuclei(hosts: list[Host], guard: ScopeGuard, cfg_nuclei: dict) -> list[Finding]:
    if not shutil.which("nuclei"):
        return []
    urls = [h.url for h in hosts if h.url and guard.url_in_scope(h.url)]
    if not urls:
        return []

    cmd = ["nuclei", "-silent", "-jsonl", "-disable-update-check", "-no-color"]
    c = cfg_nuclei or {}
    if c.get("severity"):
        cmd += ["-severity", str(c["severity"])]
    if c.get("exclude_severity"):
        cmd += ["-exclude-severity", str(c["exclude_severity"])]
    if c.get("tags"):
        cmd += ["-tags", str(c["tags"])]
    # 공격성 태그는 기본 제외(안전 프리셋)
    cmd += ["-exclude-tags", str(c.get("exclude_tags", "dos,fuzz,intrusive,brute-force"))]
    for t in (c.get("templates") or []):
        cmd += ["-t", str(t)]
    cmd += ["-rate-limit", str(c.get("rate_limit", 10))]
    cmd += ["-c", str(c.get("concurrency", 25))]
    cmd += ["-bulk-size", str(c.get("bulk_size", 25))]
    cmd += ["-timeout", str(c.get("timeout", 10))]
    cmd += ["-retries", str(c.get("retries", 1))]
    cmd += list(c.get("extra_args", []))

    try:
        p = subprocess.run(cmd, input="\n".join(urls),
                           capture_output=True, text=True, timeout=int(c.get("max_runtime", 1800)))
    except (subprocess.SubprocessError, OSError):
        return []

    out: list[Finding] = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {}) or {}
        matched = d.get("matched-at") or d.get("host") or d.get("url") or ""
        if matched and not guard.url_in_scope(matched):
            continue  # 이중 안전장치: 스코프 밖 결과 폐기
        extracted = d.get("extracted-results")
        evidence = d.get("template-id", "")
        if extracted:
            evidence += " | " + ", ".join(str(x) for x in extracted[:3])
        out.append(Finding(
            type="nuclei",
            title=info.get("name", d.get("template-id", "nuclei finding")),
            severity=str(info.get("severity", "info")).lower(),
            target=matched,
            source="nuclei",
            evidence=evidence,
            reference=_cve_ref(d) or _first_ref(info),
        ))
    return out
