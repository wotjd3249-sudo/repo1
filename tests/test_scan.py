"""확장된 탐지 로직 테스트: 버전비교, CVE 매칭, 노출경로 시그니처, nuclei 파싱."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbauto import scan
from bbauto.recon import Host
from bbauto.config import Scope
from bbauto.scope_guard import ScopeGuard


def test_version_compare():
    assert scan._cmp("2.4.49", "2.4.49") == 0
    assert scan._cmp("2.4.49", "2.4.50") < 0
    assert scan._cmp("1.21.0", "1.17.7") > 0
    assert scan._cmp("2.4.9", "2.4.10") < 0        # 숫자 비교(문자열 아님)
    assert scan._cmp("8.1.27", "8.1.3") > 0
    print("test_version_compare OK")


def test_match_spec():
    assert scan._match_spec("2.4.49", {"eq": "2.4.49"})
    assert not scan._match_spec("2.4.50", {"eq": "2.4.49"})
    assert scan._match_spec("1.20.0", {"lt": "1.21.0"})
    assert not scan._match_spec("1.21.0", {"lt": "1.21.0"})
    assert scan._match_spec("2.441", {"le": "2.441"})
    assert scan._match_spec("8.1.10", {"range": ("8.1.0", "8.1.27")})
    assert not scan._match_spec("8.2.0", {"range": ("8.1.0", "8.1.27")})
    # 버전 불명 → 버전 기반 규칙은 보류
    assert not scan._match_spec("", {"lt": "9.9.9"})
    # any 규칙은 버전 없이도 매칭
    assert scan._match_spec("", {"any": True})
    print("test_match_spec OK")


def test_cve_match():
    hosts = [
        Host(host="a.example.com", url="https://a.example.com", status=200,
             tech={"apache": "2.4.49"}),
        Host(host="b.example.com", url="https://b.example.com", status=200,
             tech={"jenkins": "2.426.1"}),
        Host(host="c.example.com", url="https://c.example.com", status=200,
             tech={"nginx": "1.25.0"}),   # 최신 → 매칭 없어야
    ]
    findings = scan.scan_cves(hosts)
    titles = [f.title for f in findings]
    assert any("CVE-2021-41773" in t for t in titles), titles
    assert any("CVE-2024-23897" in t for t in titles), titles
    # 최신 nginx 는 lt 규칙에 안 걸림
    assert not any("nginx" in t for t in titles), titles
    # 레퍼런스 NVD 링크
    assert any("nvd.nist.gov" in f.reference for f in findings)
    print("test_cve_match OK")


class FakeResp:
    def __init__(self, status, text, url):
        self.status_code = status
        self.text = text
        self.url = url
        self.headers = {}


class FakeHttp:
    """경로별 고정 응답을 돌려주는 가짜 HTTP 클라이언트."""
    def __init__(self, mapping):
        self.mapping = mapping  # path -> (status, body)
    def get(self, url, **kw):
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        if path in self.mapping:
            st, body = self.mapping[path]
            return FakeResp(st, body, url)
        return FakeResp(404, "not found", url)


def test_exposed_path_signature():
    guard = ScopeGuard(Scope(program="t", in_domains=["example.com", "*.example.com"]))
    host = Host(host="a.example.com", url="https://a.example.com", status=200)
    http = FakeHttp({
        "/.env": (200, "APP_KEY=base64xxxx\nDB_PASSWORD=secret123\n"),
        "/.git/config": (200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]"),
        # 200 이지만 시그니처 불일치 → finding 아님(오탐 방지)
        "/config.json": (200, "<html>generic 200 page</html>"),
    })
    findings = scan.scan_exposed([host], guard, http, concurrency=4, level="deep")
    types_titles = {(f.type, f.target.split("/")[-1]) for f in findings}
    assert ("exposed-path", ".env") in types_titles, findings
    assert any(".git" in f.target for f in findings), findings
    # 시그니처 불일치 경로는 제외
    assert not any(f.target.endswith("config.json") for f in findings), findings
    # 심각도 매핑
    env_f = next(f for f in findings if f.target.endswith("/.env"))
    assert env_f.severity == "high"
    print("test_exposed_path_signature OK")


def test_exposed_level_gating():
    """standard 레벨은 deep 전용 경로를 검사하지 않는다."""
    guard = ScopeGuard(Scope(program="t", in_domains=["*.example.com", "example.com"]))
    host = Host(host="a.example.com", url="https://a.example.com", status=200)
    # /.aws/credentials 는 deep 전용
    http = FakeHttp({"/.aws/credentials": (200, "aws_access_key_id=AKIAXXXX")})
    std = scan.scan_exposed([host], guard, http, 4, level="standard")
    deep = scan.scan_exposed([host], guard, http, 4, level="deep")
    assert not any("aws" in f.target for f in std), std
    assert any("aws" in f.target for f in deep), deep
    print("test_exposed_level_gating OK")


def test_nuclei_parsing(monkeypatch):
    """nuclei JSONL 출력 파싱 + 스코프 재확인."""
    guard = ScopeGuard(Scope(program="t", in_domains=["example.com", "*.example.com"]))
    hosts = [Host(host="a.example.com", url="https://a.example.com", status=200)]

    jsonl = "\n".join([
        '{"template-id":"CVE-2021-41773","matched-at":"https://a.example.com/cgi-bin",'
        '"info":{"name":"Apache Path Traversal","severity":"critical",'
        '"classification":{"cve-id":["CVE-2021-41773"]}},"extracted-results":["root:x:0:0"]}',
        # 스코프 밖 결과 → 폐기되어야
        '{"template-id":"x","matched-at":"https://evil.com/","info":{"name":"X","severity":"high"}}',
        'not-json-line',
    ])

    def fake_which(name):
        return "/usr/bin/nuclei"

    def fake_run(cmd, **kw):
        return types.SimpleNamespace(stdout=jsonl, stderr="", returncode=0)

    monkeypatch.setattr(scan.shutil, "which", fake_which)
    monkeypatch.setattr(scan.subprocess, "run", fake_run)

    findings = scan.scan_nuclei(hosts, guard, {"severity": "low,medium,high,critical"})
    assert len(findings) == 1, findings            # 스코프 밖/비JSON 제외
    f = findings[0]
    assert f.severity == "critical"
    assert "nvd.nist.gov/vuln/detail/CVE-2021-41773" in f.reference
    assert "root:x:0:0" in f.evidence
    print("test_nuclei_parsing OK")


if __name__ == "__main__":
    class MP:
        def __init__(self): self._u = []
        def setattr(self, o, n, v):
            self._u.append((o, n, getattr(o, n))); setattr(o, n, v)
        def undo(self):
            for o, n, v in reversed(self._u): setattr(o, n, v)
    test_version_compare()
    test_match_spec()
    test_cve_match()
    test_exposed_path_signature()
    test_exposed_level_gating()
    mp = MP()
    try:
        test_nuclei_parsing(mp)
    finally:
        mp.undo()
    print("\nscan 확장 테스트 통과 ✅")
