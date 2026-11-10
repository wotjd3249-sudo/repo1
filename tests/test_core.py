"""안전장치/핵심 로직 단위 테스트 (네트워크 없음)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbauto.config import Scope
from bbauto.findings import Finding, FindingStore
from bbauto.scope_guard import ScopeGuard


def _scope():
    return Scope(
        program="t",
        in_domains=["example.com", "*.example.com"],
        in_urls=["https://example.com/app/"],
        out_domains=["blog.example.com", "*.internal.example.com"],
        out_urls=["https://example.com/app/legacy/"],
    )


def test_scope_guard():
    g = ScopeGuard(_scope())
    # apex 허용
    assert g.host_in_scope("example.com")
    # 서브도메인 허용
    assert g.host_in_scope("api.example.com")
    assert g.host_in_scope("a.b.example.com")
    # out-of-scope 우선 차단
    assert not g.host_in_scope("blog.example.com")
    assert not g.host_in_scope("db.internal.example.com")
    # 범위 밖 완전 차단
    assert not g.host_in_scope("evil.com")
    assert not g.host_in_scope("example.com.evil.com")
    assert not g.host_in_scope("notexample.com")
    # URL out-of-scope 차단
    assert not g.url_in_scope("https://example.com/app/legacy/x")
    assert g.url_in_scope("https://example.com/app/ok")
    # 포트/스킴 정규화
    assert g.host_in_scope("https://api.example.com:8443/path")
    print("test_scope_guard OK")


def test_filter_hosts_dedup():
    g = ScopeGuard(_scope())
    out = g.filter_hosts(["api.example.com", "API.EXAMPLE.COM", "evil.com", "x.example.com"])
    assert out == ["api.example.com", "x.example.com"], out
    print("test_filter_hosts_dedup OK")


def test_finding_dedup():
    with tempfile.TemporaryDirectory() as d:
        store = FindingStore(os.path.join(d, "f.json"))
        f1 = Finding(type="exposed-path", title="x", severity="high",
                     target="https://a.example.com/.env", source="secrets")
        f2 = Finding(type="exposed-path", title="x", severity="high",
                     target="https://a.example.com/.env", source="secrets")
        new1 = store.record([f1])
        assert len(new1) == 1
        new2 = store.record([f2])  # 동일 → 신규 아님
        assert len(new2) == 0
        store.save()
        # 재로딩 후에도 유지
        store2 = FindingStore(os.path.join(d, "f.json"))
        assert store2.count() == 1
    print("test_finding_dedup OK")


def test_wildcard_not_match_apex_only_registered():
    # *.example.com 은 apex 를 매칭하지 않지만, example.com 이 따로 등록되어 허용됨.
    s = Scope(program="t", in_domains=["*.example.com"])
    g = ScopeGuard(s)
    assert not g.host_in_scope("example.com")   # apex 미등록 → 차단
    assert g.host_in_scope("api.example.com")
    print("test_wildcard_not_match_apex_only_registered OK")


if __name__ == "__main__":
    test_scope_guard()
    test_filter_hosts_dedup()
    test_finding_dedup()
    test_wildcard_not_match_apex_only_registered()
    print("\n모든 테스트 통과 ✅")
