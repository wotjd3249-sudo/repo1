"""HackerOne 스코프 변환 로직 테스트 (네트워크 없음, mock API 응답)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbauto import hackerone
from bbauto.config import Config
from bbauto.scope_guard import ScopeGuard

# HackerOne /structured_scopes 응답 형태의 mock
MOCK_SCOPES = [
    {"type": "structured-scope", "attributes": {
        "asset_type": "WILDCARD", "asset_identifier": "*.example.com",
        "eligible_for_submission": True, "eligible_for_bounty": True}},
    {"type": "structured-scope", "attributes": {
        "asset_type": "URL", "asset_identifier": "api.example.com",
        "eligible_for_submission": True, "eligible_for_bounty": True}},
    {"type": "structured-scope", "attributes": {
        "asset_type": "URL", "asset_identifier": "https://example.com/app/",
        "eligible_for_submission": True, "eligible_for_bounty": False}},
    {"type": "structured-scope", "attributes": {  # out-of-scope
        "asset_type": "URL", "asset_identifier": "legacy.example.com",
        "eligible_for_submission": False, "eligible_for_bounty": False}},
    {"type": "structured-scope", "attributes": {  # 웹 자산 아님 → 무시
        "asset_type": "GOOGLE_PLAY_APP_ID", "asset_identifier": "com.example.app",
        "eligible_for_submission": True, "eligible_for_bounty": True}},
]


def test_scopes_to_scope():
    sc = hackerone.scopes_to_scope("example", MOCK_SCOPES)
    assert "*.example.com" in sc.in_domains
    assert "api.example.com" in sc.in_domains
    assert "https://example.com/app/" in sc.in_urls
    # out-of-scope 분류
    assert "legacy.example.com" in sc.out_domains
    # 모바일 앱 자산은 수집 안됨
    assert "com.example.app" not in sc.in_domains
    print("test_scopes_to_scope OK")


def test_only_bounty_filter():
    sc = hackerone.scopes_to_scope("example", MOCK_SCOPES, only_bounty=True)
    # bounty 대상만: *.example.com, api.example.com (둘 다 bounty True)
    # https://example.com/app/ 은 bounty False → 제외
    assert "https://example.com/app/" not in sc.in_urls
    assert "api.example.com" in sc.in_domains
    print("test_only_bounty_filter OK")


def test_integration_with_scope_guard():
    """HackerOne 스코프 → ScopeGuard 가 올바르게 강제하는지."""
    sc = hackerone.scopes_to_scope("example", MOCK_SCOPES)
    g = ScopeGuard(sc)
    assert g.host_in_scope("api.example.com")
    assert g.host_in_scope("x.example.com")        # 와일드카드
    assert not g.host_in_scope("legacy.example.com")  # out-of-scope 우선
    assert not g.host_in_scope("evil.com")
    print("test_integration_with_scope_guard OK")


def test_build_scope_from_config_monkeypatched(monkeypatch):
    """build_scope_from_config 가 API 클라이언트를 통해 Scope 를 구성하는지 (네트워크 대체)."""
    class FakeClient:
        def __init__(self, *a, **k): pass
        def programs(self):
            return [{"attributes": {"handle": "example"}},
                    {"attributes": {"handle": "acme"}}]
        def structured_scopes(self, handle):
            if handle == "example":
                return MOCK_SCOPES
            return [{"type": "structured-scope", "attributes": {
                "asset_type": "WILDCARD", "asset_identifier": "*.acme.io",
                "eligible_for_submission": True}}]

    monkeypatch.setattr(hackerone, "HackerOneClient", FakeClient)
    monkeypatch.setenv("H1_API_TOKEN", "dummy-token-for-test")

    cfg = Config(
        authorized=True, rate_limit_rps=10, concurrency=2, timeout=5,
        user_agent="t", output_dir="r", state_file="s", modules={},
        nuclei={}, notify={}, github={},
        scope_source="hackerone",
        hackerone={"username": "tester", "api_token_env": "H1_API_TOKEN"},
    )
    scope = hackerone.build_scope_from_config(cfg)
    assert "*.example.com" in scope.in_domains
    assert "*.acme.io" in scope.in_domains
    assert "2 programs" in scope.program
    print("test_build_scope_from_config_monkeypatched OK")


if __name__ == "__main__":
    class MP:
        def __init__(self): self._u = []
        def setattr(self, o, n, v):
            self._u.append((o, n, getattr(o, n))); setattr(o, n, v)
        def setenv(self, k, v):
            self._u.append((os.environ, k, os.environ.get(k))); os.environ[k] = v
        def undo(self):
            for o, n, v in reversed(self._u):
                if o is os.environ:
                    if v is None: os.environ.pop(n, None)
                    else: os.environ[n] = v
                else:
                    setattr(o, n, v)
    test_scopes_to_scope()
    test_only_bounty_filter()
    test_integration_with_scope_guard()
    mp = MP()
    try:
        test_build_scope_from_config_monkeypatched(mp)
    finally:
        mp.undo()
    print("\nHackerOne 테스트 통과 ✅")
