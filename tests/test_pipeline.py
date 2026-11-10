"""오프라인 통합 테스트: 외부 네트워크 없이 파이프라인 전체 흐름 검증."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbauto import pipeline, recon
from bbauto.config import Config, Scope


def _cfg(tmp):
    return Config(
        authorized=True, rate_limit_rps=100, concurrency=4, timeout=5,
        user_agent="bbauto-test", output_dir=os.path.join(tmp, "reports"),
        state_file=os.path.join(tmp, "state", "f.json"),
        modules={"subdomains": True, "http_probe": True, "secrets": False,
                 "cve_match": True, "nuclei": False},
        nuclei={}, notify={},
        github={"enabled": True, "repo_dir": os.path.join(tmp, "repo"),
                "remote": "", "branch": "main", "commit_name": "t",
                "commit_email": "t@t", "create_issues": False},
    )


def test_full_cycle_offline(monkeypatch):
    scope = Scope(program="Test", in_domains=["example.com", "*.example.com"])

    # 네트워크 레이어를 가짜로 대체 (실제 요청 없음)
    monkeypatch.setattr(recon, "enumerate_subdomains",
                        lambda seeds, guard, http: ["api.example.com"])

    def fake_probe(hosts, guard, http, concurrency):
        return [recon.Host(host="api.example.com", url="https://api.example.com",
                           status=200, server="Apache/2.4.49", title="Test",
                           tech={"apache": "2.4.49", "jenkins": "2.426.1"})]
    monkeypatch.setattr(recon, "probe_all", fake_probe)

    with tempfile.TemporaryDirectory() as tmp:
        cfg = _cfg(tmp)
        s1 = pipeline.run_cycle(cfg, scope, verbose=False)

        # CVE 매칭: apache 2.4.49 → CVE-2021-41773, jenkins → CVE-2024-23897
        assert s1["findings"] >= 2, s1
        assert s1["new"] == s1["findings"]
        assert os.path.exists(s1["report"]), "리포트 파일 생성 안됨"
        content = open(s1["report"], encoding="utf-8").read()
        assert "CVE-2021-41773" in content
        assert "CVE-2024-23897" in content
        assert "자산 인벤토리" in content

        # 로컬 git 커밋 확인
        assert "커밋" in s1["github"], s1["github"]
        assert os.path.isdir(os.path.join(tmp, "repo", ".git"))

        # 2차 실행: 동일 finding → 신규 0 (중복 제거 동작)
        s2 = pipeline.run_cycle(cfg, scope, verbose=False)
        assert s2["new"] == 0, s2
        assert s2["findings"] == s1["findings"]

    print("test_full_cycle_offline OK")


if __name__ == "__main__":
    # pytest 없이도 실행 가능하도록 간단 monkeypatch shim
    class MP:
        def __init__(self): self._undo = []
        def setattr(self, obj, name, val):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, val)
        def undo(self):
            for o, n, v in reversed(self._undo): setattr(o, n, v)
    mp = MP()
    try:
        test_full_cycle_offline(mp)
        print("\n통합 테스트 통과 ✅")
    finally:
        mp.undo()
