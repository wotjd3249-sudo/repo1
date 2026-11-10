"""전체 사이클 오케스트레이션."""
from __future__ import annotations

from .config import Config, Scope
from .findings import FindingStore
from .github_push import GitHubPublisher
from .http import HttpClient
from .notify import Notifier
from . import recon, report, scan
from .scope_guard import ScopeGuard


def run_cycle(cfg: Config, scope: Scope, verbose: bool = True) -> dict:
    def log(msg: str) -> None:
        if verbose:
            print(f"[bb-auto] {msg}", flush=True)

    guard = ScopeGuard(scope)
    http = HttpClient(cfg.user_agent, cfg.timeout, cfg.rate_limit_rps)
    notifier = Notifier(cfg.notify)
    store = FindingStore(cfg.state_file)
    stamp = report.now_stamp()
    mods = cfg.modules

    summary = {"hosts": 0, "findings": 0, "new": 0, "report": "", "github": "",
               "issues": 0, "stamp": stamp}

    try:
        if notifier.enabled():
            notifier.start(scope.program, len(scope.seed_domains))

        # 1) 서브도메인 수집
        if mods.get("subdomains", True):
            log("서브도메인 수집 중...")
            hosts = recon.enumerate_subdomains(scope.seed_domains, guard, http)
        else:
            hosts = guard.filter_hosts(scope.seed_domains)
        log(f"스코프 내 호스트 {len(hosts)}개")

        # 2) HTTP 프로빙 + 핑거프린팅
        probed: list[recon.Host] = []
        if mods.get("http_probe", True) and hosts:
            log("HTTP 프로빙 + 핑거프린팅...")
            probed = recon.probe_all(hosts, guard, http, cfg.concurrency)
        else:
            probed = [recon.Host(host=h) for h in hosts]
        live = [h for h in probed if h.status]
        summary["hosts"] = len(live)
        log(f"응답 호스트 {len(live)}개")

        # 3) 탐지
        findings = []
        if mods.get("secrets", True):
            log("노출 경로/시크릿 탐지...")
            findings += scan.scan_exposed(live, guard, http, cfg.concurrency)
        if mods.get("cve_match", True):
            log("기술→CVE 매칭...")
            findings += scan.scan_cves(live)
        if mods.get("nuclei", False):
            log("nuclei 경량 능동 탐지...")
            findings += scan.scan_nuclei(live, guard, cfg.nuclei)

        summary["findings"] = len(findings)

        # 4) 중복 제거 → 신규 추출
        new = store.record(findings)
        store.save()
        summary["new"] = len(new)
        log(f"finding {len(findings)}개 (신규 {len(new)}개)")

        for f in new:
            if notifier.enabled():
                notifier.finding(f)

        # 5) 리포트 생성
        content = report.build_report(scope.program, live, findings, new, stamp)
        rpath = report.write_report(cfg.output_dir, content, stamp)
        summary["report"] = rpath
        log(f"리포트: {rpath}")

        # 6) GitHub 푸시
        gh = GitHubPublisher(cfg.github)
        if gh.enabled:
            import os
            ok, msg = gh.publish(content, os.path.basename(rpath), stamp)
            summary["github"] = msg
            log(f"GitHub: {msg}")
            if new:
                n = gh.open_issues(new)
                summary["issues"] = n
                if n:
                    log(f"GitHub Issue {n}개 생성")

        # 7) 완료 알림
        if notifier.enabled():
            notifier.done(scope.program, len(live), len(findings), len(new))

    except Exception as e:  # noqa: BLE001
        log(f"오류: {e}")
        if notifier.enabled():
            notifier.error(scope.program, str(e))
        raise

    return summary
