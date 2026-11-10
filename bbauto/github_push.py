"""리포트를 GitHub 리포지토리에 커밋/푸시 + (옵션) Issue 생성.

repo_dir 가 코드 리포와 같은 경우('.')도, 전용 리포트 리포인 경우도 지원.
리포트 파일은 gitignore 를 무시하고 강제 추가(git add -f)되므로,
코드 리포의 .gitignore 가 reports/ 를 무시해도 리포트는 정상 커밋됩니다.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time

from .findings import Finding


def _run(cmd: list[str], cwd: str | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        return p.returncode, (p.stdout + p.stderr)
    except (subprocess.SubprocessError, OSError) as e:
        return 1, str(e)


class GitHubPublisher:
    def __init__(self, cfg_github: dict):
        self.enabled = bool(cfg_github.get("enabled", False))
        self.repo_dir = os.path.abspath(cfg_github.get("repo_dir", "./bb-reports"))
        self.remote = (cfg_github.get("remote") or "").strip()
        self.branch = cfg_github.get("branch", "main")
        self.name = cfg_github.get("commit_name", "bb-auto")
        self.email = cfg_github.get("commit_email", "bb-auto@localhost")
        self.create_issues = bool(cfg_github.get("create_issues", False))
        self.issues_repo = (cfg_github.get("issues_repo") or "").strip()

    # ── 리포 준비 ───────────────────────────────────────────────
    def _origin_url(self) -> str:
        code, out = _run(["git", "remote", "get-url", "origin"], cwd=self.repo_dir)
        return out.strip() if code == 0 else ""

    def _ensure_repo(self) -> tuple[bool, str]:
        if not shutil.which("git"):
            return False, "git 미설치"
        git_dir = os.path.join(self.repo_dir, ".git")
        if not os.path.isdir(git_dir):
            # 기존 원격이 있으면 clone 시도(기존 히스토리 유지), 실패하면 init
            if self.remote:
                os.makedirs(os.path.dirname(self.repo_dir) or ".", exist_ok=True)
                code, out = _run(["git", "clone", "--depth", "1", "-b", self.branch,
                                  self.remote, self.repo_dir])
                if code != 0:
                    # 빈 리포지토리 등 → init 로 폴백
                    os.makedirs(self.repo_dir, exist_ok=True)
                    _run(["git", "init", "-b", self.branch], cwd=self.repo_dir)
                    _run(["git", "remote", "add", "origin", self.remote], cwd=self.repo_dir)
            else:
                os.makedirs(self.repo_dir, exist_ok=True)
                _run(["git", "init", "-b", self.branch], cwd=self.repo_dir)
        elif self.remote and not self._origin_url():
            _run(["git", "remote", "add", "origin", self.remote], cwd=self.repo_dir)
        _run(["git", "config", "user.name", self.name], cwd=self.repo_dir)
        _run(["git", "config", "user.email", self.email], cwd=self.repo_dir)
        return True, "ok"

    # ── 발행 ────────────────────────────────────────────────────
    def publish(self, report_content: str, filename: str, stamp: str) -> tuple[bool, str]:
        if not self.enabled:
            return False, "github 비활성"
        ok, msg = self._ensure_repo()
        if not ok:
            return False, msg

        # 최신 상태로 동기화(충돌 최소화)
        if self._origin_url():
            _run(["git", "pull", "--rebase", "--autostash", "origin", self.branch],
                 cwd=self.repo_dir)

        reports_dir = os.path.join(self.repo_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        rel_report = os.path.join("reports", filename)
        with open(os.path.join(self.repo_dir, rel_report), "w", encoding="utf-8") as f:
            f.write(report_content)
        with open(os.path.join(self.repo_dir, "latest.md"), "w", encoding="utf-8") as f:
            f.write(report_content)

        # gitignore 를 무시하고 리포트만 강제 스테이징
        _run(["git", "add", "-f", rel_report, "latest.md"], cwd=self.repo_dir)
        code, _ = _run(["git", "diff", "--cached", "--quiet"], cwd=self.repo_dir)
        if code == 0:
            return True, "변경 없음(커밋 생략)"

        code, out = _run(["git", "commit", "-m", f"scan: {stamp} 리포트 추가"],
                         cwd=self.repo_dir)
        if code != 0:
            return False, f"커밋 실패: {out[:200]}"

        if self._origin_url():
            code, out = self._push()
            return (code == 0), ("커밋 + 푸시 완료" if code == 0 else f"푸시 실패: {out[:200]}")
        return True, "커밋 완료(origin 없음, 푸시 생략)"

    def _push(self) -> tuple[int, str]:
        last = (1, "")
        for delay in (0, 2, 4, 8, 16):
            if delay:
                time.sleep(delay)
            last = _run(["git", "push", "-u", "origin", self.branch], cwd=self.repo_dir)
            if last[0] == 0:
                return last
        return last

    # ── Issue 생성 ──────────────────────────────────────────────
    def open_issues(self, new_findings: list[Finding]) -> int:
        if not (self.create_issues and new_findings and shutil.which("gh")):
            return 0
        repo = self.issues_repo or self._infer_repo()
        if not repo:
            return 0
        created = 0
        for f in new_findings:
            title = f"[{f.severity.upper()}] {f.title}"
            body = (
                f"**대상**: `{f.target}`\n\n"
                f"**유형**: {f.type} (탐지: {f.source})\n\n"
                f"**근거**: {f.evidence or '-'}\n\n"
                f"**참고**: {f.reference or '-'}\n\n"
                f"**최초 발견**: {f.first_seen}\n\n"
                f"_bb-auto 자동 생성. 공식 채널 신고 전 검증 필요._"
            )
            code, _ = _run([
                "gh", "issue", "create", "--repo", repo,
                "--title", title, "--body", body,
                "--label", f"severity:{f.severity.lower()}",
            ])
            if code == 0:
                created += 1
        return created

    def _infer_repo(self) -> str:
        m = self.remote or self._origin_url()
        if "github.com" not in m:
            return ""
        tail = m.split("github.com", 1)[1].lstrip(":/").removesuffix(".git")
        return tail if "/" in tail else ""
