"""마크다운 리포트 생성."""
from __future__ import annotations

import os
from datetime import datetime, timezone

from .findings import SEVERITY_ORDER, Finding
from .recon import Host

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _sev_sort(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.severity.lower(), 0))


def build_report(program: str, hosts: list[Host], all_findings: list[Finding],
                 new_findings: list[Finding], stamp: str) -> str:
    lines: list[str] = []
    a = lines.append
    a(f"# 버그바운티 스캔 리포트 — {program}")
    a("")
    a(f"- **실행 시각(UTC)**: {stamp}")
    a(f"- **프로빙된 호스트**: {len(hosts)}")
    a(f"- **이번 사이클 finding**: {len(all_findings)} (신규 {len(new_findings)})")
    a("")

    # 심각도 요약
    counts: dict[str, int] = {}
    for f in all_findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
    if counts:
        a("## 심각도 요약")
        a("")
        a("| 심각도 | 개수 |")
        a("|---|---|")
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev):
                a(f"| {SEV_EMOJI[sev]} {sev} | {counts[sev]} |")
        a("")

    # 신규 finding
    if new_findings:
        a("## 🆕 신규 Finding")
        a("")
        for f in _sev_sort(new_findings):
            _write_finding(a, f)

    # 전체 finding
    a("## 전체 Finding")
    a("")
    if not all_findings:
        a("_이번 사이클에서 탐지된 finding 이 없습니다._")
        a("")
    for f in _sev_sort(all_findings):
        _write_finding(a, f)

    # 자산 인벤토리
    a("## 자산 인벤토리")
    a("")
    a("| 호스트 | 상태 | 서버 | 기술 | 제목 |")
    a("|---|---|---|---|---|")
    for h in sorted(hosts, key=lambda x: x.host):
        tech = ", ".join(f"{k}{(' ' + v) if v else ''}" for k, v in h.tech.items())
        title = (h.title or "").replace("|", "\\|")
        a(f"| {h.host} | {h.status} | {h.server or '-'} | {tech or '-'} | {title or '-'} |")
    a("")
    a("---")
    a("_생성: bb-auto. 발견 항목은 반드시 해당 프로그램의 공식 채널로만 신고하세요._")
    return "\n".join(lines)


def _write_finding(a, f: Finding) -> None:
    emoji = SEV_EMOJI.get(f.severity.lower(), "⚪")
    a(f"### {emoji} [{f.severity.upper()}] {f.title}")
    a("")
    a(f"- **대상**: `{f.target}`")
    a(f"- **유형**: {f.type} (탐지: {f.source})")
    if f.evidence:
        a(f"- **근거**: {f.evidence}")
    if f.reference:
        a(f"- **참고**: {f.reference}")
    a(f"- **최초 발견**: {f.first_seen}")
    a("")


def write_report(output_dir: str, content: str, stamp: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    safe = stamp.replace(":", "").replace("-", "").replace("T", "-")[:15]
    path = os.path.join(output_dir, f"report-{safe}.md")
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(content)
    # 최신 리포트 심볼릭 역할
    latest = os.path.join(output_dir, "latest.md")
    with open(latest, "w", encoding="utf-8") as fp:
        fp.write(content)
    return path


def now_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
