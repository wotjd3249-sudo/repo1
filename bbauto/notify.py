"""Slack / Discord 알림."""
from __future__ import annotations

import requests

from .findings import SEVERITY_ORDER, Finding

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


class Notifier:
    def __init__(self, cfg_notify: dict):
        self.slack = (cfg_notify.get("slack_webhook") or "").strip()
        self.discord = (cfg_notify.get("discord_webhook") or "").strip()
        self.min_rank = SEVERITY_ORDER.get(
            str(cfg_notify.get("min_severity", "low")).lower(), 1)

    def _post(self, text: str) -> None:
        if self.slack:
            try:
                requests.post(self.slack, json={"text": text}, timeout=10)
            except requests.RequestException:
                pass
        if self.discord:
            try:
                # Discord 2000자 제한
                requests.post(self.discord, json={"content": text[:1900]}, timeout=10)
            except requests.RequestException:
                pass

    def enabled(self) -> bool:
        return bool(self.slack or self.discord)

    def start(self, program: str, host_count: int) -> None:
        self._post(f":mag: *bb-auto 스캔 시작* — `{program}` (시드/호스트 수집 중)")

    def finding(self, f: Finding) -> None:
        if SEVERITY_ORDER.get(f.severity.lower(), 0) < self.min_rank:
            return
        emoji = SEV_EMOJI.get(f.severity.lower(), "⚪")
        self._post(
            f"{emoji} *신규 [{f.severity.upper()}]* {f.title}\n"
            f"> 대상: `{f.target}`\n> 유형: {f.type} / {f.source}"
            + (f"\n> 근거: {f.evidence}" if f.evidence else "")
        )

    def done(self, program: str, hosts: int, total: int, new: int, report_url: str = "") -> None:
        msg = (
            f":white_check_mark: *bb-auto 완료* — `{program}`\n"
            f"> 호스트 {hosts} · finding {total} (신규 {new})"
        )
        if report_url:
            msg += f"\n> 리포트: {report_url}"
        self._post(msg)

    def error(self, program: str, err: str) -> None:
        self._post(f":warning: *bb-auto 오류* — `{program}`\n> {err[:300]}")
