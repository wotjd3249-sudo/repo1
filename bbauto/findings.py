"""Finding 데이터 모델 + 중복 제거 상태 저장소."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    type: str              # 예: "exposed-file", "cve-match", "nuclei"
    title: str
    severity: str          # info|low|medium|high|critical
    target: str            # URL 또는 host
    source: str            # 탐지 모듈 이름
    evidence: str = ""
    reference: str = ""
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)

    @property
    def id(self) -> str:
        key = f"{self.type}|{self.target}|{self.title}".lower()
        return hashlib.sha1(key.encode()).hexdigest()[:16]

    def sev_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)


class FindingStore:
    def __init__(self, path: str):
        self.path = path
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def record(self, findings: list[Finding]) -> list[Finding]:
        """새 finding 저장. 이전에 못 본 것만 반환(신규)."""
        new: list[Finding] = []
        for f in findings:
            fid = f.id
            if fid in self._data:
                self._data[fid]["last_seen"] = f.last_seen
            else:
                self._data[fid] = asdict(f)
                self._data[fid]["id"] = fid
                new.append(f)
        return new

    def all(self) -> list[dict]:
        return list(self._data.values())

    def count(self) -> int:
        return len(self._data)
