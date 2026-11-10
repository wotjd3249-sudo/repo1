# bb-auto — 권한 기반 버그바운티 자동화 파이프라인

승인된(in-scope) 자산에 대해서만 **정찰 → 경량 능동 탐지 → 중복 제거 → 리포트 → GitHub 푸시 → Slack/Discord 알림**을
한 번의 사이클로 자동 수행하는 프레임워크입니다.

> ⚠️ **법적 경고 / Authorization required**
> 이 도구는 **본인이 참여 권한을 가진 버그바운티 프로그램의 in-scope 자산** 또는 **본인 소유 자산**에만 사용해야 합니다.
> 권한 없는 대상에 대한 스캔은 대부분의 국가에서 불법(무단 접근)이며, 그로 인한 책임은 전적으로 사용자에게 있습니다.
> `config.yaml`의 `authorized: true`를 직접 설정해야만 실행됩니다. 이는 "나는 등록된 범위에 대한 테스트 권한이 있다"는 확인입니다.

## 안전장치 (기본 내장)

- **Scope Guard**: 모든 호스트/URL은 `scope.yaml`의 in-scope와 일치하고 out-of-scope가 아니어야만 요청됩니다. out-of-scope가 항상 우선합니다.
- **권한 게이트**: `authorized: true` 없이는 실행 거부.
- **레이트리밋 / 동시성 제한**: 대상 서버 부하를 막기 위한 초당 요청 수·동시 연결 제한.
- **비파괴적 기본값**: GET 위주 탐지, 알려진 노출 경로·핑거프린팅·CVE 매칭. 공격성 액티브 탐지는 nuclei 안전 태그로 제한, 기본 비활성.

## 설치

```bash
cd /home/user/bb-auto
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

선택적 외부 도구(있으면 자동 사용, 없으면 건너뜀):
- `subfinder` — 서브도메인 수집 강화
- `nuclei` — 경량 능동 취약점 탐지(안전 템플릿)

## 설정

```bash
cp config.example.yaml config.yaml
# config.yaml: authorized:true, 알림 webhook, github repo 설정
```

스코프 공급 방식은 `config.yaml` 의 `scope_source` 로 선택합니다.

### 방식 1) HackerOne API 자동 수집 (`scope_source: hackerone`)

참여 중인 프로그램의 in-scope 자산을 API 로 자동 수집합니다.
`eligible_for_submission=false` 자산은 자동으로 out-of-scope 로 분류됩니다.

```bash
# 토큰은 파일에 넣지 말고 환경변수로 주입 (권장)
export H1_USERNAME="your-h1-username"
export H1_API_TOKEN="xxxxxxxx"     # https://hackerone.com/settings/api_token/edit
```

```yaml
# config.yaml
scope_source: "hackerone"
hackerone:
  username: ""                 # 비우면 H1_USERNAME 환경변수 사용
  api_token: ""                # 비우면 H1_API_TOKEN 환경변수 사용
  handles: []                  # 특정 프로그램만. 비우면 참여 중인 전체
  only_bounty_eligible: false  # bounty 대상만 수집하려면 true
  web_asset_types: ["URL", "DOMAIN", "WILDCARD"]
```

> HackerOne API 는 Basic 인증(사용자명 + API 토큰)을 사용합니다. 토큰 발급 후 위 환경변수에 넣으세요.
> 토큰을 `config.yaml` 에 직접 적지 마세요(실수 커밋 방지). `config.yaml` 은 `.gitignore` 로 제외됩니다.

### 방식 2) 스코프 파일 직접 작성 (`scope_source: file`)

```bash
cp scope.example.yaml scope.yaml
# scope.yaml 에 본인 권한 범위의 도메인/URL 입력
```

## 실행

```bash
# 한 사이클 실행
python -m bbauto run

# 주기적 자동 실행 (내장 루프, 예: 6시간마다)
python -m bbauto run --loop --interval 21600

# 설정/스코프 유효성만 점검
python -m bbauto check
```

### cron으로 자동화 (권장)

```bash
# 매일 03:17에 실행 (서버 부하 분산 위해 정각 회피)
17 3 * * * cd /home/user/bb-auto && .venv/bin/python -m bbauto run >> run.log 2>&1
```

### GitHub Actions로 자동화

`.github/workflows/bugbounty.yml` 참고. 리포지토리 Secrets에 `SLACK_WEBHOOK`/`DISCORD_WEBHOOK` 등록 후 schedule로 구동됩니다.

## 동작 흐름

1. 스코프 로드(HackerOne API 또는 `scope.yaml`) → Scope Guard 초기화
2. 서브도메인 수집(passive: crt.sh, + subfinder)
3. HTTP 프로빙 + 기술 핑거프린팅
4. 경량 탐지: 노출 시크릿/설정 경로(시그니처 기반), 기술 버전→CVE 매칭, (옵션) nuclei
5. 중복 제거(state/findings.json) → 신규 finding만 추출
6. 마크다운 리포트 생성 → GitHub 리포에 커밋/푸시 (옵션: Issue 생성)
7. Slack/Discord로 시작·신규 finding·완료 알림

## 탐지 상세

**노출 경로/시크릿** (`secrets` 모듈) — 각 경로는 **시그니처가 응답 바디에 매칭될 때만** finding 으로 올려 오탐을 줄입니다.
- `secrets.level: standard` (기본): `.env`, `.git/`, `actuator/env` 등 고가치 경로 위주 (요청량 적음)
- `secrets.level: deep`: 백업/덤프, 클라우드 자격(`.aws/credentials`, `terraform.tfstate`, `.kube/config`, `.npmrc`, SSH 키), 프레임워크 설정(Spring/Django/Laravel), `actuator/heapdump`, API 스펙 등 전체(요청량 많음)
- `secrets.extra_paths` 로 사용자 정의 경로 추가 가능

**기술 버전 → CVE 매칭** (`cve_match` 모듈) — 핑거프린팅으로 추출한 버전을 로컬 CVE DB와 **버전 비교**로 매칭
(Apache 2.4.49/50, nginx <1.21, Drupalgeddon, Joomla RCE, Jenkins CVE-2024-23897, Tomcat Ghostcat 등).
> ⚠️ 배너 버전 기반 **추정**이라 백포트 패치된 경우 오탐 가능 — 반드시 수동 검증 후 신고하세요.

**nuclei** (`nuclei` 모듈, 설치 필요) — 안전 프리셋(`dos,fuzz,intrusive,brute-force` 태그 기본 제외),
레이트리밋·동시성·타임아웃·실행시간 상한을 config로 제어, 결과에서 CVE/참고링크·추출값 파싱, 스코프 이중 재확인.

## 디렉터리

```
bb-auto/
  bbauto/            # 코드
  scope.yaml         # 권한 범위 (사용자 작성)
  config.yaml        # 설정 (사용자 작성)
  reports/           # 생성된 리포트
  state/             # 중복 제거 상태
```

## 책임 있는 공개(Responsible Disclosure)

발견한 취약점은 반드시 해당 프로그램의 공식 제출 채널로만 신고하세요. 이 도구는 탐지·정리·추적을 돕지만,
실제 제출·검증·PoC 작성은 프로그램 규칙과 법을 준수하여 사람이 판단해야 합니다.
