"""명령행 인터페이스."""
from __future__ import annotations

import argparse
import sys
import time

from .config import Config, ConfigError, assert_authorized, load_config, load_scope
from .pipeline import run_cycle


def _load_cfg(args) -> Config:
    try:
        return load_config(args.config)
    except ConfigError as e:
        print(f"[설정 오류] {e}", file=sys.stderr)
        raise SystemExit(2)


def _resolve_scope(cfg: Config, args):
    """scope_source 에 따라 스코프를 파일 또는 HackerOne API 에서 가져온다."""
    if cfg.scope_source == "hackerone":
        from .hackerone import HackerOneError, build_scope_from_config
        try:
            return build_scope_from_config(cfg)
        except HackerOneError as e:
            print(f"[HackerOne 오류] {e}", file=sys.stderr)
            raise SystemExit(2)
    try:
        return load_scope(args.scope)
    except ConfigError as e:
        print(f"[스코프 오류] {e}", file=sys.stderr)
        raise SystemExit(2)


def cmd_check(args) -> int:
    cfg = _load_cfg(args)
    print(f"스코프 소스    : {cfg.scope_source}")
    print(f"authorized     : {cfg.authorized}")
    print(f"활성 모듈      : {[k for k, v in cfg.modules.items() if v]}")
    print(f"알림           : slack={bool(cfg.notify.get('slack_webhook'))} "
          f"discord={bool(cfg.notify.get('discord_webhook'))}")
    print(f"github         : enabled={cfg.github.get('enabled')} "
          f"remote={cfg.github.get('remote') or '(origin 사용)'}")
    # 스코프 해석은 네트워크(HackerOne)일 수 있으므로 실패해도 설정 점검은 계속
    try:
        scope = _resolve_scope(cfg, args)
        print(f"프로그램       : {scope.program}")
        print(f"in-scope 도메인: {len(scope.in_domains)} / URL: {len(scope.in_urls)} "
              f"/ out-of-scope 도메인: {len(scope.out_domains)}")
        print(f"시드 도메인    : {', '.join(scope.seed_domains[:10]) or '(없음)'}"
              + (" ..." if len(scope.seed_domains) > 10 else ""))
    except SystemExit:
        print("스코프        : 가져오기 실패(위 오류 참고)")
    if not cfg.authorized:
        print("\n⚠ authorized:false — run 은 차단됩니다. 권한 확인 후 true 로 설정하세요.")
    return 0


def cmd_run(args) -> int:
    cfg = _load_cfg(args)
    assert_authorized(cfg)
    scope = _resolve_scope(cfg, args)

    if not args.loop:
        run_cycle(cfg, scope)
        return 0

    print(f"[bb-auto] 루프 모드: {args.interval}초 간격")
    while True:
        try:
            run_cycle(cfg, scope)
        except Exception as e:  # noqa: BLE001
            print(f"[bb-auto] 사이클 오류(계속 진행): {e}", file=sys.stderr)
        print(f"[bb-auto] 다음 사이클까지 {args.interval}초 대기...", flush=True)
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[bb-auto] 종료.")
            return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bbauto",
        description="권한 기반 버그바운티 자동화 파이프라인",
    )
    p.add_argument("--config", default="config.yaml", help="설정 파일 경로")
    p.add_argument("--scope", default="scope.yaml", help="스코프 파일 경로")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="설정/스코프 유효성 점검").set_defaults(func=cmd_check)

    r = sub.add_parser("run", help="스캔 사이클 실행")
    r.add_argument("--loop", action="store_true", help="주기적 반복 실행")
    r.add_argument("--interval", type=int, default=21600, help="루프 간격(초), 기본 6시간")
    r.set_defaults(func=cmd_run)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
