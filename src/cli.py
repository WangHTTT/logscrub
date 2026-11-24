#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""logscrub 命令行入口：脱敏主流程 + 授权查询 + 签发端工具。

退出码：0 成功 / 1 处理失败 / 3 触达付费边界（需 Pro）
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import license_gate
import logscrub

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_UPGRADE = 3


def _reconfigure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def resolve_license(args) -> license_gate.LicenseResult:
    """优先级：--demo > --license(文件) > --serial > 免费模式。"""
    if getattr(args, "demo", False):
        result = license_gate.verify_license(license_gate.default_demo_blob(), license_gate.DEMO_SERIAL)
        result.reason = "DEMO 内置演示授权｜" + result.reason
        return result
    blob = None
    serial = getattr(args, "serial", None)
    license_path = getattr(args, "license", None)
    if license_path:
        blob, file_serial = license_gate.load_license_file(license_path)
        serial = serial or file_serial
    return license_gate.verify_license(blob, serial)


def print_report(report) -> None:
    kinds = report["totals"]
    detail = "  ".join("{0}={1}".format(k, v) for k, v in sorted(kinds.items())) or "无敏感数据"
    files = len(report["files"])
    lines = sum(item["lines"] for item in report["files"])
    print("模式：{0}    文件：{1}    行数：{2}".format(report["mode"], files, lines))
    print("替换：{0} 处    [{1}]".format(report["replaced"], detail))
    print("复扫残留：{0} 处（必须为 0 才算通过）".format(report["residual_after_rescan"]))
    print("salt 指纹：{0}    耗时：{1} ms".format(report["salt_fingerprint"], report["elapsed_ms"]))
    if report["output"]:
        print("输出：{0}".format(report["output"]))


def cmd_scrub(args) -> int:
    lic = resolve_license(args)
    if not args.quiet:
        if lic.ok:
            print("授权：{0}｜{1}".format(lic.tier, lic.reason))
        else:
            print("授权：free｜{0}".format(lic.reason))
    extra_rules = None
    if args.rules:
        try:
            extra_rules = logscrub.load_rules_file(args.rules)
        except (OSError, ValueError) as exc:
            print("[错误] 规则文件无法使用：{0}".format(exc), file=sys.stderr)
            return EXIT_FAIL
    try:
        report = logscrub.run_scrub(
            src=Path(args.in_path),
            dst=Path(args.out_path),
            salt=args.salt,
            extra_rules=extra_rules,
            dry_run=args.dry_run,
            is_pro=lic.ok,
            rules_path=Path(args.rules) if args.rules else None,
            want_report=bool(args.report),
        )
    except logscrub.UpgradeRequired as exc:
        print("[需要 Pro] {0}".format(exc), file=sys.stderr)
        return EXIT_UPGRADE
    except (OSError, ValueError) as exc:
        print("[错误] {0}".format(exc), file=sys.stderr)
        return EXIT_FAIL

    if args.report:
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if not args.quiet:
        print_report(report)
    return EXIT_FAIL if report["residual_after_rescan"] > 0 else EXIT_OK


def cmd_license_check(args) -> int:
    lic = resolve_license(args)
    print("判定：{0}".format("通过" if lic.ok else "未通过"))
    print("档位：{0}".format(lic.tier))
    print("序列号：{0}".format(lic.serial or "-"))
    print("到期：{0}".format(lic.expires_at or "-"))
    print("功能：{0}".format(", ".join(lic.features) or "-"))
    print("代码：{0}".format(lic.code))
    print("说明：{0}".format(lic.reason))
    if lic.ok:
        return EXIT_OK
    return EXIT_UPGRADE if lic.code == "NO_LICENSE" else EXIT_FAIL


def cmd_issue(args) -> int:
    """签发端工具（正式版只在服务端的内部 CLI 里存在）。"""
    try:
        blob = license_gate.issue_license(args.serial, tier=args.tier, days=args.days)
    except ValueError as exc:
        print("[错误] {0}".format(exc), file=sys.stderr)
        return EXIT_FAIL
    if args.out:
        Path(args.out).write_text(blob, encoding="utf-8")
        print("已写入 {0}".format(args.out))
    print(blob)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logscrub",
        description="日志/工单 PII 脱敏器：本地运行、一致性令牌化、可审计。",
    )
    parser.add_argument("--version", action="version", version="logscrub {0}".format(logscrub.VERSION))
    sub = parser.add_subparsers(dest="command", required=True)

    p_scrub = sub.add_parser("scrub", help="对文件或目录做脱敏")
    p_scrub.add_argument("--in", dest="in_path", required=True, help="输入文件或目录")
    p_scrub.add_argument("--out", dest="out_path", required=True, help="输出目录，或单文件输出路径")
    p_scrub.add_argument("--salt", default=logscrub.DEFAULT_SALT, help="令牌化盐值；同盐才能保持跨文件一致性")
    p_scrub.add_argument("--rules", help="自定义规则 JSON（Pro）")
    p_scrub.add_argument("--report", help="审计报告 JSON 输出路径（Pro）")
    p_scrub.add_argument("--license", help="LICENSE_BLOB 文件（纯文本 blob 或含 serial 的 JSON）")
    p_scrub.add_argument("--serial", help="SERIAL 序列号")
    p_scrub.add_argument("--demo", action="store_true", help="使用内置演示授权")
    p_scrub.add_argument("--dry-run", action="store_true", help="只统计不落盘")
    p_scrub.add_argument("--quiet", action="store_true", help="只输出错误")
    p_scrub.set_defaults(func=cmd_scrub)

    p_check = sub.add_parser("license-check", help="校验 LICENSE_BLOB + SERIAL")
    p_check.add_argument("--license", help="LICENSE_BLOB 文件")
    p_check.add_argument("--serial", help="SERIAL 序列号")
    p_check.add_argument("--demo", action="store_true", help="使用内置演示授权")
    p_check.set_defaults(func=cmd_license_check)

    p_issue = sub.add_parser("issue", help="签发 LICENSE_BLOB（演示用签发端工具）")
    p_issue.add_argument("--serial", required=True, help="客户序列号")
    p_issue.add_argument("--tier", default="pro", choices=["pro", "free"], help="档位")
    p_issue.add_argument("--days", type=int, default=365, help="有效天数（负数可造过期负例）")
    p_issue.add_argument("--out", help="写入文件")
    p_issue.set_defaults(func=cmd_issue)

    return parser


def main(argv=None) -> int:
    _reconfigure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
