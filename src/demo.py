#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""logscrub 可复现 demo：核心脱敏 + 授权校验（正例/负例）全链路自检。

用法：python demo.py
产物写到系统临时目录，不污染仓库；全部检查通过时退出码 0。
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import cli
import license_gate
import logscrub

CHECKS = []

FAKE_PHONE_A = "13800138000"
FAKE_PHONE_B = "13900139001"
FAKE_ID_A = "110105199003071234"
FAKE_ID_B = "310101198512310011"
FAKE_EMAIL = "zhang.wei@example.com"
FAKE_CARD = "6222020200112233445"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEyMywiZW1haWwiOiJhQGIuY29tIn0.c2lnbmF0dXJlc2ln"
FAKE_SECRET = "P@ssw0rd-9x"

FIXTURES = {
    "app.log": (
        "2024-05-11 09:12:03 INFO login user=" + FAKE_EMAIL + " ip=203.0.113.7\n"
        "2024-05-11 09:12:04 WARN db password=\"" + FAKE_SECRET + "\" api_key=sk-live-8f2b1c9d4e\n"
        "2024-05-11 09:13:10 INFO order ORD2024051100123 amount=199.00\n"
        "2024-05-11 09:13:11 ERROR upstream rejected trace=" + FAKE_JWT + "\n"
    ),
    "access.log": (
        "203.0.113.7 - - [11/May/2024:09:12:03 +0800] \"GET /api/user?phone=" + FAKE_PHONE_A + " HTTP/1.1\" 200 512\n"
        "198.51.100.42 - - [11/May/2024:09:12:09 +0800] \"POST /api/pay card=" + FAKE_CARD + " HTTP/1.1\" 200 233\n"
    ),
    "tickets.csv": (
        "ticket_id,id_card,phone,note\n"
        "T-1001," + FAKE_ID_A + "," + FAKE_PHONE_A + ",客户要求回访\n"
        "T-1002," + FAKE_ID_B + "," + FAKE_PHONE_B + ",退款\n"
    ),
}

RULES = {
    "version": 1,
    "rules": [
        {"kind": "ORDER_ID", "pattern": "ORD\\d{11}"},
        {"kind": "INTERNAL_HOST", "pattern": "[a-z0-9-]+\\.corp\\.example\\.com"},
    ],
}


def check(name, ok, detail="") -> bool:
    CHECKS.append((name, bool(ok), detail))
    mark = "PASS" if ok else "FAIL"
    print("  [{0}] {1}{2}".format(mark, name, ("  -> " + detail) if detail else ""))
    return bool(ok)


def main() -> int:
    cli._reconfigure_stdio()
    tmp = Path(tempfile.mkdtemp(prefix="logscrub-demo-"))
    src = tmp / "logs"
    src.mkdir(parents=True, exist_ok=True)
    for name, body in FIXTURES.items():
        (src / name).write_text(body, encoding="utf-8")
    print("工作目录：{0}\n".format(tmp))

    print("[1/7] 生成 3 个样本日志：手机号 / 身份证 / 银行卡 / 邮箱 / 明文口令 / JWT / 内网 IP")
    check("样本文件落盘", len(list(src.iterdir())) == 3, "3 files")

    print("\n[2/7] 免费模式边界：单文件放行、目录批量拦截")
    rc_single = cli.main(["scrub", "--in", str(src / "tickets.csv"), "--out", str(tmp / "free_out"), "--quiet"])
    check("免费模式单文件脱敏放行", rc_single == cli.EXIT_OK, "exit={0}".format(rc_single))
    rc_batch = cli.main(["scrub", "--in", str(src), "--out", str(tmp / "free_batch"), "--quiet"])
    check("免费模式目录批量被拦截", rc_batch == cli.EXIT_UPGRADE, "exit={0}".format(rc_batch))

    print("\n[3/7] 签发演示授权（DEMO 共享密钥；正式版由服务端私钥签发）")
    demo_blob = license_gate.default_demo_blob()
    license_file = tmp / "license.json"
    license_file.write_text(
        json.dumps({"license_blob": demo_blob, "serial": license_gate.DEMO_SERIAL}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    lic = license_gate.verify_license(demo_blob, license_gate.DEMO_SERIAL)
    check("DEMO LICENSE_BLOB 验签通过", lic.ok and lic.tier == "pro", "{0} / 到期 {1}".format(lic.code, lic.expires_at))

    print("\n[4/7] Pro 模式批量脱敏 + JSON 审计报告")
    out = tmp / "pro_out"
    report_path = tmp / "report.json"
    rc_pro = cli.main(
        [
            "scrub",
            "--in", str(src),
            "--out", str(out),
            "--license", str(license_file),
            "--report", str(report_path),
            "--salt", "demo-salt-001",
        ]
    )
    check("Pro 批量脱敏退出码 0", rc_pro == cli.EXIT_OK, "exit={0}".format(rc_pro))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    check("处理后复扫残留为 0", report["residual_after_rescan"] == 0, "residual={0}".format(report["residual_after_rescan"]))
    check("识别出 >=6 类敏感数据", len(report["totals"]) >= 6, "kinds=" + ",".join(sorted(report["totals"])))

    print("\n[5/7] 一致性校验：同一敏感值跨文件映射为同一令牌")
    app_txt = (out / "app.log").read_text(encoding="utf-8")
    access_txt = (out / "access.log").read_text(encoding="utf-8")
    tickets_txt = (out / "tickets.csv").read_text(encoding="utf-8")
    tokenizer = logscrub.Tokenizer("demo-salt-001")
    phone_token = tokenizer.token("CN_MOBILE", FAKE_PHONE_A)
    check(
        "跨文件同一手机号令牌一致",
        (phone_token in access_txt) and (phone_token in tickets_txt),
        phone_token,
    )
    check(
        "原文敏感值已彻底消失",
        (FAKE_PHONE_A not in access_txt) and (FAKE_PHONE_A not in tickets_txt)
        and (FAKE_ID_A not in tickets_txt) and (FAKE_CARD not in access_txt)
        and (FAKE_EMAIL not in app_txt) and (FAKE_SECRET not in app_txt),
        "no plaintext in outputs",
    )
    check("非敏感字段保持原样", ("ORD2024051100123" in app_txt) and ("amount=199.00" in app_txt), "context kept")
    _, again_counts, again_residual = logscrub.scrub_text(app_txt, logscrub.Tokenizer("demo-salt-001"))
    check(
        "重复脱敏幂等（令牌不会被二次替换）",
        (not again_counts) and again_residual == 0,
        "replaced=" + str(sum(again_counts.values())),
    )
    other = logscrub.Tokenizer("another-salt")
    check("更换 salt 后令牌不可关联", other.token("CN_MOBILE", FAKE_PHONE_A) != phone_token, "salt isolation")

    print("\n[6/7] Pro 自定义规则（与 rules.example.json 同结构）")
    rules_file = tmp / "rules.json"
    rules_file.write_text(json.dumps(RULES, ensure_ascii=False, indent=2), encoding="utf-8")
    out2 = tmp / "pro_out_rules"
    rc_rules = cli.main(
        [
            "scrub",
            "--in", str(src / "app.log"),
            "--out", str(out2),
            "--license", str(license_file),
            "--rules", str(rules_file),
            "--quiet",
        ]
    )
    app_rules_txt = (out2 / "app.log").read_text(encoding="utf-8") if rc_rules == 0 else ""
    check("自定义规则 ORDER_ID 生效", rc_rules == 0 and "[ORDER_ID:" in app_rules_txt, "exit={0}".format(rc_rules))
    rc_free_rules = cli.main(
        ["scrub", "--in", str(src / "app.log"), "--out", str(tmp / "free_rules"), "--rules", str(rules_file), "--quiet"]
    )
    check("免费模式拒绝自定义规则", rc_free_rules == cli.EXIT_UPGRADE, "exit={0}".format(rc_free_rules))

    print("\n[7/7] 授权负例")
    last_char = demo_blob[-1]
    tampered = demo_blob[:-1] + ("A" if last_char != "A" else "B")
    tampered_result = license_gate.verify_license(tampered, license_gate.DEMO_SERIAL)
    check("篡改 LICENSE_BLOB -> 签名失败", tampered_result.code == "BAD_SIGNATURE", tampered_result.code)
    mismatch = license_gate.verify_license(demo_blob, "LS-PRO-OTHER-9999")
    check("串用他人 SERIAL -> 拒绝", mismatch.code == "SERIAL_MISMATCH", mismatch.code)
    expired = license_gate.issue_license(license_gate.DEMO_SERIAL, days=-30)
    expired_result = license_gate.verify_license(expired, license_gate.DEMO_SERIAL)
    check("过期授权 -> 拒绝", expired_result.code == "EXPIRED", expired_result.reason)
    no_lic = license_gate.verify_license(None, None)
    check("无授权 -> 免费模式", no_lic.code == "NO_LICENSE" and not no_lic.ok, no_lic.code)
    rc_nolic_batch = cli.main(["scrub", "--in", str(src), "--out", str(tmp / "nolic"), "--quiet"])
    check("无授权批量仍被拦截", rc_nolic_batch == cli.EXIT_UPGRADE, "exit={0}".format(rc_nolic_batch))

    passed = sum(1 for _, ok, _ in CHECKS if ok)
    total = len(CHECKS)
    print("\n" + "=" * 58)
    print("结果：{0}/{1} 通过".format(passed, total))
    failed = [name for name, ok, _ in CHECKS if not ok]
    if failed:
        print("失败项：" + "；".join(failed))
        return 1
    print("ALL CHECKS PASSED")
    print("产物目录（可查看脱敏结果与报告）：{0}".format(tmp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
