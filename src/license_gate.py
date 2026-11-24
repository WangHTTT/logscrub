# -*- coding: utf-8 -*-
"""logscrub 授权校验骨架：LICENSE_BLOB + SERIAL。

LICENSE_BLOB 结构
-----------------
    <payload_b64url>.<signature_b64url>

* payload        = JSON：format / serial / tier / features / issued_at / expires_at
* payload_b64url = 无填充 base64url(payload 的 utf-8 字节)
* signature      = 无填充 base64url(HMAC-SHA256(secret, payload_b64url))

SERIAL 必须与 payload["serial"] 相等，防止把别人的授权文件配自己的序列号使用。

[DEMO 定位]
本文件用 HMAC + 代码内置共享密钥：能验签、能过期、能绑定序列号、能防篡改，
但拿到源码即可自签。它的用途是验证产品侧的授权逻辑是否闭合（正例/负例都跑通），
不是最终的防护强度。

[REAL-INTEGRATION] 正式接入点（在 verify_license 内有对应标记）
1. 签发端（自己的服务器或内网 CLI）用 Ed25519 私钥对 payload_b64 字节签名，
   私钥永不进客户端。
2. 客户端只内置公钥 PEM，验签函数换成 ed25519_verify(PUBLIC_PEM, payload, sig)。
   对应改动位置：verify_license 里 expected_sig 那一段。
3. 设备绑定：payload 增加 "machine" = 设备指纹哈希，验签通过后与本机指纹比对。
4. 在线激活 / 续期：POST /activate 拿 blob，缓存在 %LOCALAPPDATA%/logscrub，
   带租期与离线宽限期（例如 14 天），到期前静默刷新。
5. 吊销：payload 带 license_id，客户端定期拉吊销名单；命中即降级为免费模式。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# DEMO 专用共享密钥。正式版：私钥只在签发服务端，客户端只放公钥。
DEMO_SECRET = b"logscrub-demo-shared-secret-v1"
DEMO_SERIAL = "LS-PRO-DEMO-0001"
LICENSE_FORMAT = "logscrub-license/1"

TIER_FEATURES: Dict[str, List[str]] = {
    "free": [],
    "pro": ["batch", "custom_rules", "json_report", "vault"],
}


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sign_payload(payload_b64: str, secret: bytes = DEMO_SECRET) -> str:
    """对 payload 的 base64url 文本做 HMAC-SHA256，返回 base64url 签名串。"""
    mac = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return b64u_encode(mac)


def issue_license(
    serial: str,
    tier: str = "pro",
    days: Optional[int] = 365,
    secret: bytes = DEMO_SECRET,
    issued_days_ago: int = 0,
    features: Optional[List[str]] = None,
) -> str:
    """签发一个 LICENSE_BLOB。

    正式版这段逻辑只存在于签发服务端（或内网签发 CLI），客户端不持有密钥。
    days=None 表示永久授权；days 为负数可用于生成"已过期"的负例。
    """
    if not serial or not str(serial).strip():
        raise ValueError("serial 不能为空")
    now = datetime.now(timezone.utc)
    issued = now - timedelta(days=issued_days_ago)
    payload: Dict[str, Any] = {
        "format": LICENSE_FORMAT,
        "serial": str(serial).strip(),
        "tier": tier,
        "features": features if features is not None else TIER_FEATURES.get(tier, []),
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": None if days is None else (issued + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload_b64 = b64u_encode(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return payload_b64 + "." + sign_payload(payload_b64, secret)


@dataclass
class LicenseResult:
    ok: bool
    tier: str
    serial: Optional[str]
    expires_at: Optional[str]
    features: List[str]
    code: str
    reason: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def has(self, feature: str) -> bool:
        return self.ok and feature in self.features


def _free(code: str, reason: str) -> LicenseResult:
    return LicenseResult(False, "free", None, None, [], code, reason, {})


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def verify_license(
    blob: Optional[str],
    serial: Optional[str],
    secret: bytes = DEMO_SECRET,
    now: Optional[datetime] = None,
) -> LicenseResult:
    """校验 LICENSE_BLOB + SERIAL，返回带 code 的判定结果。

    code 取值：NO_LICENSE / BAD_FORMAT / BAD_SIGNATURE / BAD_PAYLOAD /
              SERIAL_MISSING / SERIAL_MISMATCH / NOT_YET_VALID / EXPIRED / OK
    """
    moment = now or datetime.now(timezone.utc)
    if not blob or not str(blob).strip():
        return _free("NO_LICENSE", "未提供 LICENSE_BLOB，按免费模式运行")

    text = str(blob).strip()
    if text.count(".") != 1:
        return _free("BAD_FORMAT", "LICENSE_BLOB 格式错误：期望 <payload>.<signature>")
    payload_b64, signature = text.split(".", 1)
    if not payload_b64 or not signature:
        return _free("BAD_FORMAT", "LICENSE_BLOB 缺少 payload 或签名段")

    # [REAL-INTEGRATION] 正式版把下面两行换成公钥验签：
    #   ok = ed25519_verify(PUBLIC_KEY_PEM, payload_b64.encode("ascii"), b64u_decode(signature))
    expected_sig = sign_payload(payload_b64, secret)
    if not hmac.compare_digest(expected_sig, signature):
        return _free("BAD_SIGNATURE", "签名校验失败：LICENSE_BLOB 被篡改，或不是本产品签发的")

    try:
        payload = json.loads(b64u_decode(payload_b64).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return _free("BAD_PAYLOAD", "LICENSE_BLOB 解码失败")
    if not isinstance(payload, dict):
        return _free("BAD_PAYLOAD", "LICENSE_BLOB 内容不是 JSON 对象")

    blob_serial = str(payload.get("serial", "")).strip()
    given_serial = str(serial or "").strip()
    if not given_serial:
        return _free("SERIAL_MISSING", "缺少 SERIAL：授权文件必须与序列号一起使用")
    if given_serial.upper() != blob_serial.upper():
        return _free(
            "SERIAL_MISMATCH",
            "SERIAL 与授权文件不匹配（文件登记 {0}）".format(blob_serial or "空"),
        )

    # [REAL-INTEGRATION] 设备指纹绑定在这里：比对 payload["machine"] 与本机哈希
    issued_at = _parse_ts(payload.get("issued_at"))
    if issued_at and moment + timedelta(hours=24) < issued_at:
        return _free("NOT_YET_VALID", "授权尚未生效（生效时间 {0}）".format(payload.get("issued_at")))
    expires_at = _parse_ts(payload.get("expires_at"))
    if expires_at and moment > expires_at:
        return _free("EXPIRED", "授权已于 {0} 过期".format(payload.get("expires_at")))

    tier = str(payload.get("tier", "pro"))
    raw_features = payload.get("features")
    features = [str(f) for f in raw_features] if isinstance(raw_features, list) else TIER_FEATURES.get(tier, [])
    return LicenseResult(
        True,
        tier,
        blob_serial,
        payload.get("expires_at"),
        features,
        "OK",
        "授权有效：{0}，有效期至 {1}".format(tier, payload.get("expires_at") or "永久"),
        payload,
    )


def load_license_file(path: str) -> Tuple[Optional[str], Optional[str]]:
    """读取授权文件。支持纯 blob 文本，也支持 {"license_blob":..., "serial":...} JSON。"""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return None, None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return text, None
        if isinstance(data, dict):
            blob = data.get("license_blob") or data.get("LICENSE_BLOB") or data.get("blob")
            serial = data.get("serial") or data.get("SERIAL")
            return blob, serial
    return text, None


def default_demo_blob() -> str:
    """内置演示授权（10 年有效），用于 --demo 与可复现 demo。"""
    return issue_license(DEMO_SERIAL, tier="pro", days=3650)
