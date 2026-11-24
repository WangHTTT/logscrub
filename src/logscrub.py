# -*- coding: utf-8 -*-
"""logscrub 核心引擎：敏感数据识别 + 一致性令牌化 + 脱敏后复扫。

三条硬约束
----------
1. 全程本地运行：不联网、不上传，默认不落明文映射表。
2. 同一 salt 下，同一敏感值在任意文件里映射为同一令牌，脱敏后仍可做关联分析。
3. 每次脱敏立刻复扫输出，残留必须为 0，并把该数值写进审计报告。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

VERSION = "1.0.0"
DEFAULT_SALT = "logscrub-default-salt-v1"
FREE_MAX_FILES = 1
FREE_MAX_LINES = 2000
TEXT_SUFFIXES = (
    ".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson",
    ".yaml", ".yml", ".ini", ".conf", ".cfg", ".env", ".md", ".out", ".err", ".trace",
)

Rule = Tuple[str, Any, int, Any]


class UpgradeRequired(Exception):
    """免费模式触达 Pro 边界。"""


# ---------------------------------------------------------------- 识别规则

SECRET_RE = re.compile(
    r"""(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)(\s*[:=]\s*)[\"']?([^\s\"',;]{6,})"""
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
CN_ID_RE = re.compile(
    r"(?<!\d)([1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)"
)
BANK_RE = re.compile(r"(?<![\d.])\d{16,19}(?![\d.])")
MOBILE_RE = re.compile(r"(?<!\d)(1[3-9]\d{9})(?!\d)")
IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
# 本工具生成的令牌形如 [CN_MOBILE:1A2B3C4D5E6F]；复扫与重复脱敏都要跳过它
TOKEN_RE = re.compile(r"^\[[A-Z][A-Z0-9_]*:[0-9A-F]{12}\]$")

_CNID_W = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CNID_CHECK = "10X98765432"


def cn_id_checksum_ok(value: str) -> bool:
    v = value.strip().upper()
    if len(v) != 18:
        return False
    try:
        total = sum(int(v[i]) * _CNID_W[i] for i in range(17))
    except ValueError:
        return False
    return _CNID_CHECK[total % 11] == v[17]


def luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def bank_like(value: str) -> bool:
    """Luhn 通过，或卡组织常见首位（3/4/5/6）就按卡号处理。"""
    return luhn_ok(value) or value[:1] in "3456"


def ipv4_ok(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and int(part) <= 255 for part in parts)


def _builtin_rules() -> List[Rule]:
    # 顺序即优先级：同一区间被多条规则命中时，靠前者胜出（如身份证优先于卡号）
    return [
        ("SECRET", SECRET_RE, 3, None),
        ("JWT", JWT_RE, 0, None),
        ("EMAIL", EMAIL_RE, 0, None),
        ("CN_ID", CN_ID_RE, 1, None),
        ("BANK_CARD", BANK_RE, 0, bank_like),
        ("CN_MOBILE", MOBILE_RE, 1, None),
        ("IPV4", IPV4_RE, 1, ipv4_ok),
    ]


@dataclass
class Hit:
    start: int
    end: int
    kind: str
    value: str


def load_rules_file(path: str) -> List[Rule]:
    """加载自定义规则：{"rules":[{"kind":"ORDER_ID","pattern":"ORD\\d{11}"}]} 或直接数组。"""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw.get("rules") if isinstance(raw, dict) else raw
    if not isinstance(items, list) or not items:
        raise ValueError("规则文件需要非空的 rules 数组")
    rules: List[Rule] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("每条规则必须是对象：{kind, pattern}")
        kind = str(item.get("kind") or "").strip().upper()
        pattern = item.get("pattern")
        if not kind or not pattern:
            raise ValueError("每条规则需要 kind 与 pattern")
        try:
            compiled = re.compile(str(pattern))
        except re.error as exc:
            raise ValueError("规则 {0} 正则非法：{1}".format(kind, exc))
        rules.append((kind, compiled, 0, None))
    return rules


def find_hits(text: str, extra_rules: Optional[Sequence[Rule]] = None) -> List[Hit]:
    """按优先级取不重叠的命中区间。"""
    rules = _builtin_rules()
    if extra_rules:
        rules.extend(extra_rules)
    candidates: List[Tuple[int, int, str, str]] = []
    for kind, regex, group, validator in rules:
        for match in regex.finditer(text):
            start, end = match.span(group)
            if start < 0 or end <= start:
                continue
            value = match.group(group)
            if validator is not None and not validator(value):
                continue
            if TOKEN_RE.match(value):
                continue

            candidates.append((start, end, kind, value))
    candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    hits: List[Hit] = []
    last_end = -1
    for start, end, kind, value in candidates:
        if start < last_end:
            continue
        hits.append(Hit(start, end, kind, value))
        last_end = end
    return hits


class Tokenizer:
    """把敏感值映射成 [KIND:12位十六进制] 令牌；同 salt 同值必得同令牌。"""

    def __init__(self, salt: str = DEFAULT_SALT) -> None:
        if not salt:
            raise ValueError("salt 不能为空")
        self.salt = salt.encode("utf-8")
        self._cache: Dict[Tuple[str, str], str] = {}

    def token(self, kind: str, value: str) -> str:
        key = (kind, value)
        cached = self._cache.get(key)
        if cached is None:
            digest = hmac.new(self.salt, (kind + "|" + value).encode("utf-8"), hashlib.sha256).hexdigest()
            cached = "[{0}:{1}]".format(kind, digest[:12].upper())
            self._cache[key] = cached
        return cached

    def fingerprint(self) -> str:
        return hashlib.sha256(self.salt).hexdigest()[:8].upper()


def scrub_text(
    text: str,
    tokenizer: Tokenizer,
    extra_rules: Optional[Sequence[Rule]] = None,
) -> Tuple[str, Dict[str, int], int]:
    """返回（脱敏文本, 各类型替换数, 复扫残留数）。"""
    hits = find_hits(text, extra_rules)
    chunks: List[str] = []
    counts: Dict[str, int] = {}
    cursor = 0
    for hit in hits:
        chunks.append(text[cursor:hit.start])
        chunks.append(tokenizer.token(hit.kind, hit.value))
        cursor = hit.end
        counts[hit.kind] = counts.get(hit.kind, 0) + 1
    chunks.append(text[cursor:])
    masked = "".join(chunks)
    residual = len(find_hits(masked, extra_rules))
    return masked, counts, residual


def count_lines(path: Path) -> int:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def iter_files(root: Path) -> List[Path]:
    root = Path(root)
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    return [p for p in sorted(root.rglob("*")) if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES]


def run_scrub(
    src: Path,
    dst: Path,
    salt: str = DEFAULT_SALT,
    extra_rules: Optional[Sequence[Rule]] = None,
    dry_run: bool = False,
    is_pro: bool = False,
    rules_path: Optional[Path] = None,
    want_report: bool = False,
) -> Dict[str, Any]:
    src = Path(src)
    dst = Path(dst)
    if not src.exists():
        raise FileNotFoundError("输入路径不存在：{0}".format(src))
    files = iter_files(src)
    if not files:
        raise ValueError("输入路径下没有可处理的文本文件：{0}".format(src))

    if not is_pro:
        if len(files) > FREE_MAX_FILES:
            raise UpgradeRequired(
                "免费模式一次只处理 {0} 个文件（本次 {1} 个）；目录批量脱敏是 Pro 功能（--demo 或 --license 解锁）".format(
                    FREE_MAX_FILES, len(files)
                )
            )
        if rules_path is not None:
            raise UpgradeRequired("自定义规则文件是 Pro 功能（--rules）；免费模式仅内置 7 类识别")
        if want_report:
            raise UpgradeRequired("JSON 审计报告导出是 Pro 功能（--report）")
        total_lines = sum(count_lines(item) for item in files)
        if total_lines > FREE_MAX_LINES:
            raise UpgradeRequired(
                "免费模式单次上限 {0} 行（本次 {1} 行）；Pro 无行数限制".format(FREE_MAX_LINES, total_lines)
            )

    tokenizer = Tokenizer(salt)
    started = time.perf_counter()
    per_file: List[Dict[str, Any]] = []
    totals: Dict[str, int] = {}
    residual_total = 0

    for item in files:
        text = item.read_text(encoding="utf-8", errors="replace")
        masked, counts, residual = scrub_text(text, tokenizer, extra_rules)
        if src.is_file():
            out_path = dst if dst.suffix else dst / item.name
        else:
            out_path = dst / str(item.relative_to(src))
        if not dry_run:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(masked, encoding="utf-8")
        per_file.append(
            {
                "file": item.name if src.is_file() else str(item.relative_to(src)),
                "output": None if dry_run else str(out_path),
                "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
                "bytes_in": len(text.encode("utf-8")),
                "bytes_out": len(masked.encode("utf-8")),
                "hits": counts,
                "residual": residual,
            }
        )
        for kind, amount in counts.items():
            totals[kind] = totals.get(kind, 0) + amount
        residual_total += residual

    return {
        "tool": "logscrub",
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "pro" if is_pro else "free",
        "dry_run": dry_run,
        "salt_fingerprint": tokenizer.fingerprint(),
        "input": str(src),
        "output": None if dry_run else str(dst),
        "files": per_file,
        "totals": totals,
        "replaced": sum(totals.values()),
        "residual_after_rescan": residual_total,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }
