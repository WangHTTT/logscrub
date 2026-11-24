# logscrub

**Scrub PII out of production logs — locally, in 30 seconds, without breaking your support workflow.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)]() [![Deps](https://img.shields.io/badge/dependencies-zero-brightgreen)]() [![Network](https://img.shields.io/badge/network-none-lightgrey)]()

> 中文简介：把带手机号、身份证、银行卡的生产日志，30 秒本地脱敏。同一个用户跨文件变成同一个令牌，客户还能追案，但永远不知道他是谁。零依赖、零上传、源码可审。

---

## The problem

Your client files a bug. You send them a production log. That log has phone numbers, national IDs, bank cards, and live JWTs in it.

Regex replacement "works" until you realize your client can no longer trace anything: every 11-digit number is now `***`, including order IDs.

## What logscrub does

```bash
$ logscrub scrub --in prod.log --out clean/
mode: pro    files: 3    lines: 9
replaced: 13  [BANK_CARD=1 CN_ID=2 CN_MOBILE=3 EMAIL=1 IPV4=3 JWT=1 SECRET=2]
residual after rescan: 0   (must be 0 to pass)
elapsed: 11.52 ms
```

**In:**
```text
2024-05-11T09:12:04Z pay card=6222020200112233445 from 203.0.113.7 uid=110105199003071234
```

**Out:**
```text
2024-05-11T09:12:04Z pay card=[BANK_CARD:9214176C3C01] from [IPV4:86DEBFE907A8] uid=[CN_ID:E1507A684B47]
```

The same `uid` becomes the **same token** in every file. Your client can still trace a user's journey. They just can't identify the user.

## Why not a regex

| | Regex | logscrub |
|---|---|---|
| Same value → same token across files | ✗ | ✓ |
| Values scrubbed, keys kept | ✗ | ✓ (`password=[SECRET:...]`) |
| Post-run audit (residual must be 0) | ✗ | ✓ |
| Idempotent (safe to re-run) | ✗ | ✓ |
| Won't nuke order IDs | ✗ | ✓ (validated patterns only) |

## Detects

Phone · National ID · Bank card · Email · Passwords & API keys · JWT · IPv4

Pro adds custom rules for your own order IDs, ticket IDs, internal codes.

## Quickstart

```bash
git clone https://github.com/YOURNAME/logscrub
cd logscrub/src

# free tier: single file, up to 2000 lines
python cli.py scrub --in sample.log --out out/

# full self-check (19 assertions: features + license positive/negative cases)
python demo.py
```

Python 3.9+. No pip install. No network. Windows / macOS / Linux.

## Privacy

100% local. Zero dependencies. Zero network calls. No telemetry. Pure standard library. Source auditable — that's the point of this repo.

## Pricing

| Plan | Price | Includes |
|---|---|---|
| Free | $0 | 1 file, ≤2000 lines, 7 built-in types |
| Personal Pro | $19 / year | Batch, custom rules, audit report |
| Lifetime | $59 | Everything, forever, 1 year of updates |

**Buy (China, ¥129 lifetime):** https://ifdian.net/item/343fa9b6e7d811f1b03e52540025c377

Built by [零号工坊 / Zero Workshop](https://ifdian.net/a/zeroworkshop) — a one-person studio shipping small tools that solve annoying, expensive problems.

## License

Source-available. Free for personal and non-commercial use. Commercial use requires a license — see [LICENSE](LICENSE).
