"""Read-only ros6 vs published Spamhaus analysis.

Never imports RSC into RouterOS; never writes IP-level data or posts to a router.
Public report contains counts/hashes only, not ros6 addresses or subnets.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile

from .feeds import FeedError, fetch_source, parse_source


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ranges(addresses: list[str]) -> list[tuple[int, int]]:
    ranges = []
    for value in addresses:
        net = ipaddress.ip_network(value, strict=True)
        if net.version != 4:
            raise FeedError("IPv6 is not supported in this IPv4 audit")
        ranges.append((int(net.network_address), int(net.broadcast_address)))
    ranges.sort()
    return ranges


def _union(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for first, last in ranges:
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], last)
        else:
            merged.append([first, last])
    return [(a, b) for a, b in merged]


def _size(ranges: list[tuple[int, int]]) -> int:
    return sum(b - a + 1 for a, b in ranges)


def _intersection_size(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> int:
    i = j = total = 0
    while i < len(a) and j < len(b):
        x, y = a[i]
        u, v = b[j]
        total += max(0, min(y, v) - max(x, u) + 1)
        if y <= v:
            i += 1
        else:
            j += 1
    return total


def _count_covered(source: list[tuple[int, int]], covering: list[tuple[int, int]]) -> int:
    starts = [s for s, _ in covering]
    count = 0
    for first, last in source:
        i = bisect_right(starts, first) - 1
        if i >= 0 and covering[i][1] >= last:
            count += 1
    return count


def compare_feeds(ros6: list[str], spamhaus: list[str]) -> dict:
    """Numbers describe IPv4 set theory, never guessed /24 expansion."""
    a_set, b_set = set(ros6), set(spamhaus)
    a = _ranges(list(a_set))
    b = _ranges(list(b_set))
    au, bu = _union(a), _union(b)
    intersection = _intersection_size(au, bu)
    a_count, b_count = _size(au), _size(bu)
    total = a_count + b_count - intersection
    return {
        "ros6_entry_count": len(a_set),
        "spamhaus_entry_count": len(b_set),
        "exact_same_entries": len(a_set & b_set),
        "ros6_entries_fully_covered_by_spamhaus": _count_covered(a, bu),
        "spamhaus_entries_fully_covered_by_ros6": _count_covered(b, au),
        "ros6_ipv4_addresses_covered": a_count,
        "spamhaus_ipv4_addresses_covered": b_count,
        "overlap_ipv4_addresses": intersection,
        "combined_unique_ipv4_addresses": total,
        "additional_ipv4_addresses_from_ros6": a_count - intersection,
        "additional_ipv4_addresses_from_spamhaus": b_count - intersection,
        "ros6_single_ip_entries": sum(ipaddress.ip_network(x).prefixlen == 32 for x in a_set),
        "ros6_cidr_entries": sum(ipaddress.ip_network(x).prefixlen != 32 for x in a_set),
        "spamhaus_single_ip_entries": sum(ipaddress.ip_network(x).prefixlen == 32 for x in b_set),
        "spamhaus_cidr_entries": sum(ipaddress.ip_network(x).prefixlen != 32 for x in b_set),
    }


def _published_spamhaus(dist: Path, max_age_hours: float, now: datetime) -> tuple[list[str], dict]:
    manifest_path, feed_path = dist / "manifest.json", dist / "ipv4.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise FeedError("unexpected published manifest schema")
    # The published feed may contain more sources in a future version. Do not
    # silently attribute a multi-source aggregate to Spamhaus.
    if [x.get("name") for x in manifest.get("sources", [])] != ["Spamhaus DROP IPv4"]:
        raise FeedError("published feed is not Spamhaus-only; audit needs an isolated source")
    when = datetime.fromisoformat(manifest["generated_at"])
    if when.tzinfo is None:
        raise FeedError("published manifest timestamp has no timezone")
    age_hours = (now - when).total_seconds() / 3600
    if age_hours < -0.25 or age_hours > max_age_hours:
        raise FeedError(f"published Spamhaus feed too old/new: age_hours={age_hours:.1f}")
    content = feed_path.read_bytes()
    if sha256(content) != manifest.get("ipv4_sha256"):
        raise FeedError("published Spamhaus SHA-256 mismatch")
    entries, stats = parse_source(content, "plain")
    if len(entries) != manifest.get("ipv4_count") or stats["rejected_count"]:
        raise FeedError("published Spamhaus record count/format mismatch")
    return entries, manifest


def _write_atomic(path: Path, payload: bytes) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".tipi-audit-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as writer:
            writer.write(payload)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def render_markdown(report: dict) -> str:
    m = report["comparison"]
    def fmt(v: int) -> str:
        return f"{v:,}"
    rows = [
        ("ros6 有效条目", m["ros6_entry_count"]),
        ("Spamhaus 有效条目", m["spamhaus_entry_count"]),
        ("完全相同的 IP/CIDR 条目", m["exact_same_entries"]),
        ("ros6 中被 Spamhaus 完整覆盖的条目", m["ros6_entries_fully_covered_by_spamhaus"]),
        ("Spamhaus 中被 ros6 完整覆盖的条目", m["spamhaus_entries_fully_covered_by_ros6"]),
        ("ros6 覆盖的去重 IPv4 地址", m["ros6_ipv4_addresses_covered"]),
        ("Spamhaus 覆盖的去重 IPv4 地址", m["spamhaus_ipv4_addresses_covered"]),
        ("两者覆盖的重叠 IPv4 地址", m["overlap_ipv4_addresses"]),
        ("合并后覆盖的去重 IPv4 地址", m["combined_unique_ipv4_addresses"]),
        ("ros6 在 Spamhaus 之外增加的 IPv4 地址", m["additional_ipv4_addresses_from_ros6"]),
        ("Spamhaus 在 ros6 之外增加的 IPv4 地址", m["additional_ipv4_addresses_from_spamhaus"]),
    ]
    table = "\n".join(f"| {name} | {fmt(value)} |" for name, value in rows)
    return ("# ros6 × Spamhaus 只读覆盖率审计\n\n"
            f"- 生成时间（UTC）：`{report['generated_at']}`\n"
            f"- ros6 数据 SHA-256：`{report['inputs']['ros6_sha256']}`\n"
            f"- Spamhaus 发布提交时间：`{report['inputs']['spamhaus_published_at']}`\n"
            "- 公开报告仅包含汇总统计和哈希，不包含 ros6 的 IP/CIDR 明细。\n"
            "- 与 RB5009 现有 `scaners` 列表的覆盖率不是一回事；本报告只比较两份来源文件。\n\n"
            "| 指标 | 数量 |\n|---|---:|\n" + table + "\n\n"
            "**安全边界：** 未执行 `.rsc`，未生成 ros6 合并名单，未向 RouterOS 写入任何配置。\n")


def audit(config_path: Path, published_dist: Path, outdir: Path,
          ros6_file: Path | None = None, now: datetime | None = None) -> dict:
    config_path = config_path.resolve()
    root = config_path.parent.parent
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("format") != "ros6_npf_plain":
        raise FeedError("ros6 audit source must use the non-executable ros6_npf_plain parser")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise FeedError("audit clock must be timezone-aware")
    max_age_hours = float(config.get("max_spamhaus_age_hours", 72))
    if max_age_hours <= 0 or max_age_hours > 168:
        raise FeedError("invalid maximum Spamhaus feed age")
    ros6_source = {"url": config["url"]}
    # Optional local file path is restricted to read-only CLI usage; never
    # checked into the public repository. The default URL is from config.
    if ros6_file is not None:
        payload = ros6_file.read_bytes()
        if len(payload) > 16 * 1024 * 1024:
            raise FeedError("local ros6 file too large")
    else:
        payload = fetch_source(ros6_source, root)
    ros6, stats = parse_source(payload, "ros6_npf_plain")
    if stats["rejected_count"]:
        raise FeedError("ros6 contains invalid IPv4/CIDR: no partial audit")
    lower = int(config.get("min_ros6_entries", 1000))
    upper = int(config.get("max_ros6_entries", 100000))
    if lower < 1 or upper < lower or not lower <= len(ros6) <= upper:
        raise FeedError(f"ros6 entry count outside safety bounds ({len(ros6)})")
    spamhaus, manifest = _published_spamhaus(published_dist, max_age_hours, now)
    comparison = compare_feeds(ros6, spamhaus)
    report = {
        "schema": 1, "project": "threat-ip-intelligence", "version": "0.1.3",
        "mode": "AUDIT_ONLY_NO_PUBLIC_ROS6_IPS", "generated_at": now.isoformat(timespec="seconds"),
        "inputs": {
            "ros6_source": "ros6.com scaners.netbsd",
            "ros6_sha256": sha256(payload),
            "ros6_raw_count": stats["raw_count"],
            "ros6_duplicate_rows": stats["raw_count"] - len(ros6),
            "ros6_rejected_count": stats["rejected_count"],
            "spamhaus_published_at": manifest["generated_at"],
            "spamhaus_ipv4_sha256": manifest["ipv4_sha256"],
        }, "comparison": comparison,
        "notes": ["counts represent IP/CIDR entries, coverage is unique IPv4 addresses",
                  "no ros6 raw IPs or merged IP feed published",
                  "does not represent current RB5009 address-list without a separate export"],
    }
    json_data = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    md_data = render_markdown(report).encode("utf-8")
    outdir.mkdir(parents=True, exist_ok=True)
    _write_atomic(outdir / "ros6-latest.json", json_data)
    _write_atomic(outdir / "ros6-latest.md", md_data)
    return report


def main() -> None:
    p = argparse.ArgumentParser(description="只读审计 ros6 NetBSD 纯地址表与已发布 Spamhaus 交集，不公开 ros6 原始地址")
    p.add_argument("--config", default="config/ros6-audit.json")
    p.add_argument("--dist", default="dist")
    p.add_argument("--out", default="reports")
    p.add_argument("--ros6-file", help="可选本地 RSC 文件，绝不要提交到公开仓库")
    args = p.parse_args()
    try:
        report = audit(Path(args.config), Path(args.dist), Path(args.out),
                       Path(args.ros6_file) if args.ros6_file else None)
        print(json.dumps({"result": "AUDIT_PASS", "comparison": report["comparison"]}, ensure_ascii=False))
    except (FeedError, OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as e:
        p.exit(1, f"AUDIT FAILED (previous public report retained): {type(e).__name__}: {e}\n")

if __name__ == "__main__":
    main()
