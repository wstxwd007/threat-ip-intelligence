"""Untrusted feed ingestion. External content is DATA, never executed."""
from __future__ import annotations
import ipaddress
from datetime import datetime, timezone
import json
import re
import ssl
import urllib.parse
import urllib.request
from pathlib import Path

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_ROWS = 300_000

class FeedError(ValueError):
    pass


def fetch_source(source: dict, base: Path) -> bytes:
    if "file" in source:
        file = (base / source["file"]).resolve()
        # prevent config with a path outside the repository
        if not file.is_relative_to(base.resolve()):
            raise FeedError("source file path escapes project root")
        if file.stat().st_size > MAX_SOURCE_BYTES:
            raise FeedError("source file too large")
        return file.read_bytes()
    url = source.get("url", "")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise FeedError("feed URL must be HTTPS without embedded credentials")
    request = urllib.request.Request(url, headers={"User-Agent": "threat-ip-intelligence/0.1", "Accept": "application/json,text/plain"})
    with urllib.request.urlopen(request, timeout=25, context=ssl.create_default_context()) as resp:
        final = urllib.parse.urlsplit(resp.geturl())
        if final.scheme != "https" or final.hostname != parsed.hostname:
            raise FeedError("cross-host redirect blocked")
        data = resp.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise FeedError("source response too large")
    return data


def normalize_ip(value: str, allow_ipv6: bool = False) -> str:
    value = value.strip()
    if not value or len(value) > 48 or not re.fullmatch(r"[0-9a-fA-F.:/]+", value):
        raise FeedError(f"invalid IP/CIDR token: {value[:60]!r}")
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as ex:
        raise FeedError(f"invalid IP/CIDR: {value!r}") from ex
    if net.version == 6 and not allow_ipv6:
        raise FeedError("IPv6 not supported by IPv4 RAW publisher")
    # Reject special, private, documentation, default routes and non-global ranges.
    if not net.is_global:
        raise FeedError(f"non-global IP/CIDR: {net}")
    if net.version == 4 and net.prefixlen < 8:
        raise FeedError(f"overbroad subnet: {net}")
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def extract_candidates(data: bytes, fmt: str) -> list[str]:
    try:
        text = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as ex:
        raise FeedError("invalid UTF-8 feed") from ex
    if fmt == "spamhaus_json":
        try:
            parsed = json.loads(text)
            records = parsed if isinstance(parsed, list) else parsed["data"]
            if not isinstance(records, list):
                raise TypeError()
            result = [r["cidr"] for r in records if isinstance(r, dict) and isinstance(r.get("cidr"), str)]
        except (ValueError, KeyError, TypeError) as ex:
            raise FeedError("invalid Spamhaus JSON feed") from ex
    elif fmt == "plain":
        result = [line.split("#", 1)[0].strip() for line in text.splitlines()]
        result = [item for item in result if item]
    elif fmt == "ros6_rsc":
        # Optional compatibility input: interpret data-only address additions.
        # Never pass RSC to RouterOS /import; never run arbitrary RouterOS commands.
        result = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")) or line in ("/ip firewall address-list", "/ip/firewall/address-list"):
                continue
            if not line.startswith("add "):
                raise FeedError("unsupported RouterOS script directive; abort whole source")
            matches = re.findall(r'(?:^|\s)(address|list)=([^\s";]+)', line)
            attrs = dict(matches)
            if attrs.get("list") != "scaners" or "address" not in attrs:
                raise FeedError("RSC entry missing list=scaners or address")
            # Forbid command substitutions, line continuations, and separators even in ignored fields.
            if any(x in line for x in ("[", "]", "$", "\\", ";", "\r")):
                raise FeedError("unsafe or unsupported RSC syntax")
            result.append(attrs["address"])
    else:
        raise FeedError(f"unknown feed format {fmt!r}")
    if len(result) > MAX_SOURCE_ROWS:
        raise FeedError("too many source entries")
    return result


def validate_freshness(data: bytes, source: dict) -> None:
    """Optional header timestamp gate, currently supported for Feodo text feeds."""
    days = source.get("max_age_days")
    if days is None:
        return
    if source.get("format") != "plain":
        raise FeedError("freshness gate unsupported for this format")
    header = data[:4096].decode("utf-8", errors="replace")
    m = re.search(r"(?im)^#\s*Last updated:\s*(\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d)\s+UTC", header)
    if not m:
        raise FeedError("feed timestamp not found; refusing potentially stale feed")
    dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    if age < -1 or age > float(days):
        raise FeedError(f"feed freshness gate: age={age:.1f}d > max_age_days={days}")


def parse_source(data: bytes, fmt: str, allow_empty: bool = False) -> tuple[list[str], dict]:
    candidates = extract_candidates(data, fmt)
    addresses = set()
    rejects = 0
    for value in candidates:
        try:
            addresses.add(normalize_ip(value))
        except FeedError:
            rejects += 1
    if not candidates and not allow_empty:
        raise FeedError("feed unexpectedly empty")
    # Any malformed entries in strict feeds indicate broken parsing or upstream changes.
    if rejects and (rejects > 10 or rejects / max(len(candidates), 1) > 0.01):
        raise FeedError(f"feed has excessive invalid IP entries: {rejects}/{len(candidates)}")
    return sorted(addresses, key=ip_sort), {"raw_count": len(candidates), "valid_count": len(addresses), "rejected_count": rejects}


def ip_sort(s: str):
    n = ipaddress.ip_network(s, strict=False)
    return (n.version, int(n.network_address), n.prefixlen)
