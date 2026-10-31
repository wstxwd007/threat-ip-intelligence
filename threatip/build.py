"""Generate deterministic, integrity-checked, public IPv4 releases."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import ipaddress
import json
import os
import tempfile
from .feeds import FeedError, fetch_source, parse_source, ip_sort, validate_freshness


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(config_path: Path, outdir: Path) -> dict:
    config_path = config_path.resolve()
    root = config_path.parent.parent
    config = json.loads(config_path.read_text(encoding="utf-8"))
    sources = [s for s in config["sources"] if s.get("enabled", False)]
    if not sources:
        raise FeedError("no enabled sources; refusing empty release")
    all_addresses = set()
    metadata = []
    for source in sources:
        data = fetch_source(source, root)
        validate_freshness(data, source)
        addresses, stats = parse_source(data, source["format"], allow_empty=source.get("allow_empty", False))
        if not addresses and not source.get("allow_empty", False):
            raise FeedError(f"empty source: {source['name']}")
        all_addresses.update(addresses)
        metadata.append({"name": source["name"], "homepage": source.get("homepage", ""),
                         "attribution": source.get("attribution", ""), "license": source.get("license", "unknown"),
                         "sha256_source": sha256(data), **stats})
    if not all_addresses:
        raise FeedError("merged feed is empty; keep previous release")
    max_entries = int(config.get("max_entries", 150_000))
    if len(all_addresses) > max_entries:
        raise FeedError("overlarge merged set; manual review needed")
    # No subnet expansion: never summarize unrelated /32 records to large CIDRs.
    lines = sorted(all_addresses, key=ip_sort)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    header = ["# Threat IP Intelligence IPv4 v1", "# Data generated at: " + generated_at]
    for source in metadata:
        # Attribution stays with the actual IP file, not only the manifest.
        credit = (source["attribution"] or source["name"]).replace("\n", " ").replace("\r", " ")
        header.append("# Source credit: " + credit)
    header.append("# Details, rights and source hashes: manifest.json")
    text = "\n".join(header) + "\n" + "\n".join(lines) + "\n"
    content = text.encode("utf-8")
    manifest = {"schema": 1, "project": "threat-ip-intelligence", "generated_at": generated_at,
                "ipv4_file": "ipv4.txt", "ipv4_count": len(lines), "ipv4_sha256": sha256(content),
                "sources": metadata, "policy": "exact-set-no-expansion; private/special ranges excluded"}
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    sums = (f"{sha256(content)}  ipv4.txt\n{sha256(manifest_bytes)}  manifest.json\n").encode("ascii")
    outdir.mkdir(parents=True, exist_ok=True)
    # All inputs have been validated before writing; individual files use atomic replaces.
    for filename, payload in (("ipv4.txt", content), ("manifest.json", manifest_bytes), ("SHA256SUMS", sums)):
        fd, temp = tempfile.mkstemp(prefix=".tipi-", dir=outdir)
        try:
            with os.fdopen(fd, "wb") as fp:
                fp.write(payload)
                fp.flush()
                os.fsync(fp.fileno())
            os.replace(temp, outdir / filename)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    return manifest


def main():
    p = argparse.ArgumentParser(description="采集并发布高风险 IP 名单")
    p.add_argument("--config", default="config/sources.json")
    p.add_argument("--out", default="dist")
    args = p.parse_args()
    try:
        result = build(Path(args.config), Path(args.out))
        print(json.dumps({"status": "OK", "ipv4_count": result["ipv4_count"], "sources": [s["name"] for s in result["sources"]]}, ensure_ascii=False))
    except (FeedError, OSError, ValueError, KeyError) as ex:
        p.exit(1, f"BUILD FAILED (old release unchanged): {ex}\n")

if __name__ == "__main__":
    main()
