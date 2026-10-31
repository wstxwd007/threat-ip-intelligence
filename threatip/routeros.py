"""Conservative RouterOS 7 REST updater. Existing non-owned entries are immutable."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from .feeds import FeedError, normalize_ip, ip_sort

OWNER = "TIPI/v1"
MAX_DOWNLOAD = 64 * 1024 * 1024
LIST_NAME = "scaners"


def get_https(url: str, max_bytes: int = MAX_DOWNLOAD, ca_file: str | None = None) -> bytes:
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.fragment:
        raise FeedError("HTTPS URL without credentials/fragment required")
    ctx = ssl.create_default_context(cafile=ca_file)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "TIPI-RouterOS/0.1"}), context=ctx, timeout=25) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.netloc != p.netloc:
            raise FeedError("unsafe redirect")
        content = response.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise FeedError("download too large")
    return content


def load_signed_by_hash_manifest(manifest_url: str) -> tuple[list[str], dict]:
    """SHA-256 protects against accidental corruption; it is NOT a signature."""
    manifest_bytes = get_https(manifest_url, 256 * 1024)
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != 1 or manifest.get("project") != "threat-ip-intelligence":
        raise FeedError("wrong manifest schema/project")
    if manifest.get("ipv4_file") != "ipv4.txt":
        raise FeedError("unsafe list filename")
    p = urllib.parse.urlsplit(manifest_url)
    list_url = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path.rsplit("/", 1)[0] + "/ipv4.txt", "", ""))
    payload = get_https(list_url)
    if hashlib.sha256(payload).hexdigest() != manifest.get("ipv4_sha256"):
        raise FeedError("SHA-256 mismatch: refusing release")
    try:
        content = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as ex:
        raise FeedError("non UTF-8 release") from ex
    seen: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = normalize_ip(line)
        if token != line:
            raise FeedError("noncanonical release entry")
        if token in seen:
            raise FeedError("duplicate release entry")
        seen.add(token)
    if not seen or len(seen) != manifest.get("ipv4_count"):
        raise FeedError("release count mismatch or empty")
    return sorted(seen, key=ip_sort), manifest


class RouterREST:
    def __init__(self, base_url: str, username: str, password: str, ca_file: str | None):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise FeedError("router URL must be HTTPS origin, no path")
        if not username or not password:
            raise FeedError("RouterOS credentials missing")
        self.url = base_url.rstrip("/") + "/rest/"
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.ctx = ssl.create_default_context(cafile=ca_file)

    def request(self, method: str, endpoint: str, payload: dict | None = None, params: dict | None = None):
        url = self.url + endpoint.lstrip("/")
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(url, data=data, method=method,
            headers={"Authorization": self.auth, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=25, context=self.ctx) as resp:
                raw = resp.read(MAX_DOWNLOAD + 1)
                if len(raw) > MAX_DOWNLOAD:
                    raise FeedError("RouterOS response too large")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as ex:
            # No credentials/Authorization headers are logged.
            raise FeedError(f"RouterOS REST HTTP {ex.code}, endpoint={endpoint}") from ex

    def raw_verified(self) -> bool:
        rules = self.request("GET", "ip/firewall/raw", params={"chain": "prerouting", "action": "drop", "src-address-list": LIST_NAME, ".proplist": "chain,action,src-address-list,disabled"})
        return any(r.get("disabled") not in ("true", "yes") for r in rules)

    def list_entries(self) -> list[dict]:
        entries = self.request("GET", "ip/firewall/address-list", params={"list": LIST_NAME, ".proplist": ".id,address,list,comment,dynamic,disabled"})
        if not isinstance(entries, list):
            raise FeedError("address-list API returned non-list")
        return entries

    def add(self, address: str) -> str:
        result = self.request("PUT", "ip/firewall/address-list", {"address": address, "list": LIST_NAME, "comment": OWNER})
        if not isinstance(result, dict) or not isinstance(result.get(".id"), str):
            raise FeedError("missing RouterOS new entry ID")
        return result[".id"]

    def remove(self, ros_id: str):
        if not ros_id.startswith("*") or not all(x in "0123456789ABCDEFabcdef" for x in ros_id[1:]):
            raise FeedError("unsafe RouterOS record ID")
        self.request("DELETE", "ip/firewall/address-list/" + ros_id)


@dataclass
class Diff:
    additions: list[str]
    removals: list[tuple[str, str]]
    kept_external: int
    kept_managed: int


def plan_diff(target: list[str], existing: list[dict]) -> Diff:
    target_set = set(target)
    present: set[str] = set()
    owned: list[tuple[str, str]] = []
    external = 0
    for e in existing:
        if e.get("list") != LIST_NAME or e.get("disabled") in ("true", "yes"):
            continue
        try:
            ip = normalize_ip(e["address"])
        except (FeedError, KeyError):
            if e.get("comment", "") == OWNER:
                raise FeedError("managed RouterOS entry is invalid; inspect manually")
            external += 1  # preserve unrelated/non-global entries exactly as they are
            continue
        present.add(ip)
        if e.get("comment", "") == OWNER:
            if e.get("dynamic") in ("true", "yes"):
                raise FeedError("unexpected dynamic managed entry")
            owned.append((e[".id"], ip))
        else:
            external += 1
    additions = sorted(target_set - present, key=ip_sort)
    removals = [(ros_id, ip) for ros_id, ip in owned if ip not in target_set]
    return Diff(additions, removals, external, len(owned) - len(removals))


def safety_check(diff: Diff, managed_total: int, max_adds: int, max_removes: int, max_remove_ratio: float) -> None:
    if len(diff.additions) > max_adds:
        raise FeedError(f"{len(diff.additions)} additions exceed guard {max_adds}; manual approval")
    if len(diff.removals) > max_removes:
        raise FeedError(f"{len(diff.removals)} removals exceed guard {max_removes}; manual approval")
    if managed_total and len(diff.removals) / managed_total > max_remove_ratio:
        raise FeedError("too many managed entries removed in one run")


def apply_diff(client: RouterREST, diff: Diff, target: list[str]):
    created: list[tuple[str, str]] = []
    deleted: list[str] = []
    try:
        # Add first, remove only our own entries; external ros6 entries are untouched.
        for ip in diff.additions:
            created.append((client.add(ip), ip))
        for ros_id, ip in diff.removals:
            client.remove(ros_id)
            deleted.append(ip)
        result = client.list_entries()
        present = set()
        for e in result:
            if e.get("disabled") in ("true", "yes"):
                continue
            try:
                present.add(normalize_ip(e["address"]))
            except (FeedError, KeyError):
                if e.get("comment", "") == OWNER:
                    raise
        if not set(target).issubset(present):
            raise FeedError("post-apply verification failed")
    except Exception:
        # Best-effort compensation: if router/network fails, manual reconciliation is required.
        for ip in deleted:
            try:
                client.add(ip)
            except Exception as ex:
                print(f"ROLLBACK WARN restore {ip}: {type(ex).__name__}", file=sys.stderr)
        for ros_id, _ in reversed(created):
            try:
                client.remove(ros_id)
            except Exception as ex:
                print(f"ROLLBACK WARN remove newly-added entry: {type(ex).__name__}", file=sys.stderr)
        raise


def main():
    p = argparse.ArgumentParser(description="RouterOS 7 安全增量更新 scaners（默认预演）")
    p.add_argument("--manifest-url", required=True, help="https://.../dist/manifest.json")
    p.add_argument("--router-url", default=os.getenv("TIPI_ROS_URL", ""))
    p.add_argument("--ca-file", default=os.getenv("TIPI_ROS_CA"))
    p.add_argument("--apply", action="store_true", help="显式授权执行写操作")
    p.add_argument("--confirm", default="", help="写入时必须为 scaners")
    p.add_argument("--max-adds", type=int, default=2000)
    p.add_argument("--max-removes", type=int, default=300)
    p.add_argument("--max-remove-ratio", type=float, default=0.10)
    args = p.parse_args()
    try:
        if args.apply and args.confirm != LIST_NAME:
            raise FeedError("--apply requires --confirm scaners")
        if not (0 <= args.max_remove_ratio <= 1) or args.max_adds < 0 or args.max_removes < 0:
            raise FeedError("invalid guardrail value")
        wanted, manifest = load_signed_by_hash_manifest(args.manifest_url)
        client = RouterREST(args.router_url, os.getenv("TIPI_ROS_USER", ""), os.getenv("TIPI_ROS_PASSWORD", ""), args.ca_file)
        if not client.raw_verified():
            raise FeedError("expected enabled RAW prerouting drop src-address-list=scaners not found")
        existing = client.list_entries()
        diff = plan_diff(wanted, existing)
        managed_count = diff.kept_managed + len(diff.removals)
        safety_check(diff, managed_count, args.max_adds, args.max_removes, args.max_remove_ratio)
        info = {"mode": "APPLY" if args.apply else "DRY-RUN", "release_count": len(wanted),
                "current_entries": len(existing), "external_entries_preserved": diff.kept_external,
                "to_add": len(diff.additions), "to_remove_owned_only": len(diff.removals),
                "sample_additions": diff.additions[:5], "sample_removals": [ip for _, ip in diff.removals[:5]],
                "release_generated_at": manifest["generated_at"]}
        print(json.dumps(info, indent=2, ensure_ascii=False))
        if args.apply:
            apply_diff(client, diff, wanted)
            print("APPLY VERIFIED: existing RAW and non-owned scaners entries left unchanged")
        else:
            print("NO WRITE: run --apply --confirm scaners only after reviewing plan")
    except (FeedError, OSError, ValueError, KeyError, urllib.error.URLError) as ex:
        p.exit(1, f"SAFE STOP: {type(ex).__name__}: {ex}\n")

if __name__ == "__main__":
    main()
