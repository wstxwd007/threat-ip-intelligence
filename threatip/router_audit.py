"""PRIVATE read-only three-way audit of RouterOS scaners, ros6 and Spamhaus.

Only GET requests to RouterOS; no public workflows invoke this module.
Private detailed output is confined to an ignored local/ directory.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from .audit import _ranges, _union, _size, _intersection_size, compare_feeds, _published_spamhaus
from .feeds import FeedError, fetch_source, normalize_ip, parse_source, ip_sort
from .routeros import RouterREST, LIST_NAME

MAX_ROUTER_ROWS = 150_000
MAX_WATCHLIST = 256


def parse_router_entries(rows: object) -> tuple[list[str], dict]:
    if not isinstance(rows, list) or len(rows) > MAX_ROUTER_ROWS:
        raise FeedError('RouterOS response not a bounded JSON array')
    parsed: set[str] = set()
    ignored_other_list = ignored_disabled = ignored_invalid = ignored_duplicate = 0
    for row in rows:
        if not isinstance(row, dict):
            raise FeedError('RouterOS entry is not an object')
        if row.get('list') != LIST_NAME:
            ignored_other_list += 1
            continue
        if row.get('disabled') in ('true', 'yes', True):
            ignored_disabled += 1
            continue
        try:
            value = normalize_ip(row['address'])
        except (FeedError, KeyError, TypeError):
            ignored_invalid += 1
            continue
        if value in parsed:
            ignored_duplicate += 1
        parsed.add(value)
    if not parsed:
        raise FeedError('RouterOS scaners has no valid enabled global IPv4 entries')
    return sorted(parsed, key=ip_sort), {
        'router_returned_rows': len(rows), 'router_valid_unique_entries': len(parsed),
        'ignored_other_lists': ignored_other_list, 'ignored_disabled': ignored_disabled,
        'ignored_invalid_or_private': ignored_invalid, 'ignored_duplicate': ignored_duplicate,
    }


def _coverage(left: list[str], right: list[str]) -> int:
    return _intersection_size(_union(_ranges(left)), _union(_ranges(right)))


def _contains(ip: str, intervals: list[tuple[int, int]]) -> bool:
    # Input watchlist bounded to 256 rows; bisect avoids per-IP CIDR expansion.
    from bisect import bisect_right
    start = [x for x, _ in intervals]
    needle = int(ipaddress.ip_address(ip))
    pos = bisect_right(start, needle) - 1
    return pos >= 0 and intervals[pos][1] >= needle


def read_watchlist(path: Path | None) -> list[str]:
    if path is None:
        return []
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict) or set(obj) != {'addresses'} or not isinstance(obj['addresses'], list):
        raise FeedError('watchlist schema requires only {"addresses": [...]}')
    if len(obj['addresses']) > MAX_WATCHLIST:
        raise FeedError('watchlist exceeds safety limit')
    values: list[str] = []
    for raw in obj['addresses']:
        if not isinstance(raw, str):
            raise FeedError('watchlist entries must be literal IPv4 strings')
        if '/' in raw:
            raise FeedError('watchlist accepts only literal host IPs, not CIDR')
        ip = normalize_ip(raw)
        if '/' in ip:  # defense in depth
            raise FeedError('watchlist accepts only single IPv4 addresses')
        values.append(ip)
    if len(values) != len(set(values)):
        raise FeedError('watchlist contains duplicate IPs')
    return values


def three_way(router: list[str], ros6: list[str], spamhaus: list[str], watchlist: list[str]) -> dict:
    r, a, b = _union(_ranges(router)), _union(_ranges(ros6)), _union(_ranges(spamhaus))
    rb = _union(_ranges(ros6 + spamhaus))
    rc = _size(r)
    ac = _size(a)
    bc = _size(b)
    r_a = _intersection_size(r, a)
    r_b = _intersection_size(r, b)
    r_both = _intersection_size(r, _union(_range_intersection(a,b)))
    safe_watch = []
    for ip in watchlist:
        sources = [name for name, source in (('router',r),('ros6',a),('spamhaus',b)) if _contains(ip, source)]
        safe_watch.append({'ip': ip, 'blocked_by': sources})
    return {
        'router_unique_entries': len(router), 'ros6_unique_entries': len(ros6), 'spamhaus_unique_entries': len(spamhaus),
        'router_unique_ipv4': rc, 'ros6_unique_ipv4': ac, 'spamhaus_unique_ipv4': bc,
        'router_coverage_in_ros6': r_a, 'router_coverage_in_spamhaus': r_b,
        'router_coverage_in_both': r_both,
        'ros6_addresses_not_covered_by_router': ac - r_a,
        'spamhaus_addresses_not_covered_by_router': bc - r_b,
        'router_addresses_outside_both_sources': rc - _intersection_size(r, rb),
        'router_exact_entries_in_ros6': len(set(router) & set(ros6)),
        'router_exact_entries_in_spamhaus': len(set(router) & set(spamhaus)),
        'watchlist_count': len(watchlist),
        'watchlist_conflicts': sum(bool(x['blocked_by']) for x in safe_watch),
        'watchlist_local_only': safe_watch,
    }


def _range_intersection(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> list[tuple[int, int]]:
    i = j = 0
    result = []
    while i < len(a) and j < len(b):
        x,y = a[i]; u,v = b[j]
        if max(x,u) <= min(y,v):
            result.append((max(x,u), min(y,v)))
        if y <= v: i += 1
        else: j += 1
    return result


def _private_output_path(path: Path, project_root: Path) -> Path:
    # Avoid accidentally committing private RouterOS/watchlist material to reports/.
    if (project_root / 'local').is_symlink():
        raise FeedError('local directory must not be a symlink')
    base = (project_root / 'local').resolve()
    target = path.resolve()
    if not target.is_relative_to(base) or target.suffix != '.json':
        raise FeedError('private audit report must remain inside ignored local/*.json')
    return target


def private_audit(dist: Path, router_rows: object, ros6_payload: bytes,
                  watchlist: list[str], out: Path, project_root: Path,
                  now: datetime | None = None) -> dict:
    target = _private_output_path(out, project_root)  # before any processing/network access
    if len(ros6_payload) > 16 * 1024 * 1024:
        raise FeedError('ros6 payload exceeds limit')
    now = now or datetime.now(timezone.utc)
    ros6, stats = parse_source(ros6_payload, 'ros6_npf_plain')
    if stats['rejected_count'] or not 1000 <= len(ros6) <= 100000:
        raise FeedError('ros6 feed failed strict validation or count bounds')
    spamhaus, manifest = _published_spamhaus(dist, 72, now)
    router, rstats = parse_router_entries(router_rows)
    summary = three_way(router, ros6, spamhaus, watchlist)
    report = {
        'schema': 1, 'version': '0.1.3', 'mode': 'LOCAL_ONLY_READ_ONLY',
        'generated_at': now.isoformat(timespec='seconds'),
        'router': rstats, 'coverage': summary,
        'inputs': {'ros6_sha256': hashlib.sha256(ros6_payload).hexdigest(),
                   'spamhaus_sha256': manifest['ipv4_sha256'],
                   'router_data_sha256': hashlib.sha256(json.dumps(router_rows, sort_keys=True).encode()).hexdigest()},
        'warning': 'watchlist_local_only contains private endpoints; NEVER upload report to GitHub',
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    # Private report replacement is transactional within local directory.
    from .quality import _atomic_write
    _atomic_write(target, (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode())
    return report


def main():
    p = argparse.ArgumentParser(description='RB5009 三方私有只读审计：绝不上传地址列表到 GitHub')
    p.add_argument('--dist', default='dist')
    p.add_argument('--router-file', help='本地保存的 RouterOS REST JSON 数组')
    p.add_argument('--router-url', help='仅从 RouterOS HTTPS REST GET，严禁公网暴露服务')
    p.add_argument('--ca-file', default=os.getenv('TIPI_ROS_CA'))
    p.add_argument('--ros6-file', help='本地 ros6 scaners.netbsd 纯地址文件')
    p.add_argument('--fetch-ros6', action='store_true', help='显式允许 HTTPS 下载 ros6 纯地址数据')
    p.add_argument('--watchlist', help='本地关键业务 IP JSON 文件，可选')
    p.add_argument('--out', default='local/router-audit-latest.json')
    args = p.parse_args()
    try:
        root = Path.cwd().resolve()
        path = _private_output_path(Path(args.out), root)
        if bool(args.router_file) == bool(args.router_url) or bool(args.ros6_file) == bool(args.fetch_ros6):
            raise FeedError('exactly one router input and exactly one ros6 input required')
        if args.router_file:
            rows = json.loads(Path(args.router_file).read_text(encoding='utf-8'))
        else:
            user, password = os.getenv('TIPI_ROS_USER', ''), os.getenv('TIPI_ROS_PASSWORD', '')
            api = RouterREST(args.router_url, user, password, args.ca_file)
            if not api.raw_verified():
                raise FeedError('expected active RAW drop src-address-list=scaners missing')
            rows = api.list_entries()  # GET only
        if args.ros6_file:
            ros6_raw = Path(args.ros6_file).read_bytes()
        else:
            cfg = json.loads((root/'config/ros6-audit.json').read_text(encoding='utf-8'))
            ros6_raw = fetch_source({'url': cfg['url']}, root)
        watchlist = read_watchlist(Path(args.watchlist))
        result = private_audit(Path(args.dist), rows, ros6_raw, watchlist, path, root)
        print(json.dumps({'status': 'AUDIT_PASS_PRIVATE',
                          'router_entries': result['router']['router_valid_unique_entries'],
                          'watchlist_conflicts': result['coverage']['watchlist_conflicts'],
                          'private_report': str(path)}, ensure_ascii=False))
    except (OSError, FeedError, ValueError, KeyError, TypeError, json.JSONDecodeError) as ex:
        p.exit(1, f'PRIVATE AUDIT STOP (router unchanged): {type(ex).__name__}: {ex}\n')


if __name__ == '__main__':
    main()
