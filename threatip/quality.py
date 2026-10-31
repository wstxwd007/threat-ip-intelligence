"""Fail-closed quality gate for publicly distributable IPv4 feeds.

This module never fetches ros6 nor writes to RouterOS. Do not include IP/CIDR
samples in PUBLIC reports; aggregate counts and stable hashes only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile

from .audit import _ranges, _union, _size, _intersection_size
from .feeds import FeedError, parse_source


def read_feed(path: Path) -> tuple[list[str], str]:
    data = path.read_bytes()
    entries, stats = parse_source(data, 'plain')
    if stats['rejected_count'] or stats['raw_count'] != stats['valid_count']:
        raise FeedError('quality input is noncanonical, duplicate or invalid')
    if len(entries) == 0:
        raise FeedError('quality input empty')
    return entries, hashlib.sha256(data).hexdigest()


def summarize(values: list[str], large_prefix: int = 16) -> dict:
    networks = [ipaddress.ip_network(x, strict=True) for x in values]
    histogram: dict[str, int] = {}
    for n in networks:
        key = f'/{n.prefixlen}'
        histogram[key] = histogram.get(key, 0) + 1
    large = [n for n in networks if n.prefixlen <= large_prefix]
    return {
        'entry_count': len(networks),
        'unique_ipv4_addresses': _size(_union(_ranges(values))),
        'single_ip_entries': sum(n.prefixlen == 32 for n in networks),
        'large_cidr_entries': len(large),
        'large_cidr_address_sum_not_deduplicated': sum(n.num_addresses for n in large),
        'large_prefix_threshold': f'/{large_prefix}',
        'prefix_histogram': dict(sorted(histogram.items(), key=lambda x: int(x[0][1:]))),
    }


def evaluate(old: list[str], candidate: list[str], policy: dict) -> dict:
    """Compare exact ranges. One swapped /8 is not harmless merely because total stays constant."""
    allowed_keys = {'large_prefix_threshold', 'max_added_unique_ipv4',
                    'max_added_ratio', 'max_removed_ratio', 'max_new_large_cidrs'}
    if set(policy) - allowed_keys:
        raise FeedError('unknown quality gate settings')
    lp = int(policy.get('large_prefix_threshold', 16))
    max_added = int(policy.get('max_added_unique_ipv4', 2000000))
    max_added_ratio = float(policy.get('max_added_ratio', .25))
    max_removed_ratio = float(policy.get('max_removed_ratio', .35))
    max_large = int(policy.get('max_new_large_cidrs', 2))
    if not 8 <= lp <= 24 or min(max_added, max_large) < 0 or not (0 <= max_added_ratio <= 5) or not (0 <= max_removed_ratio <= 1):
        raise FeedError('invalid quality gate limits')
    old_set, new_set = set(old), set(candidate)
    if not old_set or not new_set:
        raise FeedError('quality gate needs nonempty previous and candidate feeds')
    a = _union(_ranges(old)); b = _union(_ranges(candidate))
    oldsize, newsize = _size(a), _size(b)
    shared = _intersection_size(a, b)
    added = newsize - shared
    removed = oldsize - shared
    novel_big = [x for x in new_set - old_set if ipaddress.ip_network(x).prefixlen <= lp]
    reasons: list[str] = []
    if added > max_added and added / oldsize > max_added_ratio:
        reasons.append('NEW_IPV4_COVERAGE_ABOVE_BOTH_LIMITS')
    if removed / oldsize > max_removed_ratio:
        reasons.append('REMOVED_IPV4_COVERAGE_ABOVE_LIMIT')
    if len(novel_big) > max_large:
        reasons.append('NEW_LARGE_PREFIX_COUNT_ABOVE_LIMIT')
    return {
        'schema': 1, 'version': '0.1.3',
        'old': summarize(old, lp), 'candidate': summarize(candidate, lp),
        'changes': {
            'exact_entries_added': len(new_set - old_set),
            'exact_entries_removed': len(old_set - new_set),
            'ipv4_addresses_added_to_coverage': added,
            'ipv4_addresses_removed_from_coverage': removed,
            'new_large_cidr_entries': len(novel_big),
            'added_coverage_ratio': round(added / oldsize, 8),
            'removed_coverage_ratio': round(removed / oldsize, 8),
        },
        'decision': 'REVIEW_REQUIRED' if reasons else 'PASS',
        'review_reasons': reasons,
        'note': 'coverage size is not false-positive rate; never infer malicious hosts from covered IP count',
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.tipi-quality-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as fp:
            fp.write(data)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def run_gate(old_path: Path, candidate_path: Path, policy_path: Path, out_path: Path) -> dict:
    old, old_hash = read_feed(old_path)
    new, new_hash = read_feed(candidate_path)
    policy = json.loads(policy_path.read_text(encoding='utf-8'))
    if not isinstance(policy, dict):
        raise FeedError('quality policy must be object')
    report = evaluate(old, new, policy)
    report['generated_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    report['old_sha256'] = old_hash
    report['candidate_sha256'] = new_hash
    # Fail-closed: do NOT overwrite previous public report when review required.
    if report['decision'] != 'PASS':
        raise FeedError('REVIEW REQUIRED: ' + ', '.join(report['review_reasons']))
    _atomic_write(out_path, (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode())
    return report


def main():
    parser = argparse.ArgumentParser(description='公开情报发布前 CIDR 变化风险闸门（无路由器写操作）')
    parser.add_argument('--old', required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--policy', default='config/quality-policy.json')
    parser.add_argument('--out', default='reports/quality-latest.json')
    args = parser.parse_args()
    try:
        r = run_gate(Path(args.old), Path(args.candidate), Path(args.policy), Path(args.out))
        print(json.dumps({'decision': r['decision'], 'changes': r['changes']}, ensure_ascii=False))
    except (FeedError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as ex:
        parser.exit(1, f'QUALITY STOP (old release unchanged): {type(ex).__name__}: {ex}\n')


if __name__ == '__main__':
    main()
