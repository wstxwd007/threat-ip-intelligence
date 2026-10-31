from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from threatip.feeds import FeedError
from threatip.router_audit import (parse_router_entries, three_way,
                                   read_watchlist, private_audit, _private_output_path)

FIXED = datetime(2026, 10, 31, 15, tzinfo=timezone.utc)


class RouterAuditTests(unittest.TestCase):
    def test_router_filters_disabled_and_private_and_preserves_enabled(self):
        rows = [
            {'list':'scaners', 'address':'8.8.8.8', 'disabled':'false'},
            {'list':'scaners', 'address':'8.8.8.8'},
            {'list':'other', 'address':'9.9.9.9'},
            {'list':'scaners', 'address':'9.9.9.9', 'disabled':'true'},
            {'list':'scaners', 'address':'10.0.0.1'},
        ]
        values, stats = parse_router_entries(rows)
        self.assertEqual(values, ['8.8.8.8'])
        self.assertEqual(stats['ignored_duplicate'], 1)
        self.assertEqual(stats['ignored_invalid_or_private'], 1)
        self.assertEqual(stats['ignored_disabled'], 1)
        self.assertEqual(stats['ignored_other_lists'], 1)

    def test_no_valid_router_entries_fails(self):
        with self.assertRaises(FeedError):
            parse_router_entries([{'list': 'scaners', 'address': '10.0.0.1'}])

    def test_non_array_and_malformed_rows_fail(self):
        for bad in ({'entries': []}, [None], ['8.8.8.8']):
            with self.assertRaises(FeedError):
                parse_router_entries(bad)

    def test_three_way_coverage_and_watchlist(self):
        d = three_way(['8.8.0.0/24', '9.9.9.9'],
                      ['8.8.8.8', '8.8.0.128/25'],
                      ['8.8.0.0/16'], ['8.8.8.8', '9.9.9.9', '1.1.1.1'])
        self.assertEqual(d['router_coverage_in_ros6'], 128)
        self.assertEqual(d['router_coverage_in_spamhaus'], 256)
        self.assertEqual(d['router_coverage_in_both'], 128)
        self.assertEqual(d['router_addresses_outside_both_sources'], 1)
        self.assertEqual(d['watchlist_conflicts'], 2)
        self.assertEqual(d['watchlist_local_only'][0]['blocked_by'], ['ros6', 'spamhaus'])

    def test_watchlist_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'watch.json'
            p.write_text(json.dumps({'addresses':['8.8.8.8','9.9.9.9']}))
            self.assertEqual(len(read_watchlist(p)), 2)
            for bad in ({'addresses':['8.8.8.8','8.8.8.8']},
                        {'addresses':['8.8.8.0/24']},
                        {'addresses':['10.0.0.1']},
                        {'addresses':['8.8.8.8'], 'token':'abc'}):
                p.write_text(json.dumps(bad))
                with self.assertRaises(FeedError):
                    read_watchlist(p)

    def test_prevent_private_output_to_public_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for out in (root/'reports'/'router.json', root/'dist'/'router.json', root/'router.json'):
                with self.assertRaises(FeedError):
                    _private_output_path(out, root)
            self.assertEqual(_private_output_path(root/'local'/'router.json', root), root/'local'/'router.json')

    def test_symlinked_local_directory_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'reports').mkdir()
            (root/'local').symlink_to(root/'reports', target_is_directory=True)
            with self.assertRaises(FeedError):
                _private_output_path(root/'local'/'unsafe.json', root)

    def test_three_way_no_partial_overlap_overcount(self):
        d = three_way(['8.8.0.0/24'], ['8.8.0.128/25'],
                      ['8.8.0.0/25'], [])
        self.assertEqual(d['router_coverage_in_ros6'], 128)
        self.assertEqual(d['router_coverage_in_spamhaus'], 128)
        self.assertEqual(d['router_coverage_in_both'], 0)
        self.assertEqual(d['router_addresses_outside_both_sources'], 0)

    def test_local_end_to_end_without_network_and_no_report_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'dist').mkdir()
            # 1000 real-format synthetic IPv4 entries for strict input lower bound.
            ros6 = ('\n'.join(str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('8.8.0.0')) + i))
                              for i in range(1000)) + '\n').encode()
            spam = b'8.8.0.0/16\n'
            (root/'dist'/'ipv4.txt').write_bytes(spam)
            (root/'dist'/'manifest.json').write_text(json.dumps({
                'schema': 1, 'generated_at': (FIXED-timedelta(hours=1)).isoformat(),
                'ipv4_count': 1, 'ipv4_sha256': hashlib.sha256(spam).hexdigest(),
                'sources':[{'name':'Spamhaus DROP IPv4'}]}))
            rows = [{'list':'scaners','address':'8.8.8.8','disabled':'false'}]
            out = root/'local'/'router-audit.json'
            result = private_audit(root/'dist', rows, ros6, ['8.8.8.8','9.9.9.9'], out, root, FIXED)
            self.assertEqual(result['coverage']['watchlist_conflicts'], 1)
            self.assertTrue(out.exists())
            self.assertIn('8.8.8.8', out.read_text())
            self.assertFalse((root/'reports').exists())
            self.assertEqual(result['coverage']['ros6_addresses_not_covered_by_router'], 1000)

    def test_fail_preserves_private_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'local').mkdir()
            p = root/'local'/'router.json'
            p.write_text('OLD')
            with self.assertRaises(FeedError):
                private_audit(root/'dist', [], b'8.8.8.8\n', [], p, root)
            self.assertEqual(p.read_text(), 'OLD')
