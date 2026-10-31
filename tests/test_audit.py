import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from threatip.audit import audit, compare_feeds, render_markdown
from threatip.feeds import FeedError, extract_candidates, parse_source

FIXED_NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


class OverlapTests(unittest.TestCase):
    def test_exact_duplicate_and_subnet_containment(self):
        result = compare_feeds(['8.8.8.8', '8.8.4.0/24', '1.1.1.1'],
                               ['8.8.0.0/16', '1.1.1.1'])
        self.assertEqual(result['exact_same_entries'], 1)
        self.assertEqual(result['ros6_entries_fully_covered_by_spamhaus'], 3)
        self.assertEqual(result['spamhaus_entries_fully_covered_by_ros6'], 1)
        self.assertEqual(result['overlap_ipv4_addresses'], 258)
        self.assertEqual(result['combined_unique_ipv4_addresses'], 65537)
        self.assertEqual(result['additional_ipv4_addresses_from_ros6'], 0)
        self.assertEqual(result['additional_ipv4_addresses_from_spamhaus'], 65279)

    def test_partial_overlap_not_counted_as_full_entry(self):
        result = compare_feeds(['8.8.0.0/24'], ['8.8.0.128/25'])
        self.assertEqual(result['exact_same_entries'], 0)
        self.assertEqual(result['ros6_entries_fully_covered_by_spamhaus'], 0)
        self.assertEqual(result['spamhaus_entries_fully_covered_by_ros6'], 1)
        self.assertEqual(result['overlap_ipv4_addresses'], 128)
        self.assertEqual(result['additional_ipv4_addresses_from_ros6'], 128)

    def test_no_double_count_for_nested_ranges(self):
        result = compare_feeds(['8.8.0.0/24', '8.8.0.128/25', '8.8.0.0/24'],
                               ['8.8.0.0/23'])
        self.assertEqual(result['ros6_entry_count'], 2)
        self.assertEqual(result['ros6_ipv4_addresses_covered'], 256)
        self.assertEqual(result['combined_unique_ipv4_addresses'], 512)

    def test_empty_and_nonoverlap(self):
        result = compare_feeds([], ['1.1.1.1'])
        self.assertEqual(result['overlap_ipv4_addresses'], 0)
        self.assertEqual(result['combined_unique_ipv4_addresses'], 1)
        self.assertEqual(result['additional_ipv4_addresses_from_spamhaus'], 1)

    def test_no_address_leak_in_report(self):
        record = {'generated_at': '2026-10-31T12:00:00+00:00',
                  'inputs': {'ros6_sha256': 'a'*64, 'spamhaus_published_at': '2026-10-31T10:00:00+00:00'},
                  'comparison': compare_feeds(['8.8.8.8'], ['8.8.8.8'])}
        markdown = render_markdown(record)
        self.assertNotIn('8.8.8.8', markdown)
        self.assertIn('完全相同', markdown)


class Ros6ParserTests(unittest.TestCase):
    def test_multiline_export_and_quoted_comments(self):
        text = ('# date\n/ip firewall address-list\n'
                'add address=8.8.8.8 list=scaners comment="scan detected"\n'
                'add list="scaners" address="9.9.9.0/24" timeout=30d disabled=no\n')
        self.assertEqual(extract_candidates(text.encode(), 'ros6_rsc'),
                         ['8.8.8.8', '9.9.9.0/24'])

    def test_inline_address_list_directive(self):
        text = '/ip/firewall/address-list add address=8.8.8.8 list=scaners\n'
        self.assertEqual(extract_candidates(text.encode(), 'ros6_rsc'), ['8.8.8.8'])

    def test_reject_commands_and_injection(self):
        bad = [
            'remove [find list=scaners]',
            ':delay 2s',
            'add list=scaners address=8.8.8.8; /system reboot',
            'add list=scaners address=8.8.8.8 comment=$secret',
            'add list=scaners address=8.8.8.8 disabled=yes',
            'add list=scaners address=8.8.8.8 list=scaners',
            'add list=scaners address=8.8.8.8 in-interface=WAN',
            'add list=another address=8.8.8.8',
            'add list=scaners address=8.8.8.8 comment="unclosed',
            'add list=scaners address=8.8.8.8 \\',
        ]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(FeedError):
                extract_candidates(raw.encode(), 'ros6_rsc')

    def test_non_global_rejected(self):
        with self.assertRaises(FeedError):
            parse_source(b'add list=scaners address=10.0.0.0/8', 'ros6_rsc')


class AuditEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for d in ('config', 'dist', 'reports'):
            (self.root/d).mkdir()
        self.ros6 = self.root/'local-rsc.txt'
        self.ros6.write_text('/ip firewall address-list\nadd list=scaners address=8.8.8.8\n'
                             'add address=1.1.1.1 list=scaners\n', encoding='utf-8')
        self.config = self.root/'config'/'ros6-audit.json'
        self.config.write_text(json.dumps({'format': 'ros6_rsc', 'url': 'https://example.com/scaners.rsc',
                                           'min_ros6_entries': 1, 'max_ros6_entries': 100,
                                           'max_spamhaus_age_hours': 72}), encoding='utf-8')
        self.feed = b'# synthetic\n8.8.8.0/24\n9.9.9.9\n'
        self.manifest = {'schema': 1, 'generated_at': (FIXED_NOW - timedelta(hours=1)).isoformat(),
                         'sources': [{'name': 'Spamhaus DROP IPv4'}],
                         'ipv4_count': 2, 'ipv4_sha256': hashlib.sha256(self.feed).hexdigest()}
        (self.root/'dist'/'ipv4.txt').write_bytes(self.feed)
        self._save_manifest()

    def _save_manifest(self):
        (self.root/'dist'/'manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')

    def test_report_generated_only_with_aggregates(self):
        report = audit(self.config, self.root/'dist', self.root/'reports', self.ros6, FIXED_NOW)
        self.assertEqual(report['comparison']['exact_same_entries'], 0)
        self.assertEqual(report['comparison']['ros6_entries_fully_covered_by_spamhaus'], 1)
        self.assertEqual(report['comparison']['combined_unique_ipv4_addresses'], 258)
        for name in ['ros6-latest.json', 'ros6-latest.md']:
            data = (self.root/'reports'/name).read_text(encoding='utf-8')
            self.assertNotIn('8.8.8.8', data)
            self.assertNotIn('1.1.1.1', data)
            self.assertNotIn('8.8.8.0/24', data)
        self.assertTrue((self.root/'reports'/'ros6-latest.md').exists())

    def test_corrupt_hash_does_not_modify_old_report(self):
        p = self.root/'reports'/'ros6-latest.json'
        p.write_text('PREVIOUS REPORT')
        self.manifest['ipv4_sha256'] = '0'*64
        self._save_manifest()
        with self.assertRaises(FeedError):
            audit(self.config, self.root/'dist', self.root/'reports', self.ros6, FIXED_NOW)
        self.assertEqual(p.read_text(), 'PREVIOUS REPORT')

    def test_stale_published_spamhaus_refused(self):
        self.manifest['generated_at'] = (FIXED_NOW - timedelta(days=5)).isoformat()
        self._save_manifest()
        with self.assertRaises(FeedError):
            audit(self.config, self.root/'dist', self.root/'reports', self.ros6, FIXED_NOW)

    def test_multi_source_published_feed_rejected(self):
        self.manifest['sources'].append({'name': 'Other'})
        self._save_manifest()
        with self.assertRaises(FeedError):
            audit(self.config, self.root/'dist', self.root/'reports', self.ros6, FIXED_NOW)

    def test_source_count_drop_refused(self):
        cfg = json.loads(self.config.read_text())
        cfg['min_ros6_entries'] = 1000
        self.config.write_text(json.dumps(cfg))
        with self.assertRaises(FeedError):
            audit(self.config, self.root/'dist', self.root/'reports', self.ros6, FIXED_NOW)

    def test_parser_error_does_not_modify_old_report(self):
        p = self.root/'reports'/'ros6-latest.json'
        p.write_text('PREVIOUS REPORT')
        self.ros6.write_text('add address=8.8.8.8 list=scaners\n/system reset-configuration\n')
        with self.assertRaises(FeedError):
            audit(self.config, self.root/'dist', self.root/'reports', self.ros6, FIXED_NOW)
        self.assertEqual(p.read_text(), 'PREVIOUS REPORT')

    def test_cli_remote_fetch_can_be_mocked(self):
        data = self.ros6.read_bytes()
        with patch('threatip.audit.fetch_source', return_value=data) as mocked:
            report = audit(self.config, self.root/'dist', self.root/'reports', now=FIXED_NOW)
        mocked.assert_called_once()
        self.assertEqual(report['comparison']['ros6_entry_count'], 2)

if __name__ == '__main__':
    unittest.main()
