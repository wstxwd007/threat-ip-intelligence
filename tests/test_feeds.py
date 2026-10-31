import json
import tempfile
import unittest
from pathlib import Path
from threatip.feeds import FeedError, normalize_ip, parse_source, extract_candidates, fetch_source
from threatip.build import build

class FeedTests(unittest.TestCase):
    def test_plain_dedup(self):
        entries, stats = parse_source(b'# comment\n8.8.8.8\n1.1.1.1\n8.8.8.8\n', 'plain')
        self.assertEqual(entries, ['1.1.1.1', '8.8.8.8'])
        self.assertEqual(stats['valid_count'], 2)

    def test_spamhaus_json(self):
        data = json.dumps([{'cidr':'8.8.4.0/24','sblid':'SBL123'}, {'cidr':'9.9.9.9/32'}]).encode()
        entries, _ = parse_source(data, 'spamhaus_json')
        self.assertEqual(entries, ['8.8.4.0/24', '9.9.9.9'])

    def test_no_network_expansion(self):
        entries, _ = parse_source(b'8.8.8.8\n8.8.8.9\n', 'plain')
        self.assertEqual(len(entries), 2)

    def test_non_global_rejected(self):
        for v in ['127.0.0.1', '192.168.11.1', '10.0.0.0/8', '169.254.1.2', '203.0.113.1', '0.0.0.0/0', '::1', '8.8.8.0/7']:
            with self.subTest(v=v), self.assertRaises(FeedError):
                normalize_ip(v)

    def test_invalid_ambiguous_network(self):
        with self.assertRaises(FeedError):
            normalize_ip('8.8.8.9/24')

    def test_ros6_rsc_not_executed(self):
        contents = b'/ip firewall address-list\nadd list=scaners address=8.8.8.8 comment=test\n'
        self.assertEqual(extract_candidates(contents, 'ros6_rsc'), ['8.8.8.8'])
        for s in [b'/system reset-configuration', b'add address=8.8.8.8 list=other', b'add address=8.8.8.8 list=scaners; /system reboot', b'add list=scaners address=$danger']:
            with self.subTest(s=s), self.assertRaises(FeedError):
                extract_candidates(s, 'ros6_rsc')

    def test_empty_feed_refused(self):
        with self.assertRaises(FeedError):
            parse_source(b'# only comments\n', 'plain')

    def test_allowed_empty_feed(self):
        self.assertEqual(parse_source(b'', 'plain', allow_empty=True)[0], [])

    def test_invalid_source_rejected(self):
        with self.assertRaises(FeedError):
            parse_source(b'8.8.8.8\n<script>attack</script>\n', 'plain')

    def test_path_traversal_rejected(self):
        with self.assertRaises(FeedError):
            fetch_source({'file': '../outside.txt'}, Path('/tmp/foo'))

    def test_publication_and_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'config').mkdir()
            (root/'samples').mkdir()
            (root/'samples'/'feed.txt').write_text('8.8.8.8\n1.1.1.1\n')
            cfg = {'sources': [{'name': 'synthetic', 'enabled': True, 'file': 'samples/feed.txt', 'format': 'plain'}]}
            cp = root/'config'/'sources.json'
            cp.write_text(json.dumps(cfg))
            manifest = build(cp, root/'dist')
            import hashlib
            self.assertEqual(manifest['ipv4_count'], 2)
            self.assertEqual(hashlib.sha256((root/'dist'/'ipv4.txt').read_bytes()).hexdigest(), manifest['ipv4_sha256'])
            self.assertEqual((root/'dist'/'ipv4.txt').read_text().count('8.8.8.8'), 1)

    def test_failure_keeps_last_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'config').mkdir()
            (root/'dist').mkdir()
            (root/'dist'/'ipv4.txt').write_text('OLD_RELEASE')
            cp = root/'config'/'sources.json'
            cp.write_text(json.dumps({'sources':[{'name':'none', 'enabled':False}]}))
            with self.assertRaises(FeedError):
                build(cp, root/'dist')
            self.assertEqual((root/'dist'/'ipv4.txt').read_text(), 'OLD_RELEASE')

if __name__ == '__main__': unittest.main()

# Explicit runtime gate test; stale intel must not publish.
class FreshnessTests(unittest.TestCase):
    def test_stale_feodo_refused(self):
        from threatip.feeds import validate_freshness
        with self.assertRaises(FeedError):
            validate_freshness(b'# Last updated: 2026-03-04 14:28:39 UTC\n', {'format': 'plain', 'max_age_days': 30})
    def test_header_missing_refused(self):
        from threatip.feeds import validate_freshness
        with self.assertRaises(FeedError):
            validate_freshness(b'8.8.8.8\n', {'format': 'plain', 'max_age_days': 30})
