import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from threatip.feeds import FeedError
from threatip.quality import summarize, evaluate, run_gate, read_feed


class QualityTests(unittest.TestCase):
    def test_large_prefix_histogram_and_coverage_without_ip_leak(self):
        s = summarize(['8.8.0.0/16', '8.8.8.8', '9.9.9.9'])
        self.assertEqual(s['unique_ipv4_addresses'], 65537)
        self.assertEqual(s['large_cidr_entries'], 1)
        self.assertEqual(s['prefix_histogram'], {'/16': 1, '/32': 2})
        self.assertNotIn('8.8.0.0', json.dumps(s))

    def test_unrelated_new_large_cidr_blocks(self):
        out = evaluate(['8.8.0.0/16'], ['8.8.0.0/16', '11.0.0.0/8'],
                       {'max_added_unique_ipv4': 1000, 'max_added_ratio': .1,
                        'max_new_large_cidrs': 0})
        self.assertEqual(out['decision'], 'REVIEW_REQUIRED')
        self.assertIn('NEW_LARGE_PREFIX_COUNT_ABOVE_LIMIT', out['review_reasons'])
        self.assertIn('NEW_IPV4_COVERAGE_ABOVE_BOTH_LIMITS', out['review_reasons'])

    def test_total_count_unchanged_but_range_swapped_blocks(self):
        out = evaluate(['8.8.0.0/16'], ['9.9.0.0/16'],
                       {'max_added_unique_ipv4': 100, 'max_added_ratio': .1,
                        'max_removed_ratio': .2})
        self.assertEqual(out['decision'], 'REVIEW_REQUIRED')
        self.assertEqual(out['changes']['ipv4_addresses_added_to_coverage'], 65536)
        self.assertEqual(out['changes']['ipv4_addresses_removed_from_coverage'], 65536)

    def test_small_change_passes(self):
        out = evaluate(['8.8.0.0/24'], ['8.8.0.0/24', '9.9.9.9'], {})
        self.assertEqual(out['decision'], 'PASS')
        self.assertEqual(out['changes']['ipv4_addresses_added_to_coverage'], 1)

    def test_no_previous_data_fails_closed(self):
        with self.assertRaises(FeedError):
            evaluate([], ['8.8.8.8'], {})

    def test_invalid_policy_rejected(self):
        for policy in ({'max_added_ratio': -1}, {'unknown': 1},
                       {'large_prefix_threshold': 33}):
            with self.subTest(policy=policy), self.assertRaises(FeedError):
                evaluate(['8.8.8.8'], ['8.8.8.8'], policy)

    def test_noncanonical_and_duplicate_feed_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'feed.txt'
            for content in ('8.8.8.8\n8.8.8.8\n', '8.8.8.8\n10.0.0.1\n'):
                path.write_text(content)
                with self.assertRaises(FeedError):
                    read_feed(path)

    def test_fail_preserves_previous_report_and_candidate_not_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'old.txt').write_text('8.8.0.0/16\n')
            (root/'new.txt').write_text('11.0.0.0/8\n')
            (root/'policy.json').write_text(json.dumps({'max_removed_ratio': .1}))
            (root/'out.json').write_text('PREVIOUS')
            with self.assertRaises(FeedError):
                run_gate(root/'old.txt', root/'new.txt', root/'policy.json', root/'out.json')
            self.assertEqual((root/'out.json').read_text(), 'PREVIOUS')
            self.assertEqual((root/'old.txt').read_text(), '8.8.0.0/16\n')

    def test_atomic_success_public_report_does_not_contain_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'old.txt').write_text('8.8.0.0/24\n')
            (root/'new.txt').write_text('8.8.0.0/24\n9.9.9.9\n')
            (root/'policy.json').write_text('{}')
            result = run_gate(root/'old.txt', root/'new.txt', root/'policy.json', root/'public.json')
            data = (root/'public.json').read_text()
            self.assertEqual(result['decision'], 'PASS')
            self.assertNotIn('8.8.0.0', data)
            self.assertNotIn('9.9.9.9', data)
