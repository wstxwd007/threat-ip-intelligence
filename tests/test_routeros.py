import unittest
from threatip.routeros import Diff, plan_diff, safety_check, apply_diff, FeedError, OWNER, LIST_NAME

class MockRouter:
    def __init__(self, entries):
        self.entries = list(entries)
        self.counter = 100
        self.fail_on = None
    def add(self, address):
        if self.fail_on == 'add': raise IOError('forced add failure')
        self.counter += 1
        rid = f'*{self.counter:X}'
        self.entries.append({'.id': rid, 'address': address, 'comment': OWNER, 'list': LIST_NAME})
        return rid
    def remove(self, rid):
        if self.fail_on == 'delete': raise IOError('forced delete failure')
        self.entries = [e for e in self.entries if e['.id'] != rid]
    def list_entries(self): return self.entries

class RouterTests(unittest.TestCase):
    def test_preserve_user_and_ros6_items(self):
        original = [{'.id':'*1','address':'8.8.8.8','list':LIST_NAME,'comment':'ros6'},
                    {'.id':'*2','address':'9.9.9.9','list':LIST_NAME,'comment':OWNER},
                    {'.id':'*3','address':'4.4.4.4','list':LIST_NAME,'comment':OWNER}]
        diff = plan_diff(['8.8.8.8','1.1.1.1','9.9.9.9'], original)
        self.assertEqual(diff.additions, ['1.1.1.1'])
        self.assertEqual(diff.removals, [('*3','4.4.4.4')])
        self.assertEqual(diff.kept_external, 1)
        c = MockRouter(original)
        apply_diff(c,diff,['8.8.8.8','1.1.1.1','9.9.9.9'])
        self.assertIn(original[0], c.entries)
        self.assertFalse(any(x['address']=='4.4.4.4' for x in c.entries))

    def test_mass_deletion_guard(self):
        diff=Diff([], [('*1','8.8.8.8')]*4, 1, 6)
        with self.assertRaises(FeedError): safety_check(diff, 10, 1000, 100, 0.1)

    def test_mass_addition_guard(self):
        diff=Diff(['8.8.8.8']*20, [], 0, 0)
        with self.assertRaises(FeedError): safety_check(diff, 0, 10, 10, 0.2)

    def test_add_failure_preserves_existing(self):
        original = [{'.id':'*1','address':'8.8.8.8','list':LIST_NAME,'comment':'ros6'}]
        c=MockRouter(original)
        c.fail_on='add'
        with self.assertRaises(IOError): apply_diff(c, Diff(['1.1.1.1'],[],1,0),['8.8.8.8','1.1.1.1'])
        self.assertEqual(c.entries, original)

    def test_dry_run_diff_does_not_touch_client(self):
        original=[{'.id':'*1','address':'8.8.8.8','list':LIST_NAME,'comment':'ros6'}]
        c=MockRouter(original)
        diff=plan_diff(['1.1.1.1'],c.list_entries())
        self.assertEqual(diff.removals, [])
        self.assertEqual(c.entries, original)

    def test_invalid_address_refused(self):
        with self.assertRaises(FeedError):
            plan_diff(['8.8.8.8'],[{'.id':'*1','address':'192.168.1.1','list':LIST_NAME,'comment':OWNER}])

if __name__=='__main__': unittest.main()

class PreserveTests(unittest.TestCase):
    def test_non_global_external_entry_preserved(self):
        existing=[{'.id':'*1','address':'192.168.11.1','list':LIST_NAME,'comment':'local rule'}]
        d=plan_diff(['1.1.1.1'],existing)
        self.assertEqual(d.kept_external,1)
        c=MockRouter(existing)
        apply_diff(c,d,['1.1.1.1'])
        self.assertIn(existing[0],c.entries)
