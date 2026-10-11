import tempfile
import unittest
from pathlib import Path
from rhp.model import (make_hierarchy,derive_seed,quorum,unsafe_hypergeom,binomial_unsafe,
                       zero_failure_upper_bound,wilson_interval,collect_hierarchy_stats)
from rhp.primitives import (feldman_demo,dispersal_demo,beacon_demo,weak_agreement_demo,
                            merkle_tree,merkle_proof,merkle_verify)
from rhp.simulator import Scenario,run_scenario
from rhp.evaluation import new_output_root,summaries

class CoreTests(unittest.TestCase):
    def test_sortition_reproducible_and_complete(self):
        seed=derive_seed(b'zero',0,b'beacon')
        a=make_hierarchy(100,8,seed)
        b=make_hierarchy(100,8,seed)
        self.assertEqual(a,b)
        self.assertEqual(sorted(i for c in a.levels[0] for i in c.members),list(range(100)))
        self.assertEqual(len(a.levels[-1]),1)
    def test_quorum_strict_two_thirds(self):
        self.assertEqual([quorum(x) for x in (2,3,4,5,6)], [2,3,3,4,5])
    def test_sampling_with_without_replacement(self):
        self.assertEqual(unsafe_hypergeom(10,0,5),0)
        self.assertEqual(unsafe_hypergeom(10,10,5),1)
        self.assertAlmostEqual(binomial_unsafe(.2,1),.2)
        self.assertTrue(0 < unsafe_hypergeom(100,20,8) < 1)
    def test_confidence(self):
        self.assertTrue(0 < zero_failure_upper_bound(100) < .05)
        self.assertTrue(0 <= wilson_interval(0,100)[0] <= wilson_interval(0,100)[1] < .05)
    def test_feldman_vss(self):
        self.assertTrue(feldman_demo(4,3)['reconstruction_matches_public'])
    def test_merkle_authentication(self):
        values=[11,22,33,44,55]
        tree=merkle_tree(values)
        for i,value in enumerate(values):
            p=merkle_proof(tree,i)
            self.assertTrue(merkle_verify(tree[-1][0],i,value,p))
            self.assertFalse(merkle_verify(tree[-1][0],i,value+1,p))
    def test_dispersal_recovery(self):
        value=dispersal_demo(b'test payload',9,5)
        self.assertTrue(value['message_recovered'])
        self.assertTrue(value['merkle_valid'])
        self.assertTrue(value['shards_consistent'])
    def test_beacon_quorum(self):
        self.assertTrue(beacon_demo(b'seed',[b'a',b'b',b'c'])['available'])
        self.assertFalse(beacon_demo(b'seed',[b'a',b'b',b'c'],{0})['available'])
    def test_weak_agreement_certification(self):
        self.assertEqual(weak_agreement_demo(['a']*5+['b'])['certified_value'],'a')
    def test_simulation(self):
        cfg=Scenario(n=100,s=8,seed=20)
        a=run_scenario(cfg)
        b=run_scenario(cfg)
        self.assertEqual(a['messages'],b['messages'])
        self.assertEqual(a['latency_ms_model'],b['latency_ms_model'])
        self.assertGreater(a['bytes_per_node'],0)
        self.assertEqual(a['events_processed'],a['committee_count'])
        self.assertIn('wilson_upper_95',summaries([a,b])[0])
    def test_adaptive_model(self):
        a=run_scenario(Scenario(100,8,beta=.2,adversary='adaptive'))
        self.assertEqual(a['corrupted_count'],20)
        self.assertGreaterEqual(a['unsafe_committees'],1)
    def test_unique_output_dirs(self):
        with tempfile.TemporaryDirectory() as root:
            a=new_output_root(root)
            b=new_output_root(root)
            self.assertEqual(a.name,'test1')
            self.assertEqual(b.name,'test2')
    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):make_hierarchy(100,1,b'seed')
        with self.assertRaises(ValueError):run_scenario(Scenario(100,8,beta=1/3))
if __name__=='__main__':unittest.main()
