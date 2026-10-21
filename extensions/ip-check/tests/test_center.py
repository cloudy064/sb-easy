import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from center import Center

class Job:
    def __init__(self,*_): self.result={'phase':'idle','results':[],'summary':{},'error':''}
    def start(self,p):
        self.params=p
        self.result={'phase':'running','results':[],'summary':{},'error':''}
    def snapshot(self): return copy.deepcopy(self.result)
    def cancel(self):self.result['phase']='cancelled';return self.snapshot()
    def close(self):self.cancel()

class CenterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.center=Center(self.tmp.name,'/fixed/core','eth0','/fixed/data')
        self.req={'action':'start','scope':'profile-a','config':{'outbounds':[{'tag':'Node','type':'socks','server':'proxy.example','server_port':1080,'password':'fixture-secret'}]},'params':{'tags':['Node'],'ipv6':True}}
    @patch('center.Worker',Job)
    def test_shared_results_restart_and_scope_isolation(self):
        self.center.dispatch(self.req)
        job=next(iter(self.center.jobs.values()));job.result['phase']='complete'
        job.result['results']=[{'node':'Node','ipv4':{'status':'ok','ip':'8.8.8.8'}}]
        read=dict(self.req,action='snapshot',params={})
        self.assertEqual(self.center.dispatch(read)['results'][0]['node'],'Node')
        self.assertFalse(self.center.dispatch(dict(read,scope='other-profile'))['results'])
        restored=Center(self.tmp.name,'/fixed/core','eth0','/fixed/data')
        self.assertEqual(restored.dispatch(read)['phase'],'complete')
        self.assertNotIn('fixture-secret',''.join(p.read_text() for p in Path(self.tmp.name).glob('*.json')))
        changed=copy.deepcopy(read);changed['config']['outbounds'][0]['password']='changed'
        self.assertFalse(restored.dispatch(changed)['results'])
    @patch('center.Worker',Job)
    def test_no_client_interface_config_or_core_override_and_global_busy(self):
        bad=copy.deepcopy(self.req);bad['params']['interface']='user-tun'
        with self.assertRaises(ValueError):self.center.dispatch(bad)
        self.center.dispatch(self.req)
        job=next(iter(self.center.jobs.values()))
        self.assertEqual(job.params['interface'],'eth0');self.assertEqual(job.params['sing_box'],'/fixed/core')
        with self.assertRaises(ValueError):self.center.dispatch(dict(self.req,scope='other'))
        self.assertEqual(self.center.dispatch(dict(self.req,action='cancel'))['phase'],'cancelled')
    def test_catalog_never_exposes_credentials(self):
        result=self.center.dispatch(dict(self.req,action='catalog'))
        self.assertNotIn('fixture-secret',json.dumps(result));self.assertEqual(result['interfaces'],[])
    def test_routing_mark_is_center_owned(self):
        self.center.routing_mark=8228
        with patch('center.Worker',side_effect=Job) as factory:
            self.center.dispatch(self.req)
            factory.assert_called_once_with('/fixed/data',8228)
        bad=copy.deepcopy(self.req);bad['params']['routing_mark']=123
        with self.assertRaises(ValueError):self.center.dispatch(bad)
    def test_invalid_routing_marks_rejected_before_core_start(self):
        from probe import ProbeCore,ProbeError
        for mark in (-1,0,True,2**32,'8228'):
            with self.assertRaises(ProbeError):ProbeCore('core',{},'Node','eth0',routing_mark=mark)

if __name__=='__main__':unittest.main()
