import json
import tempfile
import unittest
from pathlib import Path
from tools.audit_submission_evidence import audit

class EvidenceInventoryTests(unittest.TestCase):
    def test_missing_files_are_not_completed(self):
        with tempfile.TemporaryDirectory() as t:
            r = audit(Path(t))
            self.assertFalse(r['fully_verified'])
            self.assertTrue(all(v['status']=='NOT_PROVIDED' for v in r['items'].values()))

    def test_windows_partial_results_not_passed(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t); (base/'windows').mkdir()
            data={'platform':'Windows-11', 'checks': {f'W{i}':{'status':'PASS'} for i in (1,2,3,4,7)}}
            data['checks']['W5']={'status':'NOT_TESTED'}
            data['checks']['W6']={'status':'NOT_TESTED'}
            (base/'windows/windows_validation.json').write_text(json.dumps(data),encoding='utf-8')
            r=audit(base)
            self.assertEqual(r['items']['windows']['status'],'INCOMPLETE')

    def test_disallow_non_windows_claim(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t); (base/'windows').mkdir()
            data={'platform':'Linux', 'checks': {f'W{i}':{'status':'PASS'} for i in range(1,8)}}
            (base/'windows/windows_validation.json').write_text(json.dumps(data),encoding='utf-8')
            r=audit(base)
            self.assertEqual(r['items']['windows']['status'],'INCOMPLETE')

if __name__ == '__main__': unittest.main()
