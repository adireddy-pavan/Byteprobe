"""Tests for core/hidden_data.py — risk score and $MFT-based ADS fallback."""

import datetime
import os
import tempfile
import unittest
from unittest import mock

from core import hidden_data, mft
from core.metadata import FileMetadata
from core.signatures import SignatureResult
from core.entropy import EntropyResult
from tests import ntfs_builder as nb


def meta(path='C:\\docs\\a.txt', ext='.txt', hidden=False, system=False, size=10):
    now = datetime.datetime(2024, 1, 1)
    return FileMetadata(path=path, name=os.path.basename(path), size=size, created=now,
                        modified=now, accessed=now, is_hidden=hidden, is_system=system,
                        is_readonly=False, is_archive=False, owner='', extension=ext,
                        attributes=0)


class TestRiskScore(unittest.TestCase):
    def test_clean_file_scores_zero(self):
        self.assertEqual(hidden_data.compute_risk_score(meta()), 0)

    def test_si_fn_anomaly_weight(self):
        self.assertEqual(hidden_data.compute_risk_score(meta(), si_fn_anomaly=True), 40)

    def test_si_fn_is_highest_single_weight(self):
        sig = SignatureResult('x', '.txt', ('.exe',), '4d 5a', True, '')
        self.assertGreater(hidden_data.compute_risk_score(meta(), si_fn_anomaly=True),
                           hidden_data.compute_risk_score(meta(), sig_result=sig))

    def test_combined_and_capped(self):
        sig = SignatureResult('x', '.txt', ('.exe',), '4d 5a', True, '')
        ent = EntropyResult('x', 7.9, True, '')
        m = meta('C:\\Users\\u\\AppData\\Local\\Temp\\invoice.pdf.exe', ext='.exe',
                 hidden=True, system=True)
        self.assertEqual(hidden_data.compute_risk_score(m, sig, ent, si_fn_anomaly=True), 100)

    def test_all_seven_weights(self):
        sig = SignatureResult('x', '.txt', ('.exe',), '', True, '')
        ent = EntropyResult('x', 7.9, True, '')
        cases = [
            (dict(si_fn_anomaly=True), meta(), 40),
            (dict(sig_result=sig), meta(), 35),
            ({}, meta(hidden=True, system=True), 30),
            ({}, meta('C:\\a\\doc.txt.bat', ext='.bat'), 25 + 10),
            (dict(entropy_result=ent), meta(), 20),
            ({}, meta('C:\\temp\\run.ps1', ext='.ps1'), 20 + 10),
            ({}, meta('C:\\a\\run.ps1', ext='.ps1'), 10),
        ]
        for kwargs, m, expected in cases:
            with self.subTest(kwargs=kwargs, path=m.path):
                self.assertEqual(hidden_data.compute_risk_score(m, **kwargs), expected)

    def test_unix_temp_dirs_scored_like_flags(self):
        # Regression: compute_risk_score once checked only Windows temp paths
        # while _suspicion_flags also checked /tmp/ and /var/tmp/.
        for path in ('/tmp/run.sh.ps1', '/var/tmp/run.ps1', 'C:\\Temp\\run.ps1'):
            m = meta(path, ext='.ps1')
            with self.subTest(path=path):
                self.assertIn('Executable in temp directory',
                              ' '.join(hidden_data._suspicion_flags(m)))
                self.assertGreaterEqual(hidden_data.compute_risk_score(m), 20 + 10)


class TestMftAdsFallback(unittest.TestCase):
    def setUp(self):
        raw = nb.make_record(41, [
            nb.si_attr(*[nb.filetime(2024, 1, 1)] * 4),
            nb.fn_attr('a.txt', 5, [nb.filetime(2024, 1, 1)] * 4, parent_seq=5),
            nb.data_attr(b'hello'),
            nb.data_attr(b'[ZoneTransfer]\r\nZoneId=3', name='Zone.Identifier'),
        ])
        self.record = mft.parse_record(raw, 41)

    def test_ads_from_mft_format_matches_windows_api(self):
        [s] = hidden_data.ads_from_mft(self.record, host_file='E:\\a.txt')
        self.assertEqual((s.host_file, s.stream_name, s.size),
                         ('E:\\a.txt', ':Zone.Identifier:$DATA', 24))

    def test_fallback_used_when_api_unavailable(self):
        with mock.patch.object(hidden_data, 'IS_WINDOWS', False):
            self.assertEqual(hidden_data.enumerate_ads('/x/a.txt'), [])
            streams = hidden_data.enumerate_ads('/x/a.txt', self.record)
        self.assertEqual([s.stream_name for s in streams], [':Zone.Identifier:$DATA'])

    def test_windows_api_result_preferred(self):
        api = [hidden_data.AltDataStream('C:\\a.txt', ':api:$DATA', 1)]
        with mock.patch.object(hidden_data, 'IS_WINDOWS', True), \
             mock.patch.object(hidden_data, '_enumerate_ads_windows', return_value=api):
            self.assertEqual(hidden_data.enumerate_ads('C:\\a.txt', self.record), api)

    def test_analyze_all_uses_lookup(self):
        with tempfile.NamedTemporaryFile(suffix='.txt') as f:
            m = meta(f.name)
            with mock.patch.object(hidden_data, 'IS_WINDOWS', False):
                [res] = hidden_data.analyze_all([m], mft_lookup=lambda _m: self.record)
        self.assertTrue(res.is_suspicious)
        self.assertEqual(res.ads_streams[0].host_file, f.name)


if __name__ == '__main__':
    unittest.main()
