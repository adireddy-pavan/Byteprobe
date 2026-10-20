"""Tests for core/virustotal.py — the VirusTotal API is mocked; no network."""

import json
import threading
import unittest
import urllib.error
from unittest import mock

from core import virustotal as vt
from core.hasher import FileHashes

SHA = 'a' * 64


def _response(stats):
    body = json.dumps({'data': {'attributes': {'last_analysis_stats': stats}}}).encode()
    resp = mock.MagicMock()
    resp.read.return_value = body
    resp.__enter__.return_value = resp
    return resp


def _http_error(code):
    return urllib.error.HTTPError(vt.VT_URL.format(SHA), code, 'err', {}, None)


STATS = {'malicious': 0, 'suspicious': 0, 'undetected': 60,
         'harmless': 0, 'timeout': 2, 'type-unsupported': 10}


class TestCheckHash(unittest.TestCase):
    def check(self, side_effect=None, return_value=None):
        with mock.patch('urllib.request.urlopen', side_effect=side_effect,
                        return_value=return_value) as m:
            result = vt.check_hash(SHA, 'KEY')
        return result, m

    def test_request_url_and_api_key_header(self):
        _, m = self.check(return_value=_response(STATS))
        req = m.call_args.args[0]
        self.assertEqual(req.full_url, f'https://www.virustotal.com/api/v3/files/{SHA}')
        self.assertEqual(req.get_header('X-apikey'), 'KEY')

    def test_malicious(self):
        r, _ = self.check(return_value=_response({**STATS, 'malicious': 5, 'suspicious': 1}))
        self.assertEqual((r['verdict'], r['malicious'], r['suspicious']), ('malicious', 5, 1))
        self.assertEqual(r['total'], 78)
        self.assertEqual(r['permalink'], f'https://www.virustotal.com/gui/file/{SHA}')

    def test_suspicious(self):
        r, _ = self.check(return_value=_response({**STATS, 'suspicious': 2}))
        self.assertEqual(r['verdict'], 'suspicious')

    def test_clean(self):
        r, _ = self.check(return_value=_response(STATS))
        self.assertEqual((r['verdict'], r['undetected'], r['error']), ('clean', 60, ''))

    def test_unknown_hash_404(self):
        r, _ = self.check(side_effect=_http_error(404))
        self.assertEqual((r['verdict'], r['error']), ('unknown', 'Not in VirusTotal database'))

    def test_bad_key_401(self):
        r, _ = self.check(side_effect=_http_error(401))
        self.assertEqual((r['verdict'], r['error']), ('error', 'Invalid API key'))

    def test_rate_limited_429(self):
        r, _ = self.check(side_effect=_http_error(429))
        self.assertEqual(r['verdict'], 'error')
        self.assertIn('Rate limit', r['error'])

    def test_network_failure(self):
        r, _ = self.check(side_effect=urllib.error.URLError('no route'))
        self.assertEqual(r['verdict'], 'error')

    def test_malformed_json(self):
        bad = mock.MagicMock()
        bad.read.return_value = b'{"data": {}}'
        bad.__enter__.return_value = bad
        r, _ = self.check(return_value=bad)
        self.assertEqual(r['verdict'], 'error')


class TestCheckAll(unittest.TestCase):
    def hashes(self, n):
        return [FileHashes(f'/f{i}', '', '', f'{i:064x}', 1) for i in range(n)]

    def test_rate_limit_between_requests_only(self):
        with mock.patch.object(vt, 'check_hash', return_value={
                'malicious': 0, 'suspicious': 0, 'undetected': 1, 'total': 1,
                'verdict': 'clean', 'permalink': '', 'error': ''}) as ch, \
             mock.patch('time.sleep') as sleep:
            results = vt.check_all(self.hashes(3), 'KEY')
        self.assertEqual(ch.call_count, 3)
        self.assertEqual([r.path for r in results], ['/f0', '/f1', '/f2'])
        # 16 one-second sleeps after each of the first two requests, none after the last
        self.assertEqual(sleep.call_count, 2 * vt.RATE_WAIT)
        self.assertGreaterEqual(vt.RATE_WAIT, 15)      # free tier: 4 requests / minute

    def test_cancel_stops_early(self):
        flag = threading.Event()

        def fake(_sha, _key):
            flag.set()
            return {'malicious': 0, 'suspicious': 0, 'undetected': 0, 'total': 0,
                    'verdict': 'clean', 'permalink': '', 'error': ''}
        with mock.patch.object(vt, 'check_hash', side_effect=fake), \
             mock.patch('time.sleep') as sleep:
            results = vt.check_all(self.hashes(5), 'KEY', cancel_flag=flag)
        self.assertEqual(len(results), 1)
        self.assertEqual(sleep.call_count, 0)

    def test_progress_callback(self):
        seen = []
        with mock.patch.object(vt, 'check_hash', return_value={
                'malicious': 0, 'suspicious': 0, 'undetected': 0, 'total': 0,
                'verdict': 'unknown', 'permalink': '', 'error': 'x'}), \
             mock.patch('time.sleep'):
            vt.check_all(self.hashes(2), 'KEY',
                         progress_cb=lambda d, t, p: seen.append((d, t, p)))
        self.assertEqual(seen, [(1, 2, '/f0'), (2, 2, '/f1')])


if __name__ == '__main__':
    unittest.main()
