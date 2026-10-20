"""Tests for core/hasher.py.

Expected digests are the published test vectors: RFC 1321 (MD5) and
FIPS 180-2 Appendix A/B (SHA-1, SHA-256), so the hashing engine is checked
against an external reference, not just against hashlib itself.
"""

import hashlib
import os
import tempfile
import unittest

from core import hasher

VECTORS = {
    b'': ('d41d8cd98f00b204e9800998ecf8427e',
          'da39a3ee5e6b4b0d3255bfef95601890afd80709',
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    b'abc': ('900150983cd24fb0d6963f7d28e17f72',
             'a9993e364706816aba3e25717850c26c9cd0d89d',
             'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    b'message digest': ('f96b697d7cb7938d525a2f31aaf161d0', None, None),
    b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq': (
        None,
        '84983e441c3bd26ebaae4aa1f95129e5e54670f1',
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'),
}


class HasherTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data):
        path = os.path.join(self.tmp.name, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path


class TestKnownVectors(HasherTestCase):
    def test_published_vectors(self):
        for i, (data, (md5, sha1, sha256)) in enumerate(VECTORS.items()):
            with self.subTest(data=data):
                fh = hasher.compute_hashes(self.write(f'v{i}', data))
                self.assertEqual(fh.size, len(data))
                if md5:
                    self.assertEqual(fh.md5, md5)
                if sha1:
                    self.assertEqual(fh.sha1, sha1)
                if sha256:
                    self.assertEqual(fh.sha256, sha256)

    def test_million_a(self):
        # FIPS 180-2 long-message vector — spans many 64 KB read chunks
        fh = hasher.compute_hashes(self.write('a', b'a' * 1_000_000))
        self.assertEqual(fh.sha1, '34aa973cd4c4daa4f61eeb2bdbad27316534016f')
        self.assertEqual(fh.sha256,
                         'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')


class TestChunking(HasherTestCase):
    def test_chunk_boundaries(self):
        # Sizes around the 64 KB buffer must hash identically to one-shot hashing
        for size in (hasher.CHUNK - 1, hasher.CHUNK, hasher.CHUNK + 1, 3 * hasher.CHUNK + 7):
            with self.subTest(size=size):
                data = os.urandom(size)
                fh = hasher.compute_hashes(self.write(f's{size}', data))
                self.assertEqual(fh.sha256, hashlib.sha256(data).hexdigest())
                self.assertEqual(fh.md5, hashlib.md5(data).hexdigest())

    def test_progress_reports_bytes_read(self):
        seen = []
        hasher.compute_hashes(self.write('p', bytes(2 * hasher.CHUNK + 10)), seen.append)
        self.assertEqual(seen, [hasher.CHUNK, 2 * hasher.CHUNK, 2 * hasher.CHUNK + 10])

    def test_hashing_does_not_modify_file(self):
        path = self.write('evidence.bin', b'evidence')
        before = os.stat(path)
        hasher.compute_hashes(path)
        after = os.stat(path)
        self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))


class TestProperties(HasherTestCase):
    """The properties that make hashes useful as forensic evidence."""

    def test_deterministic(self):
        path = self.write('d', os.urandom(5000))
        self.assertEqual(hasher.compute_hashes(path), hasher.compute_hashes(path))

    def test_avalanche_one_bit_change(self):
        data = bytearray(os.urandom(4096))
        a = hasher.compute_hashes(self.write('a', bytes(data)))
        data[100] ^= 0x01
        b = hasher.compute_hashes(self.write('b', bytes(data)))
        diff = bin(int(a.sha256, 16) ^ int(b.sha256, 16)).count('1')
        # Expected ~128 of 256 bits; far outside 64..192 would indicate a bug
        self.assertTrue(64 < diff < 192, diff)

    def test_digest_lengths(self):
        fh = hasher.compute_hashes(self.write('l', b'x'))
        self.assertEqual((len(fh.md5), len(fh.sha1), len(fh.sha256)), (32, 40, 64))


class TestHashSets(HasherTestCase):
    def test_duplicates_found(self):
        a = self.write('a', b'same')
        b = self.write('b', b'same')
        c = self.write('c', b'different')
        dups = hasher.find_duplicates(hasher.hash_all([a, b, c]))
        self.assertEqual(list(dups.values()), [[a, b]])

    def test_hashset_match_md5_or_sha256_case_insensitive(self):
        a = self.write('a', b'abc')
        b = self.write('b', b'')
        c = self.write('c', b'clean')
        hs = self.write('set.txt',
                        b'900150983CD24FB0D6963F7D28E17F72\n\n'
                        b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n')
        matches = hasher.match_against_hashset(hasher.hash_all([a, b, c]),
                                               hasher.load_hashset(hs))
        self.assertEqual(sorted(m.path for m in matches), [a, b])

    def test_unreadable_file_skipped(self):
        ok = self.write('ok', b'1')
        results = hasher.hash_all([ok, os.path.join(self.tmp.name, 'missing')])
        self.assertEqual([r.path for r in results], [ok])

    def test_unreadable_file_is_logged(self):
        missing = os.path.join(self.tmp.name, 'missing')
        with self.assertLogs('core.hasher', level='WARNING') as cm:
            hasher.hash_all([missing])
        self.assertIn(missing, cm.output[0])


if __name__ == '__main__':
    unittest.main()


class HashDatabaseTests(unittest.TestCase):
    """NSRL-style hash sets: CSV parsing, SHA-1 matching, known-good vs known-bad."""

    def setUp(self):
        import tempfile, os
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.dir = self.d.name
        self.f1 = os.path.join(self.dir, 'a.bin')
        self.f2 = os.path.join(self.dir, 'b.bin')
        with open(self.f1, 'wb') as f:
            f.write(b'known file')
        with open(self.f2, 'wb') as f:
            f.write(b'other file')
        self.h = hasher.hash_all([self.f1, self.f2])

    def _write(self, name, text):
        import os
        p = os.path.join(self.dir, name)
        with open(p, 'w') as f:
            f.write(text)
        return p

    def test_nsrl_csv_matches_on_sha1(self):
        # classic NSRLFile.txt layout: SHA-1 first, then MD5
        p = self._write('NSRLFile.txt',
                        '"SHA-1","MD5","CRC32","FileName"\n'
                        f'"{self.h[0].sha1.upper()}","{"0" * 32}","00000000","a.bin"\n')
        db = hasher.load_hash_database(p)
        self.addCleanup(db.close)
        self.assertEqual(db.kind, hasher.KNOWN_GOOD)
        matches = hasher.match_against_hashset(self.h, db)
        self.assertEqual([m.path for m in matches], [self.f1])

    def test_plain_list_defaults_to_known_bad(self):
        p = self._write('badlist.txt', self.h[1].sha256 + '\n')
        db = hasher.load_hash_database(p)
        self.addCleanup(db.close)
        self.assertEqual(db.kind, hasher.KNOWN_BAD)
        self.assertEqual([m.path for m in hasher.match_against_hashset(self.h, db)], [self.f2])

    def test_sqlite_rds_is_queried_not_loaded(self):
        import sqlite3, os
        p = os.path.join(self.dir, 'RDS.db')
        c = sqlite3.connect(p)
        c.execute('CREATE TABLE FILE (sha256 TEXT, sha1 TEXT, md5 TEXT, file_name TEXT)')
        c.execute('INSERT INTO FILE VALUES (?,?,?,?)',
                  ('X' * 64, self.h[0].sha1.upper(), 'Y' * 32, 'a.bin'))
        c.commit(); c.close()
        db = hasher.load_hash_database(p)
        self.addCleanup(db.close)
        self.assertEqual(db.kind, hasher.KNOWN_GOOD)
        self.assertEqual(len(db), 1)
        self.assertEqual([m.path for m in hasher.match_against_hashset(self.h, db)], [self.f1])

    def test_duplicates_keyed_by_sha256(self):
        import os
        c = os.path.join(self.dir, 'c.bin')
        with open(c, 'wb') as f:
            f.write(b'known file')
        dups = hasher.find_duplicates(hasher.hash_all([self.f1, self.f2, c]))
        self.assertEqual(list(dups), [self.h[0].sha256])
        self.assertEqual(sorted(dups[self.h[0].sha256]), sorted([self.f1, c]))
