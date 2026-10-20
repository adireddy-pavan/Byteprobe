"""Tests for core/entropy.py — Shannon entropy H = -Σ p(x)·log2 p(x).

Byte entropy ranges from 0 bits (one repeated value) to 8 bits (all 256
values equally likely). Most cases below have exact analytical answers.
"""

import os
import random
import tempfile
import unittest
import zlib

from core import entropy


class EntropyTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def measure(self, data: bytes, name='f'):
        path = os.path.join(self.tmp.name, name)
        with open(path, 'wb') as f:
            f.write(data)
        return entropy.compute_entropy(path)


class TestExactValues(EntropyTestCase):
    def test_single_symbol_is_zero(self):
        self.assertEqual(self.measure(b'A' * 10_000).entropy, 0.0)

    def test_two_equiprobable_symbols_is_one_bit(self):
        self.assertEqual(self.measure(b'AB' * 5_000).entropy, 1.0)

    def test_sixteen_symbols_is_four_bits(self):
        self.assertEqual(self.measure(bytes(range(16)) * 1000).entropy, 4.0)

    def test_all_256_values_is_maximum(self):
        self.assertEqual(self.measure(bytes(range(256)) * 100).entropy, 8.0)

    def test_skewed_distribution(self):
        # p = 3/4, 1/4 -> H = 0.8113 bits
        self.assertAlmostEqual(self.measure(b'AAAB' * 2500).entropy, 0.8113, places=4)

    def test_order_does_not_matter(self):
        data = bytearray(os.urandom(20_000))
        shuffled = bytearray(data)
        random.Random(1).shuffle(shuffled)
        self.assertEqual(self.measure(bytes(data), 'a').entropy,
                         self.measure(bytes(shuffled), 'b').entropy)

    def test_counts_span_read_chunks(self):
        # Half 'A' in the first 64 KB chunk, half 'B' in the second
        data = b'A' * entropy.CHUNK + b'B' * entropy.CHUNK
        self.assertEqual(self.measure(data).entropy, 1.0)


class TestClassification(EntropyTestCase):
    def test_random_data_flagged(self):
        r = self.measure(os.urandom(256 * 1024))
        self.assertGreater(r.entropy, 7.99)
        self.assertTrue(r.is_high_entropy)

    def test_compressed_prose_flagged(self):
        rnd = random.Random(7)
        words = [bytes(rnd.choice(b'etaoinshrdlucmfwyp') for _ in range(rnd.randint(2, 9)))
                 for _ in range(3000)]
        prose = b' '.join(rnd.choice(words) for _ in range(40000))
        self.assertTrue(self.measure(zlib.compress(prose, 9)).is_high_entropy)

    def test_known_false_negative_highly_redundant_input(self):
        # DOCUMENTED LIMITATION: zlib output of very repetitive input keeps
        # visible structure (~6.9 bits) and falls below the 7.2 threshold.
        text = ' '.join(f'record {i} value {i * 7919 % 1000}' for i in range(20000)).encode()
        r = self.measure(zlib.compress(text, 9))
        self.assertTrue(6.5 < r.entropy < 7.2, r.entropy)
        self.assertFalse(r.is_high_entropy)

    def test_small_files_cannot_reach_threshold(self):
        # DOCUMENTED LIMITATION: n bytes hold at most n distinct values, so
        # H <= log2(n). Below 148 bytes even perfectly random data is missed.
        r = self.measure(os.urandom(100))
        self.assertLessEqual(r.entropy, 6.644)          # log2(100)
        self.assertFalse(r.is_high_entropy)

    def test_english_text_not_flagged(self):
        text = (b'The examiner recorded the hash value of every file before analysis '
                b'so that later copies could be verified against the original evidence. ') * 200
        r = self.measure(text)
        self.assertTrue(3.5 < r.entropy < 5.0, r.entropy)
        self.assertFalse(r.is_high_entropy)

    def test_threshold_is_strictly_greater_than_7_2(self):
        # 147 equiprobable symbols -> log2(147) = 7.1997 (just under the threshold)
        self.assertFalse(self.measure(bytes(range(147)) * 100).is_high_entropy)
        # 148 -> log2(148) = 7.2095
        self.assertTrue(self.measure(bytes(range(148)) * 100).is_high_entropy)


class TestEdgeCases(EntropyTestCase):
    def test_empty_file(self):
        r = self.measure(b'')
        self.assertEqual((r.entropy, r.is_high_entropy, r.note), (0.0, False, 'Empty file'))

    def test_unreadable_file(self):
        r = entropy.compute_entropy(os.path.join(self.tmp.name, 'missing'))
        self.assertEqual(r.note, 'Could not read file')

    def test_analyze_all_progress(self):
        paths = []
        for i in range(3):
            p = os.path.join(self.tmp.name, f'{i}')
            with open(p, 'wb') as f:
                f.write(b'x')
            paths.append(p)
        seen = []
        results = entropy.analyze_all(paths, progress_cb=seen.append)
        self.assertEqual(seen, paths)
        self.assertEqual(len(results), 3)


if __name__ == '__main__':
    unittest.main()


class BlockEntropyTests(unittest.TestCase):
    def _res(self, data):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'f.bin')
            with open(p, 'wb') as f:
                f.write(data)
            return entropy.compute_entropy(p)

    def test_hidden_random_section_is_found_in_low_entropy_file(self):
        import random
        rnd = random.Random(1)
        data = b'A' * 200_000 + bytes(rnd.randrange(256) for _ in range(40_000)) + b'A' * 200_000
        r = self._res(data)
        self.assertFalse(r.is_high_entropy)          # whole file looks normal
        self.assertTrue(r.has_high_entropy_region)   # but a region is not
        self.assertGreater(r.max_block_entropy, 7.5)

    def test_plain_text_has_no_region(self):
        r = self._res(b'hello world ' * 50_000)
        self.assertFalse(r.has_high_entropy_region)
        self.assertEqual(r.high_blocks, 0)
