"""Regression tests for time-zone-safe independent-reference comparison.

These mock timestamps test the comparator implementation; they are NOT
independent $MFT benchmarking evidence.
"""
import unittest
from evaluation.compare_mftecmd import _time


class ReferenceTimestampParsingTests(unittest.TestCase):
    def test_utc_seven_fractional_digits(self):
        self.assertEqual(_time('2022-01-01 10:00:00.3000007Z'),
                         '2022-01-01T10:00:00.300000')

    def test_positive_timezone_offset_is_not_mistaken_for_microseconds(self):
        self.assertEqual(_time('2022-01-01 10:00:00.3000007+05:30'),
                         '2022-01-01T04:30:00.300000')

    def test_negative_timezone_offset(self):
        self.assertEqual(_time('2022-01-01 10:00:00.3000007-04:00'),
                         '2022-01-01T14:00:00.300000')

    def test_empty_mftecmd_sentinel(self):
        self.assertIsNone(_time(''))
        self.assertIsNone(_time('1601-01-01 00:00:00.0000000'))

    def test_invalid_reference_must_fail(self):
        with self.assertRaises(ValueError):
            _time('2026-not-a-date')

if __name__ == '__main__': unittest.main()
