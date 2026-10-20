"""Regression tests for new scientific comparison/stress-test scripts.

Using a deliberately generated *mock* reference CSV validates comparison code
only. It is NOT a true external-tool benchmark.
"""
import csv
import tempfile
import unittest
from pathlib import Path

from evaluation.compare_mftecmd import compare
from evaluation.evaluate_controlled_timestamps import build_fixture, evaluate, wilson
from tests import ntfs_builder as nb


class TestIndependentComparisonHarness(unittest.TestCase):
    def test_identical_and_disagreeing_reference_fields(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            ts = nb.filetime(2022, 1, 1, 10, 0, 0, ticks=3_000_000)
            raw = nb.make_record(0, [nb.si_attr(*[ts]*4), nb.fn_attr('a.txt', 5, [ts]*4)])
            mft_path = td/'MFT'; mft_path.write_bytes(raw)
            csv_path = td/'ref.csv'
            with csv_path.open('w', newline='', encoding='utf-8') as f:
                w = csv.DictWriter(f, fieldnames=['EntryNumber', 'SequenceNumber', 'InUse', 'IsDirectory',
                            'Created0x10', 'Created0x30', 'LastModified0x10'])
                w.writeheader()
                w.writerow(dict(EntryNumber=0, SequenceNumber=1, InUse='True', IsDirectory='False',
                                Created0x10='2022-01-01 10:00:00.3000000',
                                Created0x30='2020-01-01 10:00:00.3000000',
                                LastModified0x10='2022-01-01 10:00:00.3000000'))
            result = compare(mft_path, csv_path, td/'out')
            self.assertEqual(result['common_record_keys'], 1)
            self.assertEqual(result['fields']['created_si']['agree'], 1)
            self.assertEqual(result['fields']['created_fn']['disagree'], 1)
            self.assertEqual(result['fields']['modified_si']['agree'], 1)
            self.assertTrue((td/'out'/'discrepancies.csv').exists())
            self.assertTrue((td/'out'/'summary.json').exists())

    def test_duplicate_reference_key_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            ts = nb.filetime(2022, 1, 1)
            mft_path = td/'MFT'
            mft_path.write_bytes(nb.make_record(0, [nb.si_attr(*[ts]*4), nb.fn_attr('a', 5, [ts]*4)]))
            csv_path = td/'ref.csv'
            with csv_path.open('w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=['EntryNumber', 'SequenceNumber', 'InUse', 'IsDirectory'])
                w.writeheader()
                for _ in range(2):
                    w.writerow(dict(EntryNumber=0, SequenceNumber=1, InUse='True', IsDirectory='False'))
            summary = compare(mft_path, csv_path, td/'out')
            self.assertEqual(summary['ambiguous_reference_keys'], 1)
            self.assertEqual(summary['fields']['in_use']['excluded'], 1)


class TestControlledStressTest(unittest.TestCase):
    def test_expected_limits_and_benign_confusion(self):
        records, rows = build_fixture()
        counts, _ = evaluate(records, rows, 2, 5)
        self.assertEqual(len(records), 640)
        self.assertEqual(counts['A']['high'], 80)
        self.assertEqual(counts['B']['high'], 80)
        self.assertEqual([counts[k]['high'] for k in 'CDE'], [0, 0, 0])
        self.assertEqual(counts['F']['high'], 20)
        self.assertEqual(counts['benign_unique_old_created']['high'], 40)
        self.assertEqual(counts['benign_bulk_installer']['high'], 0)

    def test_threshold_tradeoff(self):
        recs, rows = build_fixture()
        a, _ = evaluate(recs, rows, 2, 5)
        b, _ = evaluate(recs, rows, 2, 10)
        self.assertLess(a['F']['high'], b['F']['high'])
        self.assertLess(a['benign_bulk_installer']['high'],
                        b['benign_bulk_installer']['high'])

    def test_wilson_is_bounded(self):
        self.assertEqual(wilson(0, 0), (0.0, 0.0))
        for successes in (0, 5, 10):
            lo, hi = wilson(successes, 10)
            self.assertTrue(0 <= lo <= hi <= 1)


if __name__ == '__main__': unittest.main()
