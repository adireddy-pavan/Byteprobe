"""Tests for core/timeline.py — $SI vs $FN timestomping detection."""

import datetime
import unittest

from core import mft, timeline
from core.metadata import FileMetadata
from tests import ntfs_builder as nb

# A normal file: $SI and $FN written together by the kernel at creation,
# $SI updated later by ordinary edits. Full 100 ns precision everywhere.
CREATE = nb.filetime(2024, 5, 10, 14, 3, 27, ticks=4819203)
EDIT   = nb.filetime(2024, 6, 1, 9, 12, 5, ticks=1100457)
READ   = nb.filetime(2024, 6, 2, 8, 0, 1, ticks=9920001)


def record(si, fn, in_use=True, name='file.txt'):
    raw = nb.make_record(64, [nb.si_attr(*si),
                              nb.fn_attr(name, 5, fn, parent_seq=5)], in_use=in_use)
    recs = {5: mft.parse_record(nb.make_record(5, [nb.fn_attr('.', 5, [CREATE] * 4, 5)],
                                               directory=True, sequence=5), 5),
            64: mft.parse_record(raw, 64)}
    mft.build_paths(recs)
    return recs[64]


class TestCheckSiFn(unittest.TestCase):
    def test_normal_file_is_clean(self):
        r = record(si=[CREATE, EDIT, EDIT, READ], fn=[CREATE] * 4)
        self.assertEqual(timeline.check_si_fn(r), [])

    def test_backdated_created_detected(self):
        # SetFileTime-style backdating: $SI created moved 3 years earlier
        stomped = nb.filetime(2021, 1, 1, 12, 0, 0, ticks=4819203)
        r = record(si=[stomped, EDIT, EDIT, READ], fn=[CREATE] * 4)
        findings = timeline.check_si_fn(r)
        self.assertEqual(len(findings), 1)
        self.assertIn('$SI Created earlier than $FN Created', findings[0])

    def test_backdated_mft_changed_detected(self):
        stomped = nb.filetime(2020, 1, 1, ticks=77)
        r = record(si=[CREATE, EDIT, stomped, READ], fn=[CREATE] * 4)
        self.assertIn('MFT-changed', timeline.check_si_fn(r)[0])

    def test_zeroed_subsecond_created_detected(self):
        # Whole-second tool: correct date, but the 100 ns digits are lost
        whole = CREATE - CREATE % nb.TICKS + nb.TICKS    # just after $FN, so not earlier
        r = record(si=[whole, EDIT, EDIT, READ], fn=[CREATE] * 4)
        self.assertEqual(timeline.check_si_fn(r),
                         ['$SI Created has zero sub-second precision; $FN Created does not'])

    def test_all_four_zeroed_reported_once(self):
        whole = [nb.filetime(2025, 1, 1, 10, 0, s) for s in range(4)]
        r = record(si=whole, fn=[CREATE] * 4)
        findings = timeline.check_si_fn(r)
        self.assertEqual(findings,
                         ['All four $SI timestamps have zero sub-second precision; $FN does not'])

    def test_classic_timestomp_triggers_both_rules(self):
        whole = [nb.filetime(2019, 3, 3, 3, 3, 3)] * 4
        r = record(si=whole, fn=[CREATE] * 4)
        self.assertEqual(len(timeline.check_si_fn(r)), 3)   # created, mft_changed, precision

    def test_copied_file_not_flagged(self):
        # Copy/extract preserves the OLD modified time in $SI while $FN gets
        # the copy time. That is normal, so modified is deliberately not compared.
        old_modified = nb.filetime(2015, 8, 8, 8, 8, 8, ticks=5550001)
        r = record(si=[CREATE, old_modified, CREATE, CREATE], fn=[CREATE] * 4)
        self.assertEqual(timeline.check_si_fn(r), [])

    def test_whole_second_fn_is_not_a_precision_finding(self):
        whole = nb.filetime(2024, 5, 10, 14, 3, 27)
        r = record(si=[whole, EDIT, EDIT, READ], fn=[whole] * 4)
        self.assertEqual(timeline.check_si_fn(r), [])

    def test_tolerance(self):
        r = record(si=[CREATE - 5 * nb.TICKS, EDIT, EDIT, READ], fn=[CREATE] * 4)
        self.assertEqual(len(timeline.check_si_fn(r)), 1)
        self.assertEqual(timeline.check_si_fn(r, tolerance_seconds=10), [])

    def test_missing_attributes(self):
        raw = nb.make_record(70, [nb.data_attr(b'x', name='ads')])
        self.assertEqual(timeline.check_si_fn(mft.parse_record(raw, 70)), [])


class TestFindSiFnAnomalies(unittest.TestCase):
    def test_report_rows(self):
        clean = record(si=[CREATE, EDIT, EDIT, READ], fn=[CREATE] * 4)
        stomp = record(si=[nb.filetime(2019, 3, 3, 3, 3, 3)] * 4, fn=[CREATE] * 4,
                       in_use=False, name='evil.exe')
        rows = timeline.find_si_fn_anomalies([clean, stomp])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['path'], '\\evil.exe')
        self.assertFalse(row['in_use'])
        self.assertEqual(row['si_created'], '2019-03-03 03:03:03.000')
        self.assertEqual(row['fn_created'], '2024-05-10 14:03:27.481')
        self.assertEqual(timeline.find_si_fn_anomalies([clean, stomp], include_deleted=False), [])


class TestConfidence(unittest.TestCase):
    BUILD = nb.filetime(2006, 2, 28, 12)       # installer's whole-second build time

    def test_millisecond_creation_jitter_ignored_by_default(self):
        r = record(si=[CREATE, EDIT, CREATE - 100_000, READ], fn=[CREATE] * 4)   # 10 ms
        self.assertEqual(timeline.check_si_fn(r), [])
        self.assertEqual(len(timeline.check_si_fn(r, tolerance_seconds=0)), 1)

    def test_bulk_installer_pattern_is_low_confidence(self):
        recs = [record(si=[self.BUILD, self.BUILD, EDIT, READ], fn=[CREATE] * 4)
                for _ in range(timeline.BULK_THRESHOLD)]
        rows = timeline.find_si_fn_anomalies(recs)
        self.assertEqual(len(rows), timeline.BULK_THRESHOLD)
        self.assertTrue(all(r['confidence'] == 'low' for r in rows))
        self.assertEqual(rows[0]['shared_by'], timeline.BULK_THRESHOLD)
        self.assertIn('installer/bulk pattern', rows[0]['note'])

    def test_unique_backdate_among_bulk_files_is_high(self):
        bulk = [record(si=[self.BUILD, self.BUILD, EDIT, READ], fn=[CREATE] * 4)
                for _ in range(10)]
        stomp = record(si=[nb.filetime(2019, 3, 3, 3, 3, 3)] * 4, fn=[CREATE] * 4,
                       name='evil.exe')
        rows = {r['path']: r for r in timeline.find_si_fn_anomalies(bulk + [stomp])}
        self.assertEqual(rows['\\evil.exe']['confidence'], 'high')

    def test_below_threshold_is_high(self):
        recs = [record(si=[self.BUILD, self.BUILD, EDIT, READ], fn=[CREATE] * 4)
                for _ in range(timeline.BULK_THRESHOLD - 1)]
        self.assertTrue(all(r['confidence'] == 'high'
                            for r in timeline.find_si_fn_anomalies(recs)))


class TestOsStatHeuristic(unittest.TestCase):
    def _meta(self, created, modified):
        return FileMetadata(path='/x', name='x', size=0, created=created, modified=modified,
                            accessed=modified, is_hidden=False, is_system=False,
                            is_readonly=False, is_archive=False, owner='', extension='',
                            attributes=0)

    def test_modified_before_created(self):
        d = datetime.datetime
        rows = timeline.find_timestamp_anomalies([
            self._meta(d(2024, 1, 2), d(2024, 1, 1)),
            self._meta(d(2024, 1, 1), d(2024, 1, 2)),
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['delta'], '1 day, 0:00:00')
        self.assertIn('low confidence', rows[0]['note'])


if __name__ == '__main__':
    unittest.main()
