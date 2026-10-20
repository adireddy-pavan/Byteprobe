"""Tests for core/mft.py — NTFS $MFT parsing."""

import datetime
import os
import tempfile
import unittest

from core import mft
from tests import ntfs_builder as nb

DATA = os.path.join(os.path.dirname(__file__), 'data')
UTC = datetime.timezone.utc

T_2020 = nb.filetime(2020, 3, 1, 9, 30, 15, ticks=1234567)
T_2021 = nb.filetime(2021, 6, 2, 10, 0, 0, ticks=7654321)


def _file(number, name, parent=5, si=None, fn=None, extra=(), **kw):
    si = si or [T_2021] * 4
    fn = fn or [T_2021] * 4
    parent_seq = 5 if parent == 5 else 1       # the root directory has sequence 5
    return nb.make_record(number, [nb.si_attr(*si), nb.fn_attr(name, parent, fn, parent_seq),
                                   *extra], **kw)


def _dir(number, name, parent=5):
    return _file(number, name, parent, directory=True)


def _root():
    return nb.make_record(5, [nb.si_attr(*[T_2020] * 4),
                              nb.fn_attr('.', 5, [T_2020] * 4, parent_seq=5, namespace=3)],
                          directory=True, sequence=5)


class TestFiletime(unittest.TestCase):
    def test_unix_epoch(self):
        self.assertEqual(mft.filetime_to_datetime(116444736000000000),
                         datetime.datetime(1970, 1, 1, tzinfo=UTC))

    def test_zero_is_none(self):
        self.assertIsNone(mft.filetime_to_datetime(0))

    def test_subsecond_ticks_kept(self):
        ts = mft.NTFSTimestamps(T_2020, T_2020, T_2020, T_2020)
        self.assertEqual(ts.subsecond_ticks('created'), 1234567)
        self.assertFalse(ts.has_zero_subsecond('created'))
        whole = mft.NTFSTimestamps(nb.filetime(2020, 1, 1), 0, 0, 0)
        self.assertTrue(whole.has_zero_subsecond('created'))
        self.assertFalse(whole.has_zero_subsecond('modified'))   # 0 = unset, not zeroed


class TestRunlist(unittest.TestCase):
    def test_single_run(self):
        # header 0x21: 1-byte length, 2-byte offset -> 16 clusters at LCN 256
        self.assertEqual(mft.decode_runlist(bytes([0x21, 0x10, 0x00, 0x01, 0x00])),
                         [(256, 16)])

    def test_negative_relative_offset(self):
        data = bytes([0x11, 0x08, 0x40, 0x11, 0x04, 0xF6, 0x00])   # +64, then -10
        self.assertEqual(mft.decode_runlist(data), [(64, 8), (54, 4)])

    def test_sparse_run(self):
        data = bytes([0x01, 0x20, 0x11, 0x02, 0x10, 0x00])
        self.assertEqual(mft.decode_runlist(data), [(None, 32), (16, 2)])

    def test_builder_roundtrip(self):
        runs = [(100000, 300), (12, 1), (None, 7), (5000000, 70000)]
        self.assertEqual(mft.decode_runlist(nb.encode_runlist(runs)), runs)

    def test_truncated_runlist_raises(self):
        with self.assertRaises(mft.MFTError):
            mft.decode_runlist(bytes([0x31, 0x01, 0x00]))


class TestFixup(unittest.TestCase):
    def test_protected_bytes_restored(self):
        rec = mft.parse_record(_file(40, 'a.txt'), 40)
        self.assertTrue(rec.fixup_ok)
        self.assertEqual(rec.name, 'a.txt')

    def test_torn_sector_detected(self):
        raw = bytearray(_file(40, 'a.txt'))
        raw[1022:1024] = b'\x99\x99'            # second sector never written
        rec = mft.parse_record(bytes(raw), 40)
        self.assertFalse(rec.fixup_ok)

    def test_4096_byte_records(self):
        rec = mft.parse_record(_file(7, 'big.bin', size=4096), 7)
        self.assertTrue(rec.fixup_ok)
        self.assertEqual(rec.name, 'big.bin')


class TestParseRecord(unittest.TestCase):
    def test_non_file_slots_ignored(self):
        self.assertIsNone(mft.parse_record(bytes(1024)))
        self.assertIsNone(mft.parse_record(b'BAAD' + bytes(1020)))

    def test_si_and_fn_timestamps_are_separate(self):
        si = [T_2020, T_2020 + 1, T_2020 + 2, T_2020 + 3]
        fn = [T_2021, T_2021 + 10, T_2021 + 20, T_2021 + 30]
        rec = mft.parse_record(_file(41, 'x.doc', si=si, fn=fn), 41)
        self.assertEqual([rec.si.created, rec.si.modified, rec.si.mft_changed,
                          rec.si.accessed], si)
        t = rec.fn.timestamps
        self.assertEqual([t.created, t.modified, t.mft_changed, t.accessed], fn)

    def test_flags_and_header(self):
        rec = mft.parse_record(_file(42, 'gone.txt', in_use=False, sequence=9), 42)
        self.assertFalse(rec.in_use)
        self.assertFalse(rec.is_directory)
        self.assertEqual(rec.sequence, 9)
        self.assertTrue(mft.parse_record(_dir(43, 'Users'), 43).is_directory)

    def test_record_number_read_from_header(self):
        self.assertEqual(mft.parse_record(_file(1234, 'n.txt')).record_number, 1234)

    def test_win32_name_preferred_over_dos(self):
        raw = nb.make_record(44, [
            nb.si_attr(*[T_2020] * 4),
            nb.fn_attr('LONGFI~1.TXT', 5, [T_2020] * 4, namespace=2),
            nb.fn_attr('long file name.txt', 5, [T_2020] * 4, namespace=1),
        ])
        rec = mft.parse_record(raw, 44)
        self.assertEqual(len(rec.file_names), 2)
        self.assertEqual(rec.name, 'long file name.txt')

    def test_resident_ads(self):
        raw = _file(45, 'invoice.pdf', extra=[
            nb.data_attr(b'%PDF-1.7 ...'),
            nb.data_attr(b'[ZoneTransfer]\r\nZoneId=3\r\n', name='Zone.Identifier'),
            nb.data_attr(b'MZ' + bytes(100), name='payload.exe'),
        ])
        rec = mft.parse_record(raw, 45)
        self.assertEqual(rec.data_size, 12)
        self.assertEqual([(a.name, a.size) for a in rec.ads],
                         [('Zone.Identifier', 26), ('payload.exe', 102)])

    def test_non_resident_ads_size(self):
        raw = _file(46, 'host.txt', extra=[
            nb.data_attr(b'hello'),
            nb.nonresident_attr(0x80, nb.encode_runlist([(900, 3)]), 10_000_000,
                                name='hidden', clusters=3),
        ])
        ads = mft.parse_record(raw, 46).ads
        self.assertEqual(len(ads), 1)
        self.assertEqual((ads[0].name, ads[0].size, ads[0].resident),
                         ('hidden', 10_000_000, False))
        self.assertEqual(ads[0].runs, [(900, 3)])


class TestRealRecords(unittest.TestCase):
    """Records captured from real Windows volumes; expected values were
    cross-checked with the independent `mft` crate (see tests/data/README.md)."""

    def _load(self, name):
        with open(os.path.join(DATA, name), 'rb') as f:
            return mft.parse_record(f.read(), 0)

    def test_single_file(self):
        rec = self._load('entry_single_file')
        self.assertTrue(rec.fixup_ok)
        self.assertTrue(rec.in_use)
        self.assertEqual(rec.name, 'test_cfuncs.py')
        self.assertEqual(sorted(f.name for f in rec.file_names),
                         ['TEST_C~3.PY', 'test_cfuncs.py'])
        self.assertEqual(rec.fn.parent_record, 26359)
        self.assertEqual(rec.si.as_datetime('created'),
                         datetime.datetime(2008, 2, 29, 4, 12, 36, tzinfo=UTC))
        self.assertEqual(rec.si.as_datetime('mft_changed'),
                         datetime.datetime(2009, 11, 13, 1, 56, 44, tzinfo=UTC))
        self.assertEqual(rec.fn.timestamps.as_datetime('created'),
                         datetime.datetime(2009, 11, 13, 1, 56, 44, tzinfo=UTC))
        self.assertEqual(rec.data_size, 8072)
        self.assertEqual(rec.ads, [])

    def test_torn_real_record(self):
        rec = self._load('entry_102130_fixup_issue')
        self.assertFalse(rec.fixup_ok)
        self.assertTrue(rec.is_directory)
        self.assertEqual(rec.name, 'Application Data')
        self.assertEqual(rec.si.as_datetime('created'),
                         datetime.datetime(2018, 1, 2, 23, 36, 7, 186655, tzinfo=UTC))
        self.assertEqual(rec.fn.timestamps.as_datetime('created'),
                         datetime.datetime(2018, 1, 12, 13, 47, 19, 174318, tzinfo=UTC))

    def test_usnjrnl_extension_record(self):
        rec = self._load('entry_data_run_at_offset')
        self.assertEqual(rec.base_record, 57676)
        self.assertIsNone(rec.si)
        [j] = rec.ads
        self.assertEqual(j.name, '$J')
        self.assertEqual(j.size, 2152925272)
        self.assertEqual(j.runs[0], (None, 517248))      # sparse head of $J
        self.assertEqual(len(j.runs), 53)


class TestPaths(unittest.TestCase):
    def test_nested_paths_and_orphans(self):
        raws = [_root(), _dir(40, 'Users'), _dir(41, 'alice', parent=40),
                _file(42, 'notes.txt', parent=41),
                _file(43, 'lost.txt', parent=999)]              # parent missing
        records = {r.record_number: r for r in (mft.parse_record(x) for x in raws)}
        mft.build_paths(records)
        self.assertEqual(records[5].path, '\\')
        self.assertEqual(records[42].path, '\\Users\\alice\\notes.txt')
        self.assertEqual(records[43].path, mft.ORPHAN_PREFIX + '\\lost.txt')

    def test_reused_parent_slot_is_orphaned(self):
        raws = [_root(), _dir(40, 'NewDir'),                     # sequence 1
                nb.make_record(41, [nb.si_attr(*[T_2020] * 4),
                                    nb.fn_attr('old.txt', 40, [T_2020] * 4, parent_seq=7)],
                               in_use=False)]
        records = {r.record_number: r for r in (mft.parse_record(x) for x in raws)}
        mft.build_paths(records)
        self.assertEqual(records[41].path, mft.ORPHAN_PREFIX + '\\old.txt')

    def test_parent_cycle_does_not_hang(self):
        raws = [_dir(40, 'a', parent=41), _dir(41, 'b', parent=40)]
        records = {r.record_number: r for r in (mft.parse_record(x) for x in raws)}
        mft.build_paths(records)
        self.assertTrue(records[40].path.startswith(mft.ORPHAN_PREFIX))


def _sample_records():
    """Records 1..44 for volume tests: root, a dir, files, one with ADS."""
    recs = [None] * 44
    recs[4] = _root()
    recs[39] = _dir(40, 'Evidence')
    recs[40] = _file(41, 'report.docx', parent=40, extra=[nb.data_attr(b'PK\x03\x04')])
    recs[41] = _file(42, 'readme.txt', parent=40, extra=[
        nb.data_attr(b'hello'), nb.data_attr(b'secret', name='hidden.txt')])
    recs[42] = _file(43, 'deleted.tmp', parent=40, in_use=False)
    # Extension record 44 carries an ADS that belongs to base record 41
    recs[43] = nb.make_record(44, [nb.data_attr(b'x' * 50, name='overflow')], base=41)
    return recs


class TestSources(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, data):
        path = os.path.join(self.tmp.name, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    def _check(self, records):
        by_num = {r.record_number: r for r in records}
        self.assertEqual(by_num[41].path, '\\Evidence\\report.docx')
        self.assertEqual(by_num[42].path, '\\Evidence\\readme.txt')
        self.assertEqual([a.name for a in by_num[42].ads], ['hidden.txt'])
        self.assertFalse(by_num[43].in_use)
        self.assertEqual([a.name for a in by_num[41].ads], ['overflow'])   # merged
        self.assertNotIn(44, by_num)
        return by_num

    def test_extracted_mft_file(self):
        rec0 = nb.make_record(0, [nb.si_attr(*[T_2020] * 4),
                                  nb.fn_attr('$MFT', 5, [T_2020] * 4)])
        blob = rec0 + b''.join(r or bytes(1024) for r in _sample_records())
        self._check(mft.parse_mft(self._write('$MFT', blob)))

    def test_fragmented_volume_with_backwards_run(self):
        # 45 records = 12 clusters of 4 records; second fragment lies *before*
        # the first on disk, so the run list carries a negative offset.
        vol = nb.build_volume(_sample_records(), layout=[(30, 4), (10, 8)])
        records = mft.parse_mft(self._write('vol.raw', vol))
        by_num = self._check(records)
        self.assertEqual(by_num[0].path, '\\$MFT')

    def test_sparse_run_keeps_numbering(self):
        # Records 16..31 live in a sparse (unallocated) run and must be skipped
        # without shifting the numbers of the records after it.
        recs = _sample_records()
        for i in range(15, 31):
            recs[i] = None
        vol = nb.build_volume(recs, layout=[(20, 4), (None, 4), (40, 4)])
        self._check(mft.parse_mft(self._write('sparse.raw', vol)))

    def test_mbr_disk_image_autodetected(self):
        disk = nb.with_mbr(nb.build_volume(_sample_records(), layout=[(8, 12)]))
        self._check(mft.parse_mft(self._write('disk.dd', disk)))

    def test_gpt_disk_image_autodetected(self):
        disk = nb.with_gpt(nb.build_volume(_sample_records(), layout=[(8, 12)]))
        self._check(mft.parse_mft(self._write('gpt.dd', disk)))

    def test_explicit_offset(self):
        disk = nb.with_mbr(nb.build_volume(_sample_records(), layout=[(8, 12)]),
                           start_lba=63)
        self._check(mft.parse_mft(self._write('disk.dd', disk), volume_offset=63 * 512))

    def test_exclude_deleted(self):
        vol = nb.build_volume(_sample_records(), layout=[(8, 12)])
        records = mft.parse_mft(self._write('vol.raw', vol), include_deleted=False)
        self.assertTrue(all(r.in_use for r in records))

    def test_not_ntfs_raises(self):
        with self.assertRaises(mft.MFTError):
            mft.parse_mft(self._write('junk.bin', os.urandom(4096)))

    def test_missing_source_raises(self):
        with self.assertRaises(mft.MFTError):
            mft.parse_mft(os.path.join(self.tmp.name, 'nope.raw'))

    def test_source_opened_read_only(self):
        vol = nb.build_volume(_sample_records(), layout=[(8, 12)])
        path = self._write('vol.raw', vol)
        os.chmod(path, 0o444)
        mft.parse_mft(path)
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), vol)


class TestHelpers(unittest.TestCase):
    def test_normalise_live_volume(self):
        self.assertEqual(mft.normalise_source('c:'), '\\\\.\\C:')
        self.assertEqual(mft.normalise_source('D:\\'), '\\\\.\\D:')
        self.assertEqual(mft.normalise_source('/tmp/image.dd'), '/tmp/image.dd')

    def test_index_lookup_requires_matching_size(self):
        raws = [_root(), _dir(40, 'Users'),
                _file(41, 'a.txt', parent=40, extra=[nb.data_attr(b'12345')])]
        records = {r.record_number: r for r in (mft.parse_record(x) for x in raws)}
        mft.build_paths(records)
        index = mft.MFTIndex(list(records.values()))
        self.assertIs(index.lookup('E:\\Users\\A.TXT', size=5), records[41])
        self.assertIsNone(index.lookup('E:\\Users\\a.txt', size=6))
        # Mounted image scanned from its mount point on macOS/Linux
        self.assertIs(index.lookup('/Volumes/EVID/Users/a.txt', size=5,
                                   scan_root='/Volumes/EVID'), records[41])
        self.assertIsNone(index.lookup('/home/x/Users/a.txt', size=5,
                                       scan_root='/home/x/Users'))

    def test_index_lookup_through_symlinked_scan_root(self):
        # metadata.py stores resolved paths; the scan root may be a symlink
        raws = [_root(), _file(41, 'a.txt', extra=[nb.data_attr(b'12345')])]
        records = {r.record_number: r for r in (mft.parse_record(x) for x in raws)}
        mft.build_paths(records)
        index = mft.MFTIndex(list(records.values()))
        with tempfile.TemporaryDirectory() as real:
            link = real + '-link'
            os.symlink(real, link)
            try:
                resolved = os.path.join(os.path.realpath(real), 'a.txt')
                self.assertIs(index.lookup(resolved, size=5, scan_root=link), records[41])
            finally:
                os.unlink(link)


if __name__ == '__main__':
    unittest.main()
