"""Only tests the OS guard and pure-output logic; not genuine Windows evidence."""
import unittest
from types import SimpleNamespace
from tools.run_windows_w5_w6_lab import preflight, _summary


class WindowsLabGuardTests(unittest.TestCase):
    def test_explicit_consent_is_required(self):
        with self.assertRaisesRegex(RuntimeError, 'confirm-disposable-test'):
            preflight(system='Windows', consent=False)

    def test_linux_must_never_be_reported_as_windows(self):
        with self.assertRaisesRegex(RuntimeError, 'Windows-only'):
            preflight(system='Linux', consent=True)

    def test_pure_summary_reports_raw_ticks(self):
        import datetime as dt
        class Stamp:
            created = 130000000000000000
            def as_datetime(self, name):
                return dt.datetime(2019, 1, 1, tzinfo=dt.timezone.utc)
        record = SimpleNamespace(record_number=19, sequence=2, path='\\test.txt',
                                 fixup_ok=True, in_use=True, si=Stamp(),
                                 fn=SimpleNamespace(timestamps=Stamp()))
        result = _summary(record)
        self.assertEqual(result['si_raw_created_ticks'], Stamp.created)
        self.assertEqual(result['record_number'], 19)


if __name__ == '__main__': unittest.main()
