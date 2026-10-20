"""Deterministic Tkinter integration smoke tests.

The event loop must actually be running while worker threads invoke ``root.after``.
Calling ``root.update()`` in a polling loop does not satisfy Tkinter's requirement
that the main thread be inside ``mainloop``. Reset confirms its modal dialogue
using a mock; no test must require a human clicking a button.

Run on Linux with: xvfb-run -a python -m unittest tests.test_gui_smoke -v
Run on Windows:    python -m unittest tests.test_gui_smoke -v
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import tkinter
    _TK = True
except ImportError:
    _TK = False


def _display_available():
    if not _TK:
        return False
    try:
        root = tkinter.Tk()
        root.withdraw()
        root.destroy()
        return True
    except tkinter.TclError:
        return False


EXPECTED_TABS = ["File Catalogue", "Type Check", "Integrity", "Covert Data",
                 "Event Log", "NTFS $MFT", "Entropy Map", "VirusTotal", "Export"]


@unittest.skipUnless(_display_available(), "Tkinter or display unavailable")
class GuiSmokeTest(unittest.TestCase):
    """Independent GUI instances avoid test-order dependence and stale workers."""

    def setUp(self):
        from gui.app import ByteProbeApp
        self.app = ByteProbeApp()
        self.addCleanup(self.app.root.destroy)

    def _notebook(self):
        for widget in self.app.root.winfo_children():
            for child in (widget, *widget.winfo_children()):
                if child.winfo_class() == "TNotebook":
                    return child
        self.fail("Notebook not found")

    def test_window_constructs(self):
        self.assertTrue(self.app.root.winfo_exists())

    def test_nine_tabs_present_and_named(self):
        notebook = self._notebook()
        labels = [notebook.tab(i, "text").strip()
                  for i in range(notebook.index("end"))]
        self.assertEqual(labels, EXPECTED_TABS)

    def test_every_tab_selectable(self):
        notebook = self._notebook()
        for i in range(notebook.index("end")):
            notebook.select(i)
            self.app.root.update_idletasks()
            self.assertEqual(notebook.index("current"), i)

    def test_background_scan_completes_and_populates(self):
        # A temporary directory is cleaned up even when an assertion fails.
        with tempfile.TemporaryDirectory(prefix="byteprobe_gui_test_") as target:
            with open(os.path.join(target, "a.txt"), "w") as f:
                f.write("plain text content " * 20)
            with open(os.path.join(target, "fake.jpg"), "wb") as f:
                f.write(b"%PDF-1.4 not really a jpeg")
            with open(os.path.join(target, "rand.bin"), "wb") as f:
                f.write(os.urandom(120000))

            self.app._scan_dir.set(target)
            timed_out = [False]
            completed = [False]

            def _poll():
                # This callback is executed by Tk's genuine mainloop, not by
                # intermittent calls to ``update`` in the test thread.
                ready = (self.app._scan_end is not None and
                         str(self.app._scan_btn.cget("state")) == "normal")
                if ready:
                    completed[0] = True
                    self.app.root.quit()
                else:
                    self.app.root.after(25, _poll)

            def _timeout():
                if not completed[0]:
                    timed_out[0] = True
                    self.app._cancel_flag.set()
                    self.app.root.quit()

            self.app.root.after(0, self.app._start_scan)
            self.app.root.after(25, _poll)
            watchdog = self.app.root.after(20000, _timeout)
            self.app.root.mainloop()
            self.app.root.after_cancel(watchdog)

            self.assertFalse(timed_out[0], "background scan timed out after 20 seconds")
            self.assertTrue(completed[0], "scan completion callback did not run")
            self.assertEqual(len(self.app._metas), 3)
            self.assertTrue(any(s.mismatch for s in self.app._sigs),
                            "renamed PDF was not flagged")
            self.assertTrue(any(e.is_high_entropy for e in self.app._entropy),
                            "random file not flagged as high-entropy")
            self.assertEqual(self.app._meta_table.row_count(), 3,
                             "GUI metadata table did not populate")
            self.assertEqual(self.app._sig_table.row_count(), 3,
                             "GUI signature table did not populate")

    def test_reset_clears_results(self):
        # Seed non-empty state; the test must be independent of scan-test order.
        self.app._metas = [object()]
        with patch("gui.app.messagebox.askyesno", return_value=True) as confirm:
            self.app._reset()
        confirm.assert_called_once()
        self.assertFalse(self.app._metas)
        self.assertEqual(self.app._meta_table.row_count(), 0)
        self.assertEqual(self.app._scan_dir.get(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
