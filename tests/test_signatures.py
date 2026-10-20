import os, tempfile, unittest
from core import signatures


def _write(d, name, data):
    p = os.path.join(d, name)
    with open(p, 'wb') as f:
        f.write(data)
    return p


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def check(self, name, data):
        return signatures.analyze_signature(_write(self.d.name, name, data))

    def test_pe_renamed_to_txt_is_mismatch(self):
        self.assertTrue(self.check('a.txt', b'MZ\x90\x00' + b'\x00' * 60).mismatch)

    def test_real_png_ok(self):
        self.assertFalse(self.check('a.png', b'\x89PNG\r\n\x1a\n' + b'\x00' * 20).mismatch)

    def test_riff_wav_ok_and_webp_ok(self):
        self.assertFalse(self.check('a.wav', b'RIFF\x00\x00\x00\x00WAVEfmt ').mismatch)
        self.assertFalse(self.check('a.webp', b'RIFF\x00\x00\x00\x00WEBPVP8 ').mismatch)

    def test_riff_wav_named_avi_is_mismatch(self):
        self.assertTrue(self.check('a.avi', b'RIFF\x00\x00\x00\x00WAVEfmt ').mismatch)

    def test_bm_in_text_file_is_not_a_bitmap(self):
        r = self.check('notes.txt', b'BMW service history 2020')
        self.assertFalse(r.mismatch)

    def test_real_bmp_ok(self):
        hdr = b'BM' + b'\x36\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x36\x00\x00\x00'
        self.assertFalse(self.check('a.bmp', hdr).mismatch)

    def test_unknown_header_with_mandatory_extension_is_flagged(self):
        r = self.check('photo.png', bytes(range(256)) * 4)
        self.assertTrue(r.mismatch)
        self.assertIn('no known signature', r.note)

    def test_unknown_header_with_plain_extension_is_not_flagged(self):
        self.assertFalse(self.check('data.bin', bytes(range(256))).mismatch)
        self.assertFalse(self.check('readme.txt', b'just some text').mismatch)

    def test_empty_file_not_flagged(self):
        self.assertFalse(self.check('empty.png', b'').mismatch)


if __name__ == '__main__':
    unittest.main()
