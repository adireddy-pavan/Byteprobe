"""Hidden data detection — NTFS ADS, hidden/system files, suspicious attributes."""

import os
import ctypes
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from .metadata import FileMetadata
from .mft import MFTRecord

IS_WINDOWS = platform.system() == 'Windows'


@dataclass
class AltDataStream:
    host_file: str
    stream_name: str
    size: int


@dataclass
class HiddenDataResult:
    meta: FileMetadata
    ads_streams: list[AltDataStream] = field(default_factory=list)
    suspicion_flags: list[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.ads_streams) or bool(self.suspicion_flags)


# ── NTFS ADS via Windows API ─────────────────────────────────────────────────

class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ('StreamSize', ctypes.c_longlong),
        ('cStreamName', ctypes.c_wchar * 296),
    ]



def _enumerate_ads_windows(path: str) -> list[AltDataStream]:
    streams: list[AltDataStream] = []
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Declare the Windows API signatures explicitly.
    k32.FindFirstStreamW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.POINTER(_WIN32_FIND_STREAM_DATA),
        ctypes.c_uint32,
    ]
    k32.FindFirstStreamW.restype = ctypes.c_void_p

    k32.FindNextStreamW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WIN32_FIND_STREAM_DATA),
    ]
    k32.FindNextStreamW.restype = ctypes.c_int

    k32.FindClose.argtypes = [ctypes.c_void_p]
    k32.FindClose.restype = ctypes.c_int

    INVALID = ctypes.c_void_p(-1).value
    data = _WIN32_FIND_STREAM_DATA()

    handle = k32.FindFirstStreamW(path, 0, ctypes.byref(data), 0)

    if handle == INVALID or handle is None:
        raise OSError(
            ctypes.get_last_error(),
            "FindFirstStreamW failed"
        )

    try:
        while True:
            name = data.cStreamName

            if name and name != "::$DATA":
                streams.append(
                    AltDataStream(
                        host_file=path,
                        stream_name=name,
                        size=data.StreamSize,
                    )
                )

            if not k32.FindNextStreamW(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()

                if error == 38:  # ERROR_HANDLE_EOF
                    break

                raise OSError(
                    error,
                    "FindNextStreamW failed"
                )
    finally:
        if not k32.FindClose(handle):
            raise OSError(
                ctypes.get_last_error(),
                "FindClose failed"
            )

    return streams


# ── NTFS ADS from a parsed $MFT (works on any OS, and on disk images) ────────

def ads_from_mft(record: MFTRecord, host_file: Optional[str] = None) -> list[AltDataStream]:
    """Named $DATA attributes of an MFT record, in FindFirstStreamW format."""
    return [AltDataStream(host_file=host_file or record.path,
                          stream_name=f":{d.name}:$DATA",
                          size=d.size)
            for d in record.ads]


def enumerate_ads(path: str, mft_record: Optional[MFTRecord] = None) -> list[AltDataStream]:
    """List ADS via the Windows API, falling back to the parsed $MFT record."""
    if IS_WINDOWS:
        try:
            streams = _enumerate_ads_windows(path)
        except Exception:
            streams = []
        if streams:
            return streams
    if mft_record is not None:
        return ads_from_mft(mft_record, host_file=path)
    return []


# ── Suspicion heuristics ──────────────────────────────────────────────────────

_DOUBLE_EXT = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1', '.com'}
_RISKY_EXT  = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1',
               '.com', '.jar', '.py', '.rb', '.lnk', '.hta', '.js', '.jse'}
# Shared by _suspicion_flags and compute_risk_score so the two cannot drift apart.
_TEMP_DIRS  = ('\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\', '/tmp/', '/var/tmp/')


def _suspicion_flags(meta: FileMetadata) -> list[str]:
    flags: list[str] = []
    p = Path(meta.path)

    if meta.is_hidden and meta.is_system:
        flags.append("Hidden + System attributes set")

    # Double extension: file.txt.exe
    suffixes = p.suffixes
    if len(suffixes) >= 2 and suffixes[-1].lower() in _DOUBLE_EXT:
        flags.append(f"Double extension detected: {''.join(suffixes)}")

    # Executable in temp or unusual location
    lower_path = meta.path.lower()
    for tmp in _TEMP_DIRS:
        if tmp in lower_path and meta.extension in _RISKY_EXT:
            flags.append(f"Executable in temp directory: {tmp}")
            break

    # Zero-byte file with executable extension
    if meta.size == 0 and meta.extension in _RISKY_EXT:
        flags.append("Zero-byte executable")

    # Very large file with text extension
    if meta.size > 100 * 1024 * 1024 and meta.extension in ('.txt', '.log', '.csv'):
        flags.append(f"Unusually large text file ({meta.size // (1024*1024)} MB)")

    return flags


def analyze_file(meta: FileMetadata, mft_record: Optional[MFTRecord] = None) -> HiddenDataResult:
    return HiddenDataResult(
        meta=meta,
        ads_streams=enumerate_ads(meta.path, mft_record),
        suspicion_flags=_suspicion_flags(meta),
    )


def analyze_all(metas: list[FileMetadata], progress_cb=None,
                mft_lookup=None) -> list[HiddenDataResult]:
    """mft_lookup: optional callable FileMetadata -> MFTRecord | None."""
    results = []
    for meta in metas:
        record = mft_lookup(meta) if mft_lookup else None
        results.append(analyze_file(meta, record))
        if progress_cb:
            progress_cb(meta.path)
    return results


def filter_suspicious(results: list[HiddenDataResult]) -> list[HiddenDataResult]:
    return [r for r in results if r.is_suspicious]


def compute_risk_score(meta, sig_result=None, entropy_result=None,
                       si_fn_anomaly: bool = False) -> int:
    """Combine forensic signals into a 0-100 risk score.

    Weights:
      $SI/$FN timestamp mismatch: +40  -- NTFS timestomping signature
      Extension mismatch (sig)  : +35  -- major red flag
      Hidden + System bits set  : +30
      High entropy (> 7.2)      : +20  -- encrypted or packed
      Double extension          : +25  -- e.g. document.txt.exe
      Executable in temp dir    : +20
      Risky extension           : +10
    Maximum returned value is capped at 100.
    """
    from pathlib import Path
    score = 0
    if si_fn_anomaly:
        score += 40
    if meta.is_hidden and meta.is_system:
        score += 30
    if sig_result and sig_result.mismatch:
        score += 35
    if meta.extension in _RISKY_EXT:
        score += 10
    if entropy_result and entropy_result.is_high_entropy:
        score += 20
    p = Path(meta.path)
    if len(p.suffixes) >= 2 and p.suffixes[-1].lower() in _DOUBLE_EXT:
        score += 25
    lower = meta.path.lower()
    for tmp in _TEMP_DIRS:
        if tmp in lower and meta.extension in _RISKY_EXT:
            score += 20
            break
    return min(score, 100)
