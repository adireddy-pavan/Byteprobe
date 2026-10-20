"""Build synthetic NTFS structures byte-by-byte for tests.

Everything here follows the on-disk layouts documented in Carrier,
"File System Forensic Analysis" (2005), ch. 13, so the parser under test
is checked against the specification rather than against itself.
"""

import datetime
import struct

TICKS = 10_000_000
_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime(y, mo, d, h=0, mi=0, s=0, ticks=0) -> int:
    """FILETIME for a UTC date plus `ticks` (100 ns units below a second)."""
    dt = datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc)
    return int((dt - _EPOCH).total_seconds()) * TICKS + ticks


def _align8(n: int) -> int:
    return (n + 7) & ~7


def resident_attr(atype: int, content: bytes, name: str = '') -> bytes:
    name_b = name.encode('utf-16-le')
    content_off = _align8(0x18 + len(name_b))
    length = _align8(content_off + len(content))
    buf = bytearray(length)
    struct.pack_into('<IIBBHHHIHBB', buf, 0, atype, length, 0, len(name),
                     0x18, 0, 0, len(content), content_off, 0, 0)
    buf[0x18:0x18 + len(name_b)] = name_b
    buf[content_off:content_off + len(content)] = content
    return bytes(buf)


def nonresident_attr(atype: int, runlist: bytes, real_size: int,
                     name: str = '', start_vcn: int = 0, clusters: int = 1) -> bytes:
    name_b = name.encode('utf-16-le')
    run_off = _align8(0x40 + len(name_b))
    length = _align8(run_off + len(runlist) + 1)
    buf = bytearray(length)
    struct.pack_into('<IIBBHHH', buf, 0, atype, length, 1, len(name), 0x40, 0, 0)
    struct.pack_into('<QQHH', buf, 0x10, start_vcn, start_vcn + clusters - 1, run_off, 0)
    struct.pack_into('<QQQ', buf, 0x28, clusters * 4096, real_size, real_size)
    buf[0x40:0x40 + len(name_b)] = name_b
    buf[run_off:run_off + len(runlist)] = runlist
    return bytes(buf)


def si_attr(created, modified, mft_changed, accessed) -> bytes:
    content = struct.pack('<4QI', created, modified, mft_changed, accessed, 0x20) + bytes(44)
    return resident_attr(0x10, content)


def fn_attr(name: str, parent: int, times, parent_seq: int = 1, namespace: int = 1) -> bytes:
    name_b = name.encode('utf-16-le')
    content = (struct.pack('<Q', parent | (parent_seq << 48))
               + struct.pack('<4Q', *times)
               + struct.pack('<QQII', 0, 0, 0x20, 0)
               + bytes([len(name), namespace]) + name_b)
    return resident_attr(0x30, content)


def data_attr(content: bytes = b'', name: str = '') -> bytes:
    return resident_attr(0x80, content, name)


def encode_runlist(runs) -> bytes:
    """[(lcn | None, clusters)] -> NTFS run list with relative signed offsets."""
    out, prev = bytearray(), 0
    for lcn, length in runs:
        len_b = length.to_bytes((length.bit_length() + 8) // 8, 'little')
        if lcn is None:
            out += bytes([len(len_b)]) + len_b
            continue
        delta = lcn - prev
        size = 1
        while not -(1 << (8 * size - 1)) <= delta < (1 << (8 * size - 1)):
            size += 1
        out += bytes([(size << 4) | len(len_b)]) + len_b + delta.to_bytes(size, 'little', signed=True)
        prev = lcn
    return bytes(out) + b'\x00'


def make_record(number: int, attrs, in_use: bool = True, directory: bool = False,
                sequence: int = 1, base: int = 0, size: int = 1024,
                usn: bytes = b'\x01\x00') -> bytes:
    """A complete FILE record with the update sequence array applied."""
    usa_count = size // 512 + 1
    attr_off = _align8(0x30 + usa_count * 2)
    body = b''.join(attrs) + b'\xff\xff\xff\xff\x00\x00\x00\x00'
    used = attr_off + len(body)
    assert used <= size, 'attributes do not fit in the record'
    flags = (1 if in_use else 0) | (2 if directory else 0)

    buf = bytearray(size)
    buf[0:4] = b'FILE'
    struct.pack_into('<HHQHHHHIIQHHI', buf, 4, 0x30, usa_count, 0, sequence, 1,
                     attr_off, flags, used, size, base, 0, 0, number)
    buf[attr_off:attr_off + len(body)] = body

    # Protect each 512-byte stride: real bytes go into the array, USN at the end
    buf[0x30:0x32] = usn
    for i in range(1, usa_count):
        end = i * 512
        buf[0x30 + 2 * i:0x32 + 2 * i] = buf[end - 2:end]
        buf[end - 2:end] = usn
    return bytes(buf)


def boot_sector(mft_lcn: int, bytes_per_sector: int = 512, sectors_per_cluster: int = 8,
                clusters_per_record: int = -10, total_sectors: int = 0) -> bytes:
    bs = bytearray(512)
    bs[0:3] = b'\xeb\x52\x90'
    bs[3:11] = b'NTFS    '
    struct.pack_into('<HB', bs, 0x0B, bytes_per_sector, sectors_per_cluster)
    struct.pack_into('<QQQ', bs, 0x28, total_sectors, mft_lcn, mft_lcn + 1)
    struct.pack_into('<b', bs, 0x40, clusters_per_record)
    bs[510:512] = b'\x55\xaa'
    return bytes(bs)


def build_volume(records, layout, cluster_size: int = 4096, record_size: int = 1024) -> bytes:
    """An NTFS volume whose $MFT (record 0, built here) is stored in `layout`.

    records: raw FILE records for numbers 1..n (None leaves an empty slot)
    layout:  [(lcn, clusters)] runs holding the $MFT, may be fragmented
    """
    total = len(records) + 1
    rec0 = make_record(0, [
        si_attr(*[filetime(2020, 1, 1)] * 4),
        fn_attr('$MFT', 5, [filetime(2020, 1, 1)] * 4, parent_seq=5, namespace=3),
        nonresident_attr(0x80, encode_runlist(layout), total * record_size,
                         clusters=sum(n for _, n in layout)),
    ], size=record_size)
    all_records = [rec0] + [r or bytes(record_size) for r in records]

    per_cluster = cluster_size // record_size
    assert sum(n for _, n in layout) * per_cluster >= total, 'layout too small'
    end = max(lcn + n for lcn, n in layout if lcn is not None) + 1
    img = bytearray(end * cluster_size)
    img[0:512] = boot_sector(layout[0][0], sectors_per_cluster=cluster_size // 512,
                             total_sectors=end * cluster_size // 512)
    it = iter(all_records)
    for lcn, n in layout:
        for slot in range(n * per_cluster):
            rec = next(it, None)
            if rec is None:
                break
            if lcn is None:          # sparse run: records here are not stored
                continue
            pos = lcn * cluster_size + slot * record_size
            img[pos:pos + record_size] = rec
    return bytes(img)


def with_mbr(volume: bytes, start_lba: int = 2048) -> bytes:
    """Wrap a volume in a whole-disk image with an MBR partition (type 0x07)."""
    mbr = bytearray(512)
    struct.pack_into('<B3sB3sII', mbr, 446, 0x80, b'\x00' * 3, 0x07, b'\x00' * 3,
                     start_lba, len(volume) // 512)
    mbr[510:512] = b'\x55\xaa'
    return bytes(mbr) + bytes(start_lba * 512 - 512) + volume


def with_gpt(volume: bytes, start_lba: int = 2048) -> bytes:
    """Wrap a volume in a whole-disk image with a GPT partition table."""
    disk = bytearray(start_lba * 512)
    disk[510:512] = b'\x55\xaa'                      # protective MBR
    disk[446 + 4] = 0xEE
    hdr = bytearray(92)
    hdr[0:8] = b'EFI PART'
    struct.pack_into('<QII', hdr, 72, 2, 128, 128)   # entries at LBA 2
    disk[512:512 + 92] = hdr
    entry = bytearray(128)
    entry[0:16] = bytes.fromhex('a2a0d0ebe5b9334487c068b6b72699c7')  # basic data
    struct.pack_into('<QQ', entry, 32, start_lba, start_lba + len(volume) // 512 - 1)
    disk[1024:1024 + 128] = entry
    return bytes(disk) + volume
