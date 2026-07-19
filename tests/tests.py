'''Tests for checkdisk — each builds a fresh NTFS image, fabricates one
specific corruption, and asserts the tool triages and repairs it correctly.

No root, no pytest, no external tooling: stdlib unittest only. Test images
are fabricated in pure Python by format.py, corruption is fabricated by raw
byte surgery, and results are verified with the tool's own readers. The
independent oracle is real Windows chkdsk, run natively on the Windows CI
runner (tests/win_github_ci.py).

    python3 tests.py            # all cases
    python3 tests.py -v         # verbose
    python3 tests.py NtfsDirentFixTests.test_orphan_purge_frees_record
'''

from __future__ import annotations

import os, struct, hashlib, shutil, subprocess, sys, tempfile
import unittest

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)                    # tests/ (sibling tests)
sys.path.insert(0, os.path.dirname(_here))   # repo root (checkdisk)
import checkdisk as ndf  # noqa: E402
import format as FMT     # noqa: E402

IMAGE_BYTES = 64 * 1024 * 1024


# ── raw-image helpers (parse geometry, find/patch MFT records & INDX blocks) ──

def _read(path: str) -> bytes:
    with open(path, 'rb') as fh:
        return fh.read()


def _geometry(path: str) -> tuple[int, int, int]:
    '''(mft_offset, record_size, cluster_size) from the boot sector '''

    boot = _read(path)[:72]
    bytes_per_sector = struct.unpack_from('<H', boot, 11)[0]
    spc = boot[13]
    cluster = bytes_per_sector * (2 ** (256 - spc) if spc > 0x80 else spc)
    mft_lcn = struct.unpack_from('<Q', boot, 48)[0]
    raw = struct.unpack_from('<b', boot, 64)[0]
    rec_size = (2 ** -raw) if raw < 0 else raw * cluster
    return mft_lcn * cluster, rec_size, cluster


def _find_file_record(path: str, name: str) -> tuple[int, int]:
    '''(record_number, byte_offset) of the single non-directory FILE record
       whose bytes contain this name. Directories are skipped because their
       resident index root also embeds child names '''

    mft_off, rec_size, _ = _geometry(path)
    needle = name.encode('utf-16-le')
    data = _read(path)
    hits = []
    for i in range(16384):
        off = mft_off + i * rec_size
        if off + rec_size > len(data):
            break
        rec = data[off:off + rec_size]
        if rec[:4] != b'FILE' or needle not in rec:
            continue
        if struct.unpack_from('<H', rec, 22)[0] & 2:  # directory
            continue
        hits.append((i, off))
    if len(hits) != 1:
        raise AssertionError(f'expected one file record for {name!r}, got {hits}')
    return hits[0]


def _patch(path: str, offset: int, blob: bytes) -> None:
    with open(path, 'r+b') as fh:
        fh.seek(offset)
        fh.write(blob)


def corrupt_orphan(path: str, name: str) -> None:
    '''Bump the file record's sequence number, leaving it in use — the dirent's
       (record, seq) no longer matches, so the entry dangles onto a live record '''

    _, off = _find_file_record(path, name)
    seq = struct.unpack_from("<H", _read(path), off + 16)[0]
    _patch(path, off + 16, struct.pack('<H', seq + 1))


def corrupt_record_free(path: str, name: str) -> None:
    '''Clear MFT_RECORD_IN_USE — the record is gone, the dirent left behind '''

    _, off = _find_file_record(path, name)
    flags = struct.unpack_from("<H", _read(path), off + 22)[0]
    _patch(path, off + 22, struct.pack('<H', flags & ~1))


def corrupt_record_reused(path: str, name: str, squatter: str) -> None:
    '''Bump seq AND rename the record in place (same length) so it looks like a
       different live file now owns the record the stale dirent points at '''

    old, new = name.encode('utf-16-le'), squatter.encode('utf-16-le')
    assert len(old) == len(new), 'squatter name must match victim length'
    _, off = _find_file_record(path, name)
    rec_size = _geometry(path)[1]
    data = _read(path)
    rec = bytearray(data[off:off + rec_size])
    assert rec.count(old) == 1, 'victim name should appear once in its record'
    rec = rec.replace(old, new)
    struct.pack_into('<H', rec, 16, struct.unpack_from('<H', rec, 16)[0] + 1)
    _patch(path, off, bytes(rec))


def corrupt_cross_link(path: str, name: str, squatter: str) -> None:
    '''Rename the record in place WITHOUT touching seq — the dirent's (record,
       seq) still matches, but the record no longer carries the dirent's name '''

    old, new = name.encode('utf-16-le'), squatter.encode('utf-16-le')
    assert len(old) == len(new), 'squatter name must match victim length'
    _, off = _find_file_record(path, name)
    rec_size = _geometry(path)[1]
    data = _read(path)
    rec = bytearray(data[off:off + rec_size])
    assert rec.count(old) == 1, 'victim name should appear once in its record'
    rec = rec.replace(old, new)
    _patch(path, off, bytes(rec))


def corrupt_parent_seq(path: str, name: str) -> None:
    '''Bump the parent sequence in every resident $FILE_NAME of the file's
       record — the name now claims a previous incarnation of its parent dir '''

    _, off = _find_file_record(path, name)
    rec_size = _geometry(path)[1]
    data = _read(path)
    rec = data[off:off + rec_size]
    attr_off = struct.unpack_from('<H', rec, 20)[0]
    patched = 0
    while attr_off + 8 <= len(rec):
        attr_type = struct.unpack_from('<I', rec, attr_off)[0]
        if attr_type == 0xFFFFFFFF:
            break
        length = struct.unpack_from('<I', rec, attr_off + 4)[0]
        if length < 24 or attr_off + length > len(rec):
            break
        if attr_type == 0x30 and rec[attr_off + 8] == 0:  # resident $FILE_NAME
            value_ofs = struct.unpack_from('<H', rec, attr_off + 20)[0]
            fn_off = off + attr_off + value_ofs
            parent = struct.unpack_from('<Q', data, fn_off)[0]
            _patch(path, fn_off, struct.pack('<Q', parent + (1 << 48)))
            patched += 1
        attr_off += length
    assert patched, f'no resident $FILE_NAME found for {name!r}'


def corrupt_torn_truncate(path: str, name: str) -> None:
    '''Zero the sizes and highest_vcn of the file's non-resident $DATA while
       leaving its mapping pairs behind — a torn truncate-to-empty '''

    _, off = _find_file_record(path, name)
    rec_size = _geometry(path)[1]
    rec = _read(path)[off:off + rec_size]
    a = struct.unpack_from('<H', rec, 20)[0]
    while a + 8 <= len(rec):
        t = struct.unpack_from('<I', rec, a)[0]
        if t == 0xFFFFFFFF:
            break
        length = struct.unpack_from('<I', rec, a + 4)[0]
        if t == 0x80 and rec[a + 8] == 1:  # non-resident $DATA
            _patch(path, off + a + 24, struct.pack('<q', -1))         # highest_vcn
            _patch(path, off + a + 40, struct.pack('<QQQ', 0, 0, 0))  # alloc/data/init
            return
        if length < 24:
            break
        a += length
    raise AssertionError(f'no non-resident $DATA for {name!r}')


def tear_index_block(path: str, needle: str) -> int:
    '''Break one INDX block's sector fixup (a torn multi-sector write). Returns
       the count of that needle in the torn block. Raises if no INDX spill.'''
    key = needle.encode('utf-16-le')
    data = _read(path)
    for off in range(0, len(data) - 4096, 4096):
        if data[off:off + 4] != b'INDX':
            continue
        if key not in data[off:off + 4096]:
            continue
        usa_ofs = struct.unpack_from('<H', data, off + 4)[0]
        usn = data[off + usa_ofs:off + usa_ofs + 2]
        tear_at = off + 3 * 512 - 2  # end-of-3rd-sector check value
        _patch(path, tear_at, bytes(b ^ 0xFF for b in usn))
        return data[off:off + 4096].count(key)
    raise AssertionError(f'no INDX block containing {needle!r} — directory did not spill')


# ── image fixture ─────────────────────────────────────────────────────────────

class NtfsImage:
    def __init__(self, size: int = IMAGE_BYTES) -> None:
        fd, self.path = tempfile.mkstemp(suffix='.ntfs.img', prefix='ndf-test-')
        os.close(fd)
        FMT.format_volume(self.path, size_mib=size // (1024 * 1024))

    def populate(self, files: dict[str, bytes], dirs: tuple[str, ...] = ()) -> None:
        FMT.populate(self.path, files, dirs)

    def list_dir(self, rel: str) -> list[str]:
        with ndf.RawVolume(self.path) as v:
            return sorted(e['name'] for e in v.scan_dir('/' + rel.strip('/'))
                          if e['status'] != 'dir-self')

    def md5(self) -> str:
        return hashlib.md5(_read(self.path)).hexdigest()

    def dispose(self) -> None:
        if os.path.exists(self.path):
            os.unlink(self.path)


def patch_stream(path: str, rec_no: int, attr_type: int, name: str,
                 offset: int, blob: bytes) -> None:
    '''Overwrite bytes inside an attribute's value on disk — resident values
       through record surgery, non-resident through the runlist. The raw
       corruption fabricator that replaces driver-side attribute I/O.'''
    name_u16 = name.encode('utf-16-le') if name else None
    with ndf.RawVolumeRW(path) as v:
        size, runs = v._stream_runs(rec_no, attr_type, name_u16)
        if runs is None:                                  # resident
            for frozen, a, _l in v._record_attrs(rec_no):
                if struct.unpack_from('<I', frozen, a)[0] != attr_type:
                    continue
                nlen = frozen[a + 9]
                nofs = struct.unpack_from('<H', frozen, a + 10)[0]
                aname = frozen[a + nofs:a + nofs + 2 * nlen] if nlen else None
                if (name_u16 or None) != (bytes(aname) if aname else None):
                    continue
                vo = struct.unpack_from('<H', frozen, a + 20)[0]
                rec = v._load_record(rec_no)
                rec[a + vo + offset:a + vo + offset + len(blob)] = blob
                v.write_record(rec_no, rec)
                return
            raise AssertionError('resident attribute not found')
    csz = _geometry(path)[2]
    pos = 0
    for lcn, n, vcn in runs:
        lo, hi = vcn * csz, (vcn + n) * csz
        if lo <= offset < hi:
            _patch(path, lcn * csz + (offset - lo), blob)
            return
        pos = hi
    raise AssertionError(f'offset {offset} beyond stream ({pos})')


def add_named_data(path: str, rec_no: int, name: str, value: bytes) -> None:
    '''Add a named resident $DATA stream to a record (fabrication helper).'''
    with ndf.RawVolumeRW(path) as v:
        rec = v._load_record(rec_no)
        v._add_attr(rec, ndf.AT_DATA, name.encode('utf-16-le'),
                    resident=True, value=value)
        v.write_record(rec_no, rec)


@unittest.skipIf(sys.platform == 'win32',
                 'Linux mount-detection semantics: /proc/mounts + sysfs loop '
                 'devices + os.symlink have no Windows analogue here')
class MountCheckTests(unittest.TestCase):
    '''assert_not_mounted against fabricated /proc/mounts + sysfs trees — the
       loop-device paths are exercised without root, FUSE, or mkfs.'''

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix='ndf-mntchk-')
        self.addCleanup(shutil.rmtree, self.tmp)
        self.image = os.path.join(self.tmp, 'disk.img')
        open(self.image, 'wb').close()

    def _fake(self, mount_lines: list[str], loops: dict[str, str]) -> tuple[str, str]:
        mounts = os.path.join(self.tmp, 'mounts')
        with open(mounts, 'w') as fh:
            fh.writelines(mount_lines)
        sys_block = os.path.join(self.tmp, 'sys')
        for name, backing in loops.items():
            d = os.path.join(sys_block, name, 'loop')
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, 'backing_file'), 'w') as fh:
                fh.write(backing + '\n')
        return mounts, sys_block

    def test_direct_source_refused(self) -> None:
        mounts, sysb = self._fake([f'{self.image} /mnt/t fuseblk rw 0 0\n'], {})
        with self.assertRaises(SystemExit):
            ndf.assert_not_mounted(self.image, mounts=mounts, sys_block=sysb)

    def test_loop_mounted_image_refused(self) -> None:
        mounts, sysb = self._fake(['/dev/loop7 /mnt/t ntfs3 rw 0 0\n'],
                                  {'loop7': self.image})
        with self.assertRaises(SystemExit):
            ndf.assert_not_mounted(self.image, mounts=mounts, sys_block=sysb)

    def test_loop_partition_mounted_image_refused(self) -> None:
        # /dev/loop7p1: sysfs nests the partition node under the whole device,
        # reached from /sys/class/block/loop7p1 through its symlink and ../ .
        mounts, sysb = self._fake(['/dev/loop7p1 /mnt/t ntfs3 rw 0 0\n'],
                                  {'loop7': self.image})
        os.makedirs(os.path.join(sysb, 'loop7', 'loop7p1'))
        os.symlink(os.path.join('loop7', 'loop7p1'), os.path.join(sysb, 'loop7p1'))
        with self.assertRaises(SystemExit):
            ndf.assert_not_mounted(self.image, mounts=mounts, sys_block=sysb)

    def test_unrelated_mounts_pass(self) -> None:
        other = os.path.join(self.tmp, 'other.img')
        open(other, 'wb').close()
        mounts, sysb = self._fake(['/dev/loop3 /mnt/o ext4 rw 0 0\n',
                                   '/dev/sda1 / ext4 rw 0 0\n',
                                   'tmpfs /tmp tmpfs rw 0 0\n'],
                                  {'loop3': other})
        ndf.assert_not_mounted(self.image, mounts=mounts, sys_block=sysb)  # no raise


def usn_v2(usn: int, name: str = 'a.txt') -> bytes:
    '''One well-formed USN_RECORD_V2 whose Usn field claims the given offset '''

    n = name.encode('utf-16-le')
    length = (60 + len(n) + 7) & ~7
    rec = struct.pack('<IHHQQqqIIIIHH', length, 2, 0, 0x1234, 0x5678, usn,
                      133525344000000000, 0x1, 0, 0, 0x20, len(n), 60)
    return (rec + n).ljust(length, b'\0')


def usn_stream(*names: str) -> bytes:
    '''A valid $J stream: records back to back, each Usn = its own offset '''

    out = b''
    for name in names:
        out += usn_v2(len(out), name)
    return out


class UsnWalkTests(unittest.TestCase):
    '''_walk_usn_records against synthetic buffers — no image, no root.'''

    @staticmethod
    def _walk(blob: bytes, start: int = 0):
        return ndf._walk_usn_records(
            lambda pos, count: blob[pos:pos + count], start, len(blob))

    def test_valid_stream(self) -> None:
        blob = usn_stream('a.txt', 'b.txt', 'sub dir entry.dat')
        self.assertEqual(self._walk(blob), (3, []))

    def test_zero_padding_to_page_boundary_ok(self) -> None:
        first = usn_v2(0, 'x' * 200)  # long name, still < one page
        blob = first.ljust(4096, b'\0') + usn_v2(4096, 'next.txt')
        self.assertEqual(self._walk(blob), (2, []))

    def test_wrong_usn_flagged(self) -> None:
        blob = usn_stream('a.txt') + usn_v2(9999, 'b.txt')
        count, problems = self._walk(blob)
        self.assertEqual(count, 1)
        self.assertIn('claims usn 9999', problems[0])

    def test_bad_length_flagged(self) -> None:
        good = usn_stream('a.txt')
        blob = good + struct.pack('<I', 61) + b'\0' * 60  # 61: not 8-aligned
        count, problems = self._walk(blob)
        self.assertEqual(count, 1)
        self.assertIn('bad record length 61', problems[0])

    def test_garbage_in_padding_flagged(self) -> None:
        first = usn_v2(0)
        pad = bytearray(4096 - len(first))
        pad[100] = 0xEE  # non-zero after a zero length field
        blob = bytes(first) + bytes(pad) + usn_v2(4096, 'next.txt')
        _, problems = self._walk(blob)
        self.assertTrue(problems and 'garbage inside zero padding' in problems[0])

    def test_truncated_tail_flagged(self) -> None:
        blob = usn_stream('a.txt') + usn_v2(9999)[:20]
        _, problems = self._walk(blob)
        self.assertTrue(problems)


def first_data_lcn(path: str, name: str) -> int:
    '''First cluster of the file's non-resident $DATA, from raw mapping pairs '''

    _, off = _find_file_record(path, name)
    rec = _read(path)[off:off + _geometry(path)[1]]
    a = struct.unpack_from('<H', rec, 20)[0]
    while a + 24 <= len(rec):
        t = struct.unpack_from('<I', rec, a)[0]
        if t == 0xFFFFFFFF:
            break
        length = struct.unpack_from('<I', rec, a + 4)[0]
        if t == 0x80 and rec[a + 8] == 1:
            mp = struct.unpack_from('<H', rec, a + 32)[0]
            header = rec[a + mp]
            len_sz, ofs_sz = header & 0xF, header >> 4
            base = a + mp + 1
            return int.from_bytes(rec[base + len_sz:base + len_sz + ofs_sz],
                                  'little', signed=True)
        if length < 24:
            break
        a += length
    raise AssertionError(f'no non-resident $DATA for {name!r}')


class MappingPairsCodecTests(unittest.TestCase):
    '''_encode_mapping_pairs must round-trip through the real decoder.'''

    def _decode(self, mp: bytes, nc=1 << 30):
        # wrap the pairs in a minimal non-resident ATTR_RECORD and decode
        total = 0
        # compute clusters for highest_vcn from a trial decode
        rec = bytearray(64 + len(mp))
        struct.pack_into('<IIBBHHHQqqHHIQ', rec, 0,
                         0x80, len(rec), 1, 0, 0, 0, 0,   # type,len,nonres,...
                         0,                                # start_vcn (Q@16)
                         0,                                # lowest_vcn? placeholder
                         0, 0x40, 0, 0, 0)                 # rough
        # simpler: build fields we actually read
        rec = bytearray(72 + len(mp))
        struct.pack_into('<I', rec, 0, 0x80)      # type
        struct.pack_into('<I', rec, 4, len(rec))  # length
        rec[8] = 1                                 # non-resident
        struct.pack_into('<q', rec, 16, 0)         # lowest_vcn
        struct.pack_into('<H', rec, 32, 64)        # mapping_pairs_offset
        rec[64:64 + len(mp)] = mp
        # highest_vcn must equal total clusters - 1 for the count check
        return rec

    def test_roundtrip(self) -> None:
        import random
        rng = random.Random(11)
        for _ in range(200):
            runs, lcn, total = [], rng.randrange(1, 10000), 0
            for _ in range(rng.randrange(1, 6)):
                length = rng.randrange(1, 500)
                lcn += rng.randrange(-3000, 3000)
                if lcn < 0:
                    lcn += 6000
                runs.append((lcn, length))
                lcn += length
                total += length
            mp = ndf._encode_mapping_pairs(runs)
            rec = self._decode(mp)
            struct.pack_into('<q', rec, 24, total - 1)     # highest_vcn
            struct.pack_into('<qqq', rec, 40, total * 4096, total * 4096, total * 4096)
            prob, phantom, decoded = ndf._check_mapping_pairs(rec, 0, len(rec), 1 << 40)
            self.assertIsNone(prob, f'{runs} -> {prob}')
            self.assertEqual([(l, n) for l, n, _v in decoded], runs)

    def test_minbytes(self) -> None:
        self.assertEqual(ndf._min_bytes_signed(-1), b'\xff')
        self.assertEqual(ndf._min_bytes_signed(127), b'\x7f')
        self.assertEqual(ndf._min_bytes_signed(128), b'\x80\x00')
        self.assertEqual(ndf._min_bytes_signed(-128), b'\x80')
        self.assertEqual(ndf._min_bytes_signed(-129), b'\x7f\xff')

    def test_length_128_encodes_as_two_bytes(self) -> None:
        '''Run lengths are signed varints: 128 in a single byte reads back as
           -128 (Windows and every driver sign-extend the top byte), so it must
           encode as 80 00 — and the decoder must flag the one-byte form.'''
        mp = ndf._encode_mapping_pairs([(3688, 128)])
        self.assertEqual(mp[0] & 0xF, 2)               # two length bytes
        self.assertEqual(mp[1:3], b'\x80\x00')
        rec = self._decode(mp)
        struct.pack_into('<q', rec, 24, 127)           # highest_vcn
        prob, _, decoded = ndf._check_mapping_pairs(rec, 0, len(rec), 1 << 40)
        self.assertIsNone(prob)
        self.assertEqual([(l, n) for l, n, _v in decoded], [(3688, 128)])
        bad = bytes([0x21, 0x80]) + mp[3:]             # the invalid old form
        rec = self._decode(bad)
        struct.pack_into('<q', rec, 24, 127)
        prob, _, _ = ndf._check_mapping_pairs(rec, 0, len(rec), 1 << 40)
        self.assertIn('non-positive run length', prob or '')


class UpcaseTableTests(unittest.TestCase):
    '''format.py must emit the exact frozen Windows $UpCase: chkdsk silently
       skips index verification on a volume whose table it does not expect,
       so a drifted table (e.g. a newer Python Unicode adding mappings) would
       quietly disable the strongest oracle. md5 taken from a real Windows 10
       system volume.'''

    def test_bit_identical_to_windows(self) -> None:
        self.assertEqual(hashlib.md5(FMT.build_upcase()).hexdigest(),
                         '7ff498a44e45e77374cc7c962b1b92f2')


class FixupSealTests(unittest.TestCase):
    '''_seal_fixups must be the exact inverse of _apply_fixups.'''

    def test_roundtrip(self) -> None:
        import random
        rng = random.Random(3)
        logical = bytearray(rng.randbytes(1024))
        logical[:4] = b'FILE'
        struct.pack_into('<HH', logical, 4, 48, 3)   # usa_ofs, usa_count
        struct.pack_into('<H', logical, 48, 41)      # current USN
        sealed = bytearray(logical)
        ndf._seal_fixups(sealed)
        self.assertEqual(struct.unpack_from('<H', sealed, 48)[0], 42)
        for end in (512, 1024):                      # sector ends now carry USN
            self.assertEqual(struct.unpack_from('<H', sealed, end - 2)[0], 42)
        unfixed = bytearray(sealed)
        self.assertTrue(ndf._apply_fixups(unfixed))
        self.assertEqual(unfixed[54:], logical[54:], 'payload must round-trip')
        self.assertEqual(unfixed[:48], logical[:48])


class SurfaceScanTests(unittest.TestCase):
    '''_surface_scan against a fake device — no image, no root.'''

    CSZ = 4096

    def _fake_pread(self, bad_clusters: set[int]):
        def pread(pos: int, count: int) -> bytes:
            for c in bad_clusters:
                start = c * self.CSZ
                if pos < start + self.CSZ and pos + count > start:
                    raise OSError(5, 'fake I/O error')
            return b'\0' * count
        return pread

    def test_clean_device(self) -> None:
        self.assertEqual(
            ndf._surface_scan(self._fake_pread(set()), 500 * self.CSZ, self.CSZ), [])

    def test_bisect_finds_exact_bad_clusters(self) -> None:
        bad = {5, 6, 130, 499}
        self.assertEqual(
            ndf._surface_scan(self._fake_pread(bad), 500 * self.CSZ, self.CSZ),
            sorted(bad))

    def test_premature_eof_raises(self) -> None:
        with self.assertRaises(ndf.NtfsError):
            ndf._surface_scan(lambda pos, count: b'', 10 * self.CSZ, self.CSZ)


class SecurityHashTests(unittest.TestCase):
    '''The $Secure hash (rol3 over dwords + "II") against known-good vectors
       taken from real on-disk $SDS entries.'''

    def test_known_vectors(self) -> None:
        self.assertEqual(ndf._security_hash(b''), 0)
        # hashes of the two descriptors format.py writes, as found in the
        # $SDS entry headers of chkdsk-accepted volumes
        sds, entries = FMT.build_sds()
        for sid_id, (h, off, length) in entries.items():
            stored = struct.unpack_from('<I', sds, off)[0]
            self.assertEqual(stored, h, hex(sid_id))
            body = sds[off + 20:off + length]
            self.assertEqual(ndf._security_hash(bytes(body)), h)


class NtfsDirentFixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.img = NtfsImage()
        self.addCleanup(self.img.dispose)

    # -- scan / inspect on a clean directory --

    def test_scan_and_inspect_healthy(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolume(self.img.path) as vol:
            entries = [e for e in vol.scan_dir('/repro') if e['status'] != 'dir-self']
            self.assertTrue(entries and all(e['status'] == 'ok' for e in entries))
            verdict = vol.classify_dirent('/repro', 'keep.py')
        self.assertEqual(verdict['state'], 'healthy')

    # -- dangling entry, record freed: rm removes it --

    def test_record_free_rm(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/gone.py': b'x\n'})
        corrupt_record_free(self.img.path, 'gone.py')

        with ndf.RawVolume(self.img.path) as vol:
            self.assertEqual(vol.classify_dirent('/repro', 'gone.py')['state'], 'record-free')
        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.remove_dirent('/repro', 'gone.py', really=True)

        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

    # -- dangling entry onto a live in-use record: purge reclaims it fully --

    def test_orphan_purge_frees_record(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/orphan.py': b'y' * 8192})
        corrupt_orphan(self.img.path, 'orphan.py')

        with ndf.RawVolume(self.img.path) as vol:
            verdict = vol.classify_dirent('/repro', 'orphan.py')
        self.assertEqual(verdict['state'], 'orphan')
        record_no = verdict['dirent_record']

        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.purge_orphan('/repro', 'orphan.py', really=True)

        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])
        # The record itself must now be free (in-use flag cleared).
        mft_off, rec_size, _ = _geometry(self.img.path)
        rec = _read(self.img.path)[mft_off + record_no * rec_size:][:rec_size]
        self.assertFalse(struct.unpack_from('<H', rec, 22)[0] & 1, 'record should be freed')

    # -- dangling entry onto a REUSED record: purge refuses, rm leaves record --

    def test_record_reused_rm_only(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/reusedme.dat': b'z\n'})
        corrupt_record_reused(self.img.path, 'reusedme.dat', 'squatter.dat')
        record_no = _find_file_record(self.img.path, 'squatter.dat')[0]

        with ndf.RawVolume(self.img.path) as vol:
            verdict = vol.classify_dirent('/repro', 'reusedme.dat')
        self.assertEqual(verdict['state'], 'record-reused')

        with ndf.RawVolumeRW(self.img.path) as vol:
            with self.assertRaises(SystemExit):
                vol.purge_orphan('/repro', 'reusedme.dat', really=True)
            vol.remove_dirent('/repro', 'reusedme.dat', really=True)

        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])
        mft_off, rec_size, _ = _geometry(self.img.path)
        rec = _read(self.img.path)[mft_off + record_no * rec_size:][:rec_size]
        self.assertTrue(struct.unpack_from('<H', rec, 22)[0] & 1, 'reused record must stay in use')

    # -- cross-linked: (record, seq) match but the name isn't in the record --

    def test_cross_linked_rm_only(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/victimme.dat': b'v\n'})
        corrupt_cross_link(self.img.path, 'victimme.dat', 'squatter.dat')

        with ndf.RawVolume(self.img.path) as vol:
            entries = {e['name']: e for e in vol.scan_dir('/repro')}
            self.assertIn('cross-linked', entries['victimme.dat']['status'])
            verdict = vol.classify_dirent('/repro', 'victimme.dat')
        self.assertEqual(verdict['state'], 'cross-linked')
        record_no = verdict['dirent_record']

        with ndf.RawVolumeRW(self.img.path) as vol:
            with self.assertRaises(SystemExit):
                vol.purge_orphan('/repro', 'victimme.dat', really=True)
            vol.remove_dirent('/repro', 'victimme.dat', really=True)

        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])
        mft_off, rec_size, _ = _geometry(self.img.path)
        rec = _read(self.img.path)[mft_off + record_no * rec_size:][:rec_size]
        self.assertTrue(struct.unpack_from('<H', rec, 22)[0] & 1,
                        'cross-linked record must stay in use')

    # -- dry runs must not modify the image --

    def test_dry_run_is_noop(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/orphan.py': b'y' * 4096})
        corrupt_orphan(self.img.path, 'orphan.py')
        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.purge_orphan('/repro', 'orphan.py', really=False)
        # semantic no-op: entry still present and still dangling, record in use
        with ndf.RawVolume(self.img.path) as vol:
            self.assertEqual(vol.classify_dirent('/repro', 'orphan.py')['state'],
                             'orphan')

    # -- torn INDX block: census recovers every name, rebuild restores the index --

    def test_torn_index_rebuild(self) -> None:
        files = {f'bigdir/bigfile_{i:02d}.dat': f'content-{i}\n'.encode() for i in range(1, 61)}
        self.img.populate(files, dirs=('bigdir/subdir',))
        expected = sorted(self.img.list_dir('bigdir'))  # readable pre-tear

        torn = tear_index_block(self.img.path, 'bigfile_')
        self.assertGreater(torn, 0)

        with ndf.RawVolume(self.img.path) as vol:
            mft_no = vol._resolve('/bigdir')
            self.assertFalse(vol.probe_dir('/bigdir')['readable'], 'index should read as torn')
            census = {c['name'] for c in vol.children_from_mft(mft_no)['children']}
        self.assertEqual(census, set(expected), 'MFT census must recover every name')

        with ndf.RawVolumeRW(self.img.path) as vol:
            result = vol.rebuild_dir('/bigdir')
        self.assertEqual(result['added'], len(expected))

        with ndf.RawVolume(self.img.path) as vol:
            verify = vol.probe_dir('/bigdir')
        self.assertTrue(verify['readable'])
        self.assertFalse([e for e in verify['entries'] if e['status'] != 'ok'])
        self.assertEqual(self.img.list_dir('bigdir'), expected)

    # -- census must not resurrect a name whose parent seq is stale --

    def test_stale_parent_seq_excluded_from_census(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/stale.py': b'x\n'})
        corrupt_parent_seq(self.img.path, 'stale.py')

        with ndf.RawVolume(self.img.path) as vol:
            census = vol.children_from_mft(vol._resolve('/repro'))

        self.assertEqual({c['name'] for c in census['children']}, {'keep.py'})
        self.assertGreaterEqual(census['stale_parent'], 1)

    # -- name comparison must come from the volume's own $UpCase table --

    def test_upcase_names_equal(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolume(self.img.path) as vol:
            self.assertTrue(vol.names_equal('MiXeD.DaT', 'mixed.dat'))
            self.assertFalse(vol.names_equal('a.dat', 'b.dat'))
            self.assertFalse(vol.names_equal('short.py', 'longer.py'))

    def test_classify_non_ascii_orphan(self) -> None:
        name = 'órphän.py'
        self.img.populate({'repro/keep.py': b'ok\n', f'repro/{name}': b'y' * 4096})
        corrupt_orphan(self.img.path, name)
        with ndf.RawVolume(self.img.path) as vol:
            self.assertEqual(vol.classify_dirent('/repro', name)['state'], 'orphan')

    def test_rebuild_refuses_healthy_without_force(self) -> None:
        self.img.populate({'bigdir/a.dat': b'1\n', 'bigdir/b.dat': b'2\n'})
        proc = self._cli('rebuild', self.img.path, '/bigdir')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('refusing to rebuild', proc.stdout.lower())

    # -- fix (/f): the full-volume chkdsk /f flow --

    def _cli(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'checkdisk.py'),
             *argv],
            capture_output=True, text=True)

    def test_fix_healthy_volume_exits_zero(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'a/b/c/deep.txt': b'x\n'})
        proc = self._cli('/f', self.img.path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('0 dangling entries, 0 torn indexes', proc.stdout)

    def test_fix_flow_repairs_full_volume(self) -> None:
        files = {'repro/keep.py': b'ok\n', 'repro/gone.py': b'x\n',
                 'repro/orphan.py': b'y' * 4096}
        files.update({f'bigdir/bigfile_{i:02d}.dat': f'c{i}\n'.encode()
                      for i in range(1, 61)})
        self.img.populate(files, dirs=('bigdir/subdir',))
        bigdir_expected = self.img.list_dir('bigdir')
        corrupt_record_free(self.img.path, 'gone.py')
        corrupt_orphan(self.img.path, 'orphan.py')
        tear_index_block(self.img.path, 'bigfile_')

        # dry run: reports everything, exits 1, changes nothing
        before = self.img.md5()
        proc = self._cli('/f', self.img.path)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("'/repro/gone.py': record-free", proc.stdout)
        self.assertIn("'/repro/orphan.py': orphan", proc.stdout)
        self.assertIn("torn index: '/bigdir'", proc.stdout)
        self.assertIn('DRY RUN', proc.stdout)
        self.assertEqual(self.img.md5(), before, 'dry run must not write')

        # --really: fixes everything, exits 0
        proc = self._cli('/f', self.img.path, '--really')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('2 dangling entries, 1 torn index; 3 fixed, 0 remaining',
                      proc.stdout)

        # volume is clean now: /f exits 0 and the driver agrees
        proc = self._cli('/f', self.img.path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])
        self.assertEqual(self.img.list_dir('bigdir'), bigdir_expected)

    # -- stage 1: torn truncate-to-zero is detected and safely repaired --

    def test_fix_repairs_torn_truncate(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/fat.bin': b'y' * 8192})
        corrupt_torn_truncate(self.img.path, 'fat.bin')

        proc = self._cli('/f', self.img.path)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn('phantom run', proc.stdout)

        proc = self._cli('/f', self.img.path, '--really')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('runlist terminated', proc.stdout)

        proc = self._cli('/f', self.img.path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        # the repaired record now describes a consistent, empty stream
        with ndf.RawVolume(self.img.path) as v:
            e = next(x for x in v.scan_dir('/repro') if x['name'] == 'fat.bin')
            self.assertEqual(v._attr_value(e['record'], ndf.AT_DATA, None), b'')

    # -- stage 5: $Bitmap reconciliation --

    def _patch_bitmap_byte(self, offset: int, value: int) -> None:
        patch_stream(self.img.path, ndf.FILE_BITMAP, ndf.AT_DATA, '',
                     offset, bytes([value]))

    def test_bitmap_audit_and_fix(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolume(self.img.path) as vol:
            base = vol.cluster_audit()
        self.assertEqual((base['extra'], base['missing'], base['failures']),
                         (0, 0, []), 'fresh volume must audit clean')

        self._patch_bitmap_byte(1200, 0xFF)  # mark free clusters used -> extra
        self._patch_bitmap_byte(0, 0x00)     # mark boot/system free -> missing
        with ndf.RawVolume(self.img.path) as vol:
            audit = vol.cluster_audit()
        self.assertGreater(audit['extra'], 0)
        self.assertGreater(audit['missing'], 0)

        proc = self._cli('/f', self.img.path, '--really')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('$Bitmap rewritten and verified', proc.stdout)
        with ndf.RawVolume(self.img.path) as vol:
            audit = vol.cluster_audit()
        self.assertEqual((audit['extra'], audit['missing']), (0, 0))
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

    # -- backup: boot + $MFT + $MFTMirr + per-dir INDX land on disk --

    def test_backup_command(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        out = tempfile.mkdtemp(prefix='ndf-bak-')
        self.addCleanup(shutil.rmtree, out)
        proc = self._cli('backup', self.img.path, out, '/repro')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        with os.scandir(out) as it:
            names = {entry.name for entry in it}
        self.assertLessEqual({'boot-16k.bin', 'mft.bin', 'mftmirr.bin', 'SHA256SUMS'},
                             names)
        self.assertGreater(os.path.getsize(os.path.join(out, 'mft.bin')), 0)
        self.assertTrue(any(n.endswith('-path.txt') for n in names))

    # -- USN journal: fabricated $UsnJrnl-style streams validate and reset --

    def _make_usn_file(self, jstream: bytes, jid: int = 0xABCDEF) -> None:
        '''A $UsnJrnl lookalike at /usnlab: $Max + $J named streams '''

        self.img.populate({'usnlab': b''})
        with ndf.RawVolume(self.img.path) as v:
            rec_no = v._resolve('/usnlab')
        maxblob = struct.pack('<QQQQ', 32 * 1024 * 1024, 8 * 1024 * 1024, jid, 0)
        add_named_data(self.img.path, rec_no, '$J', jstream)
        add_named_data(self.img.path, rec_no, '$Max', maxblob)

    def test_usn_check_and_reset(self) -> None:
        self._make_usn_file(usn_stream('a.txt', 'b.txt'))
        with ndf.RawVolume(self.img.path) as vol:
            info = vol.usn_check(path='/usnlab')
        self.assertTrue(info['present'])
        self.assertEqual((info['records'], info['problems']), (2, []))
        self.assertEqual(info['journal_id'], 0xABCDEF)

        # corrupt the first record's Usn field -> finding
        with ndf.RawVolume(self.img.path) as v:
            rec_no = v._resolve('/usnlab')
        patch_stream(self.img.path, rec_no, ndf.AT_DATA, '$J',
                     24, struct.pack('<q', 4242))
        with ndf.RawVolume(self.img.path) as vol:
            info = vol.usn_check(path='/usnlab')
        self.assertTrue(any('claims usn 4242' in p for p in info['problems']))

        # reset: $J truncated to 0, $Max restamped with a fresh id
        with ndf.RawVolumeRW(self.img.path) as vol:
            new_id = vol.usn_reset(path='/usnlab')
        with ndf.RawVolume(self.img.path) as vol:
            info = vol.usn_check(path='/usnlab')
        self.assertEqual((info['records'], info['problems'], info['next_usn']),
                         (0, [], 0))
        self.assertEqual(info['journal_id'], new_id)
        self.assertNotEqual(new_id, 0xABCDEF)

    def test_usn_cli_no_journal(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        proc = self._cli('usn', self.img.path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('no USN journal', proc.stdout)

    # -- $Secure: descriptor store + $SII/$SDH validation and repair --

    def _patch_secure_attr(self, attr_type: int, name: str, offset: int,
                           blob: bytes) -> None:
        patch_stream(self.img.path, ndf.FILE_SECURE, attr_type, name,
                     offset, blob)

    def test_secure_healthy(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolume(self.img.path) as vol:
            chk = vol.secure_check()
        self.assertTrue(chk['present'])
        self.assertGreater(chk['descriptors'], 0)
        self.assertEqual((chk['problems'], chk['mirror_fixes'],
                          chk['index_problems'], chk['ref_missing']),
                         ([], [], [], []), chk)

    def test_secure_mirror_repair(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolume(self.img.path) as vol:
            chk = vol.secure_check()
        sid, (_h, off, length) = sorted(chk['sds_entries'].items())[0]
        # flip one byte inside the primary copy's descriptor body
        self._patch_secure_attr(ndf.AT_DATA, '$SDS', off + 24, b'\xEE')

        with ndf.RawVolume(self.img.path) as vol:
            chk = vol.secure_check()
        self.assertEqual([f[2] for f in chk['mirror_fixes']], ['mirror'],
                         'the intact mirror side must be chosen as the source')
        proc = self._cli('secure', self.img.path, '--really')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        with ndf.RawVolume(self.img.path) as vol:
            chk = vol.secure_check()
        self.assertEqual(chk['mirror_fixes'], [])
        self.assertEqual(chk['problems'], [])

    def test_secure_index_rebuild(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        # corrupt the security_id inside the first $SII root entry's data
        with ndf.RawVolume(self.img.path) as vol:
            root = vol._read_whole_attr(ndf.FILE_SECURE, ndf.AT_INDEX_ROOT,
                                        '$SII'.encode('utf-16-le'), 4)
        entries_ofs = struct.unpack_from('<I', root, 16)[0]
        entry = 16 + entries_ofs
        data_ofs = struct.unpack_from('<H', root, entry)[0]
        self._patch_secure_attr(ndf.AT_INDEX_ROOT, '$SII',
                                entry + data_ofs + 4, struct.pack('<I', 0xDEAD))

        with ndf.RawVolume(self.img.path) as vol:
            chk = vol.secure_check()
        self.assertTrue(chk['index_problems'], chk)
        proc = self._cli('secure', self.img.path, '--really')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('rebuilt from $SDS', proc.stdout)
        with ndf.RawVolume(self.img.path) as vol:
            self.assertEqual(vol.secure_check()['index_problems'], [])
            # the rebuilt roots parse back entry-for-entry against $SDS
            for nm, kfmt in (('$SII', '<I'), ('$SDH', '<II')):
                bn = nm.encode('utf-16-le')
                root = vol._read_whole_attr(ndf.FILE_SECURE, ndf.AT_INDEX_ROOT, bn, 4)
                idx, probs = ndf._view_index_entries(
                    root, None, None, nm,
                    key_fn=lambda k, f=kfmt: struct.unpack_from(f, k))
                self.assertEqual(probs, [])
                self.assertEqual(len(idx), len(chk['sds_entries']))
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

    def test_secure_index_rebuild_single_block(self) -> None:
        '''More descriptors than a resident root holds → native rebuild lays them
           out in a single INDX block (the case-2 view-index path), in collation
           order and re-parseable.'''
        self.img.populate({'d/a.txt': b'x'})
        synth = {sid: ((sid * 2654435761) & 0xffffffff, sid * 20, 20)
                 for sid in range(256, 296)}               # 40 descriptors
        with ndf.RawVolumeRW(self.img.path) as v:
            assert v.rebuild_secure_indexes(synth)['added'] == 80   # 40 $SII + 40 $SDH
        for nm, kfmt in (('$SII', '<I'), ('$SDH', '<II')):
            bn = nm.encode('utf-16-le')
            with ndf.RawVolume(self.img.path) as v:
                root = v._read_whole_attr(ndf.FILE_SECURE, ndf.AT_INDEX_ROOT, bn, 4)
                alloc = v._read_whole_attr(ndf.FILE_SECURE, ndf.AT_INDEX_ALLOCATION, bn, 4)
                bmp = v._read_whole_attr(ndf.FILE_SECURE, ndf.AT_BITMAP, bn, 4)
            assert alloc, f'{nm} should have become a single-block large index'
            idx, probs = ndf._view_index_entries(
                root, alloc, bmp, nm,
                key_fn=lambda k, f=kfmt: struct.unpack_from(f, k))
            assert probs == [], (nm, probs)
            assert len(idx) == 40, (nm, len(idx))
            keys = [struct.unpack_from(kfmt, k) for k, _d in idx]
            assert keys == sorted(keys), nm

    def test_secure_index_rebuild_multiblock(self) -> None:
        '''Enough descriptors to need a multi-block view index → the native
           rebuild bulk-loads a valid multi-level B-tree with every descriptor
           present (the case that used to be report-only ENOSYS).'''
        self.img.populate({'d/a.txt': b'x'})
        synth = {sid: ((sid * 2654435761) & 0xffffffff, sid * 20, 20)
                 for sid in range(256, 456)}               # 200 descriptors
        with ndf.RawVolumeRW(self.img.path) as v:
            assert v.rebuild_secure_indexes(synth)['added'] == 400
        for nm, kfmt, id_of in (('$SII', '<I', lambda k: struct.unpack_from('<I', k)[0]),
                                ('$SDH', '<II', lambda k: struct.unpack_from('<II', k)[1])):
            bn = nm.encode('utf-16-le')
            with ndf.RawVolume(self.img.path) as v:
                root = v._read_whole_attr(ndf.FILE_SECURE, ndf.AT_INDEX_ROOT, bn, 4)
                alloc = v._read_whole_attr(ndf.FILE_SECURE, ndf.AT_INDEX_ALLOCATION, bn, 4)
                bmp = v._read_whole_attr(ndf.FILE_SECURE, ndf.AT_BITMAP, bn, 4)
            bs = struct.unpack_from('<I', root, 8)[0]
            assert len(alloc) > bs, f'{nm} should span more than one INDX block'
            idx, probs = ndf._view_index_entries(
                root, alloc, bmp, nm,
                key_fn=lambda k, f=kfmt: struct.unpack_from(f, k))
            assert probs == [], (nm, probs)
            assert sorted(id_of(k) for k, _d in idx) == sorted(synth), (nm, len(idx))

    def test_secure_dangling_reference_reported(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        _, off = _find_file_record(self.img.path, 'keep.py')
        rec = _read(self.img.path)[off:off + _geometry(self.img.path)[1]]
        a = struct.unpack_from('<H', rec, 20)[0]
        assert struct.unpack_from('<I', rec, a)[0] == 0x10, 'SI should be first'
        value_ofs = struct.unpack_from('<H', rec, a + 20)[0]
        _patch(self.img.path, off + a + value_ofs + 52, struct.pack('<I', 0xBEEF))

        with ndf.RawVolume(self.img.path) as vol:
            chk = vol.secure_check()
        self.assertTrue(any('48879' in p for p in chk['ref_missing']), chk)

    # -- surface scan: owner attribution + clean CLI run --

    def test_surface_owner_attribution(self) -> None:
        self.img.populate({'repro/fat.bin': b'y' * 8192})
        lcn = first_data_lcn(self.img.path, 'fat.bin')
        with ndf.RawVolume(self.img.path) as vol:
            free_probe = vol.nr_clusters() - 2  # tail of a fresh volume: free
            owners = vol.surface_owners({lcn, free_probe})
        owned = [o for o in owners if o['record'] is not None]
        self.assertTrue(any('fat.bin' in o['names'] and lcn in o['clusters']
                            for o in owned), owners)
        free = [o for o in owners if o['record'] is None]
        self.assertTrue(free and free_probe in free[0]['clusters'], owners)

    def test_surface_cli_direct(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        proc = self._cli('surface', self.img.path, '--direct')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('0 unreadable cluster(s)', proc.stdout)

    def test_surface_cli_clean(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        proc = self._cli('surface', self.img.path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('0 unreadable cluster(s)', proc.stdout)

    def test_raw_backend_usn(self) -> None:
        self._make_usn_file(usn_stream('a.txt', 'b.txt'))
        with ndf.RawVolume(self.img.path) as raw:
            info = raw.usn_check(path='/usnlab')
        self.assertEqual((info['records'], info['problems'], info['journal_id']),
                         (2, [], 0xABCDEF))

    def test_raw_cli_scan_and_native_write(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/gone.py': b'x\n'})
        corrupt_record_free(self.img.path, 'gone.py')
        env = dict(os.environ, CHECKDISK_NO_LIB='1')
        cli = [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'checkdisk.py')]
        proc = subprocess.run(cli + ['scan', self.img.path, '/repro'],
                              capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn('record not in use', proc.stdout)
        # the native engine performs the removal
        proc = subprocess.run(cli + ['rm', self.img.path, '/repro', 'gone.py',
                                     '--really'], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('removed', proc.stdout)
        proc = subprocess.run(cli + ['scan', self.img.path, '/repro'],
                              capture_output=True, text=True, env=env)
        self.assertNotIn('gone.py', proc.stdout)

    # -- lost files: detected volume-wide, reconnected into a live parent --

    def test_lost_file_reconnected(self) -> None:
        content = b'do not lose me\n' * 100
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/lostme.bin': content})
        # fabricate exactly the torn-rename shape: a live record whose index
        # entry vanished — our own rm removes the entry of a healthy file
        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.remove_dirent('/repro', 'lostme.bin', really=True)
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

        proc = self._cli('/f', self.img.path)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("lost file 'lostme.bin'", proc.stdout)
        self.assertIn('live parent', proc.stdout)

        proc = self._cli('/f', self.img.path, '--really')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('reconnected', proc.stdout)

        proc = self._cli('/f', self.img.path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.img.list_dir('repro'), ['keep.py', 'lostme.bin'])
        with ndf.RawVolume(self.img.path) as v:
            e = next(x for x in v.scan_dir('/repro') if x['name'] == 'lostme.bin')
            self.assertEqual(v._attr_value(e['record'], ndf.AT_DATA, None),
                             content, 'content must survive intact')

    # -- survey extras: orphaned extensions, link counts, view indexes --

    def test_survey_flags_orphaned_extension(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/victim.bin': b'v\n'})
        _, off = _find_file_record(self.img.path, 'victim.bin')
        _patch(self.img.path, off + 32, struct.pack('<Q', 999 | (5 << 48)))
        with ndf.RawVolume(self.img.path) as vol:
            s = vol.mft_survey()
        self.assertTrue(any('orphaned extension' in p['problem']
                            for p in s['runlist_problems']), s['runlist_problems'])

    def test_survey_flags_wrong_link_count(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/victim.bin': b'v\n'})
        _, off = _find_file_record(self.img.path, 'victim.bin')
        _patch(self.img.path, off + 18, struct.pack('<H', 7))
        with ndf.RawVolume(self.img.path) as vol:
            s = vol.mft_survey()
        self.assertTrue(any('hard-link count 7' in p['problem']
                            for p in s['runlist_problems']), s['runlist_problems'])

    def test_view_index_clean_on_healthy(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolume(self.img.path) as vol:
            vw = vol.view_index_check()
        self.assertEqual(vw['problems'], [], vw)

    # -- native write engine, phase 1 --

    def test_native_torn_truncate_repair(self) -> None:
        '''A phantom runlist is found, terminated, and the volume surveys
           clean afterwards.'''
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/fat.bin': b'y' * 8192})
        corrupt_torn_truncate(self.img.path, 'fat.bin')

        with ndf.RawVolumeRW(self.img.path) as vol:
            probs = [p for p in vol.mft_survey()['runlist_problems']
                     if p['fix_mp_off'] is not None]
            self.assertEqual(len(probs), 1)
            vol.terminate_mapping_pairs(probs[0]['record'], probs[0]['fix_mp_off'])

        with ndf.RawVolume(self.img.path) as v:
            s = v.mft_survey(want_used=True)
            self.assertEqual(s['runlist_problems'], [])
            e = next(x for x in v.scan_dir('/repro') if x['name'] == 'fat.bin')
            self.assertEqual(v._attr_value(e['record'], ndf.AT_DATA, None), b'')
            flags = struct.unpack_from('<H', v._attr_value(3, 0x70, None), 10)[0]
        self.assertFalse(flags & 1, 'clean close must clear the dirty flag')

    def test_native_write_record_syncs_mftmirr(self) -> None:
        '''Rewriting record 0 (content unchanged, USN bumped) must keep
           $MFTMirr byte-in-sync — drivers refuse to mount when it diverges.'''
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolumeRW(self.img.path) as vol:
            rec = bytearray(vol.read_record(0))
            assert ndf._apply_fixups(rec)
            vol.write_record(0, rec)
        with ndf.RawVolume(self.img.path) as v:
            csz = v._cluster_size
            data = _read(self.img.path)
            boot = data[:512]
            mft_lcn = struct.unpack_from('<Q', boot, 48)[0]
            mirr_lcn = struct.unpack_from('<Q', boot, 56)[0]
            rsz = v._rec_size
        self.assertEqual(data[mft_lcn * csz:mft_lcn * csz + 4 * rsz],
                         data[mirr_lcn * csz:mirr_lcn * csz + 4 * rsz],
                         '$MFTMirr must mirror the first four records')
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

    # -- native write engine, phase 2: allocators (stage 5 as oracle) --

    def test_native_cluster_allocator_audit_oracle(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolumeRW(self.img.path) as vol:
            base = vol.cluster_audit()
            self.assertEqual((base['extra'], base['missing']), (0, 0))
            runs = vol.alloc_clusters(10, near_lcn=100)
            self.assertEqual(sum(r[1] for r in runs), 10)
            audit = vol.cluster_audit()
            self.assertEqual((audit['extra'], audit['missing']), (10, 0),
                             'allocated-unreferenced clusters must audit as leak')
            with self.assertRaises(ndf.NtfsError):   # double-alloc protection
                vol.free_clusters(runs + runs)
            vol.free_clusters(runs)
            audit = vol.cluster_audit()
            self.assertEqual((audit['extra'], audit['missing']), (0, 0))
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

    def test_native_mft_record_allocator(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n'})
        with ndf.RawVolumeRW(self.img.path) as vol:
            a = vol.alloc_record()
            b = vol.alloc_record()
            self.assertGreaterEqual(a, 24)
            self.assertNotEqual(a, b, 'second alloc must pick a different slot')
        # free + realloc determinism, through a fresh volume handle
        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.free_record(a)
            vol.free_record(b)
            with self.assertRaises(ndf.NtfsError):  # double free refused
                vol.free_record(a)
            self.assertEqual(vol.alloc_record(), a, 'first-fit must reuse slot a')
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

    # -- native write engine, phase 3: leaf index-entry removal --

    @staticmethod
    def _referenced(vol):
        '''The set of records reachable by walking every directory index —
           what find_lost_files diffs against.'''
        refs, stack, seen = set(), [ndf.FILE_ROOT], {ndf.FILE_ROOT}
        while stack:
            probe = vol.probe_dir_no(stack.pop())
            if not probe['readable']:
                continue
            for e in probe['entries']:
                if e['status'] == 'ok':
                    refs.add(e['record'])
                    if e.get('is_dir') and e['record'] not in seen:
                        seen.add(e['record'])
                        stack.append(e['record'])
        return refs

    def test_native_rm_root(self) -> None:
        '''Small (root-resident) directory: native rm leaves a clean,
           collation-ordered directory.'''
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/gone.py': b'x\n',
                           'repro/third.py': b'3\n'})
        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.remove_dirent('/repro', 'gone.py', really=True)
        self.assertEqual(self.img.list_dir('repro'), ['keep.py', 'third.py'])
        with ndf.RawVolume(self.img.path) as v:
            bad = [e for e in v.scan_dir('/repro')
                   if e['status'] not in ('ok', 'dir-self')]
        self.assertEqual(bad, [])

    def test_native_rm_indx_leaf(self) -> None:
        '''Large directory (2-level tree): remove a leaf entry natively;
           the remaining set must be exact and clean.'''
        files = {f'big/file_{i:04d}.dat': f'c{i}\n'.encode() for i in range(400)}
        self.img.populate(files)
        # pick a name guaranteed to be in a leaf: not any internal separator
        _dir_no, seps = self._separators('/big')
        target = next(f'file_{i:04d}.dat' for i in range(400)
                      if f'file_{i:04d}.dat' not in seps)

        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.remove_dirent('/big', target, really=True)

        expect = sorted(f'file_{i:04d}.dat' for i in range(400)
                        if f'file_{i:04d}.dat' != target)
        self.assertEqual(self.img.list_dir('big'), expect)

    @staticmethod
    def _node_names(buf, hdr_off):
        '''Names of the NODE (internal separator) entries in one index node.'''
        out, (eo, il) = [], struct.unpack_from('<II', buf, hdr_off)
        pos = hdr_off + eo
        while pos + 16 <= hdr_off + il:
            length = struct.unpack_from('<H', buf, pos + 8)[0]
            flags = struct.unpack_from('<H', buf, pos + 12)[0]
            if length < 16:
                break
            if not flags & 2 and flags & 1:  # real key with a subnode
                nl = buf[pos + 16 + 64]
                out.append(bytes(buf[pos + 16 + 66:pos + 16 + 66 + 2 * nl])
                           .decode('utf-16-le'))
            if flags & 2:
                break
            pos += length
        return out

    def _separators(self, path):
        '''Every internal-node separator name across root + all INDX blocks.'''
        with ndf.RawVolume(self.img.path) as vol:
            dir_no = vol._resolve(path)
            root = vol._attr_value(dir_no, ndf.AT_INDEX_ROOT, vol.I30)
            names = list(self._node_names(root, 16))
            bs = struct.unpack_from("<I", root, 8)[0]
            try:
                alloc = vol._attr_value(dir_no, ndf.AT_INDEX_ALLOCATION, vol.I30)
            except ndf.NtfsError:
                alloc = b''
            for i in range(len(alloc) // bs):
                blk = bytearray(alloc[i * bs:(i + 1) * bs])
                if blk[:4] == b'INDX' and ndf._apply_fixups(blk):
                    names += self._node_names(blk, 24)
        return dir_no, set(names)

    def test_native_rm_internal_node(self) -> None:
        '''Remove an INTERNAL separator (predecessor promotion) natively;
           every remaining file must be present exactly once.'''
        self.img.populate({f'big/file_{i:04d}.dat': b'x' for i in range(600)})
        dir_no, seps = self._separators('/big')
        self.assertTrue(seps, 'expected internal-node separators somewhere')
        target = sorted(seps)[0]

        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.remove_index_entry(dir_no, target)

        expect = sorted(f'file_{i:04d}.dat' for i in range(600)
                        if f'file_{i:04d}.dat' != target)
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir('/big')
                           if e['status'] != 'dir-self')
            self.assertEqual(names, expect, 'native internal removal set mismatch')
            self.assertEqual(len(names), len(set(names)), 'duplicate key!')

    def test_native_rm_in_fix_flow(self) -> None:
        '''A record-free dangling entry removed by the native engine, then
           the volume verifies clean and the driver lists correctly.'''
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/gone.py': b'x\n'})
        corrupt_record_free(self.img.path, 'gone.py')
        with ndf.RawVolumeRW(self.img.path) as vol:
            self.assertEqual(vol.classify_dirent('/repro', 'gone.py')['state'],
                             'record-free')
            vol.remove_dirent('/repro', 'gone.py', really=True)
        with ndf.RawVolume(self.img.path) as vol:
            self.assertEqual([e for e in vol.scan_dir('/repro')
                              if e['status'] not in ('ok', 'dir-self')], [])
        self.assertEqual(self.img.list_dir('repro'), ['keep.py'])

    # -- native write engine, phase 4: index-entry insertion / reconnection --

    def test_native_reconnect_root_grow(self) -> None:
        '''Small directory: make a lost file (remove its entry, record stays
           live), reconnect it natively; the directory must list it again and
           the content must read back intact.'''
        content = b'reconnect me\n' * 40
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/lost.bin': content,
                           'repro/mid.py': b'm\n'})
        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.remove_dirent('/repro', 'lost.bin', really=True)
        with ndf.RawVolumeRW(self.img.path) as vol:
            lost = [l for l in vol.find_lost_files(self._referenced(vol))
                    if l['name'] == 'lost.bin'][0]
            self.assertEqual(vol.reconnect_lost(lost), 1)

        self.assertEqual(self.img.list_dir('repro'),
                         ['keep.py', 'lost.bin', 'mid.py'])
        with ndf.RawVolume(self.img.path) as v:
            e = next(x for x in v.scan_dir('/repro') if x['name'] == 'lost.bin')
            self.assertEqual(v._attr_value(e['record'], ndf.AT_DATA, None), content)

    def test_native_reconnect_indx_leaf(self) -> None:
        '''Large directory: reconnect a lost file whose name lands in an
           INDX leaf that has room.'''
        self.img.populate({f'big/file_{i:04d}.dat': b'x' for i in range(500)})
        victim = 'file_0250.dat'
        with ndf.RawVolumeRW(self.img.path) as vol:
            vol.remove_dirent('/big', victim, really=True)
        with ndf.RawVolumeRW(self.img.path) as vol:
            lost = [l for l in vol.find_lost_files(self._referenced(vol))
                    if l['name'] == victim][0]
            vol.reconnect_lost(lost)

        expect = sorted(f'file_{i:04d}.dat' for i in range(500))
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir('/big')
                           if e['status'] != 'dir-self')
            self.assertEqual(names, expect)
            self.assertEqual(len(names), len(set(names)), 'duplicate key!')

    def test_native_insert_ordering_and_dup(self) -> None:
        '''Insertion must land in collation order and refuse a duplicate.'''
        self.img.populate({'d/bbb.txt': b'b', 'd/mmm.txt': b'm', 'd/yyy.txt': b'y'})
        with ndf.RawVolume(self.img.path) as v:
            dno = v._resolve('/d')
            info = v.record_info  # noqa
        # forge a leaf entry for 'ggg.txt' pointing at an unused-but-plausible
        # ref is unnecessary: reuse mmm.txt's own record so the entry resolves
        with ndf.RawVolume(self.img.path) as v:
            dno = v._resolve('/d')
            e = next(x for x in v.scan_dir('/d') if x['name'] == 'mmm.txt')
            fn = None
            for frozen, a, _l in v._record_attrs(e['record']):
                if struct.unpack_from('<I', frozen, a)[0] == ndf.AT_FILE_NAME and frozen[a + 8] == 0:
                    vo = struct.unpack_from('<H', frozen, a + 20)[0]
                    vl = struct.unpack_from('<I', frozen, a + 16)[0]
                    fn = bytes(frozen[a + vo:a + vo + vl])
                    break
        # rename the key bytes to 'ggg.txt' (same length) to insert a new order slot
        new_fn = bytearray(fn)
        nm = 'ggg.txt'.encode('utf-16-le')
        new_fn[66:66 + len(nm)] = nm
        with ndf.RawVolumeRW(self.img.path) as v:
            v.insert_index_entry(dno, e['mref'], bytes(new_fn))
            with self.assertRaises(ndf.NtfsError):     # duplicate refused
                v.insert_index_entry(dno, e['mref'], bytes(new_fn))
        with ndf.RawVolume(self.img.path) as v:
            names = [x['name'] for x in v.scan_dir('/d') if x['status'] != 'dir-self']
        self.assertEqual(names, sorted(names), 'entries must stay collation-ordered')
        self.assertIn('ggg.txt', names)

    # -- native write engine, phase 5: purge composition --

    def test_native_purge_orphan(self) -> None:
        '''A seq-bumped in-use orphan, purged natively: the record and its
           clusters are freed (stage-5 audit clean) and the entry is gone.'''
        self.img.populate({'repro/keep.py': b'ok\n',
                           'repro/orphan.py': b'y' * 8192})
        corrupt_orphan(self.img.path, 'orphan.py')

        with ndf.RawVolumeRW(self.img.path) as vol:
            v = vol.classify_dirent('/repro', 'orphan.py')
            self.assertEqual(v['state'], 'orphan')
            rec_no = v['dirent_record']
            vol.purge_orphan('/repro', 'orphan.py', really=True)

        # native result: record freed, bitmap consistent, entry gone
        with ndf.RawVolume(self.img.path) as vol:
            audit = vol.cluster_audit()
            self.assertEqual((audit['extra'], audit['missing']), (0, 0),
                             'purge must leave $Bitmap consistent')
            names = [e['name'] for e in vol.scan_dir('/repro')
                     if e['status'] != 'dir-self']
            self.assertEqual(names, ['keep.py'])
        mft_off, rec_size, _ = _geometry(self.img.path)
        rec = _read(self.img.path)[mft_off + rec_no * rec_size:][:rec_size]
        self.assertFalse(struct.unpack_from('<H', rec, 22)[0] & 1,
                         'purged record must be freed (in-use cleared)')

    def test_native_purge_refuses_non_orphan(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/reusedme.dat': b'z\n'})
        corrupt_record_reused(self.img.path, 'reusedme.dat', 'squatter.dat')
        record_no = _find_file_record(self.img.path, 'squatter.dat')[0]
        with ndf.RawVolumeRW(self.img.path) as vol:
            self.assertEqual(vol.classify_dirent('/repro', 'reusedme.dat')['state'],
                             'record-reused')
            with self.assertRaises(SystemExit):
                vol.purge_orphan('/repro', 'reusedme.dat', really=True)
        # the live squatter record must be untouched (still in use)
        mft_off, rec_size, _ = _geometry(self.img.path)
        rec = _read(self.img.path)[mft_off + record_no * rec_size:][:rec_size]
        self.assertTrue(struct.unpack_from('<H', rec, 22)[0] & 1,
                        'reused record must stay in use')

    # -- native $LogFile reset (the 0xFF "clean log" shape) --

    def test_native_logfile_reset(self) -> None:
        self.img.populate({'repro/keep.py': b'ok\n', 'repro/two.py': b'2\n'})
        with ndf.RawVolumeRW(self.img.path) as vol:
            n = vol.reset_logfile()
            self.assertGreater(n, 0)
            vol.clear_dirty()
        # $LogFile is now wholly 0xff-filled (the "clean" shape) and the
        # volume still scans, with the dirty flag clear
        with ndf.RawVolume(self.img.path) as v:
            log = v._attr_value(2, ndf.AT_DATA, None)
            self.assertTrue(log and set(log) == {0xFF})
            self.assertEqual(self.img.list_dir('repro'), ['keep.py', 'two.py'])
            vi = v._attr_value(3, 0x70, None)
        self.assertFalse(struct.unpack_from('<H', vi, 10)[0] & 1)

    # -- $ATTRIBUTE_LIST purge pieces --

    def test_extension_records_parse(self) -> None:
        '''A hand-built resident $ATTRIBUTE_LIST must yield its extension refs.'''
        self.img.populate({'repro/keep.py': b'ok\n'})
        rsize = _geometry(self.img.path)[1]

        def ale(atype, mref):                     # one ATTRIBUTE_LIST_ENTRY
            b = bytearray(32)
            struct.pack_into('<I', b, 0, atype)   # type
            struct.pack_into('<H', b, 4, 32)      # entry length
            struct.pack_into('<Q', b, 16, mref)   # base record reference
            return bytes(b)

        with ndf.RawVolumeRW(self.img.path) as v:
            scratch = v.alloc_record()
        listing = ale(0x10, scratch) + ale(0x80, 77) + ale(0x80, 88)  # self + ext
        rec = bytearray(rsize)
        rec[:4] = b'FILE'
        struct.pack_into('<HH', rec, 4, rsize - 2, 1)   # usa_ofs, usa_count
        struct.pack_into('<H', rec, 16, 1)              # sequence
        struct.pack_into('<H', rec, 20, 56)             # first-attr offset
        struct.pack_into('<H', rec, 22, 1)              # flags: in use
        off, vlen = 56, len(listing)
        attr = bytearray(24 + vlen)
        struct.pack_into('<I', attr, 0, 0x20)           # $ATTRIBUTE_LIST
        struct.pack_into('<I', attr, 4, len(attr))      # attr length
        struct.pack_into('<I', attr, 16, vlen)          # value_length
        struct.pack_into('<H', attr, 20, 24)            # value_offset
        attr[24:24 + vlen] = listing
        rec[off:off + len(attr)] = attr
        struct.pack_into('<I', rec, off + len(attr), 0xFFFFFFFF)  # attr terminator
        struct.pack_into('<I', rec, 24, off + len(attr) + 4)     # bytes_in_use
        struct.pack_into('<I', rec, 28, rsize)                    # bytes_allocated

        with ndf.RawVolumeRW(self.img.path) as v:
            v.write_record(scratch, rec)
            exts = v._extension_records(scratch)
            v.free_record(scratch)
        self.assertEqual(exts, {77, 88}, 'self-entry excluded, extensions kept')

    # -- phase 4b: node split (bounded, atomic) --

    def test_native_leaf_split_reconnect(self) -> None:
        '''Reconnecting many lost files into a large dir forces leaf splits;
           the result must be complete and dup-free.'''
        self.img.populate({f'big/f{i:04d}.dat': b'x' for i in range(900)})
        import random
        rng = random.Random(4)
        victims = [f'f{i:04d}.dat' for i in sorted(rng.sample(range(900), 200))]
        with ndf.RawVolumeRW(self.img.path) as vol:
            for n in victims:
                vol.remove_dirent('/big', n, really=True)

        def lost(vol):
            refs, st, seen = set(), [ndf.FILE_ROOT], {ndf.FILE_ROOT}
            while st:
                p = vol.probe_dir_no(st.pop())
                if not p['readable']:
                    continue
                for e in p['entries']:
                    if e['status'] == 'ok':
                        refs.add(e['record'])
                        if e.get('is_dir') and e['record'] not in seen:
                            seen.add(e['record'])
                            st.append(e['record'])
            return refs

        with ndf.RawVolumeRW(self.img.path) as vol:
            for lf in [l for l in vol.find_lost_files(lost(vol)) if l['parent_ok']]:
                try:
                    vol.reconnect_lost(lf)
                except ndf.NtfsError as exc:      # cascade -> library-only, atomic
                    self.assertEqual(exc.errno, __import__('errno').ENOTSUP)
        expect = sorted(f'f{i:04d}.dat' for i in range(900))
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir('/big')
                           if e['status'] != 'dir-self')
            bad = [e for e in v.scan_dir('/big') if e['status'] not in ('ok', 'dir-self')]
        self.assertLessEqual(set(names), set(expect), 'no stray/duplicate names')
        self.assertEqual(len(names), len(set(names)), 'duplicate key!')
        self.assertEqual(bad, [], 'no dangling entries after native splits')

    def test_native_split_cascade_is_atomic(self) -> None:
        '''Sequential inserts drive multi-level cascade splits (and bitmap
           growth). Each insert is atomic — the tree stays exactly the applied
           set even where a later insert refuses (deep $ATTRIBUTE_LIST spill).'''
        self.img.populate({f'big/f{i:04d}.dat': b'x' for i in range(400)})
        with ndf.RawVolume(self.img.path) as v:
            e = next(x for x in v.scan_dir('/big') if x['name'] == 'f0000.dat')
            mref = e['mref']
            fn = None
            for fr, a, _l in v._record_attrs(e['record']):
                if struct.unpack_from('<I', fr, a)[0] == ndf.AT_FILE_NAME and fr[a + 8] == 0:
                    vo = struct.unpack_from('<H', fr, a + 20)[0]
                    vl = struct.unpack_from('<I', fr, a + 16)[0]
                    fn = bytes(fr[a + vo:a + vo + vl])
                    break
        done = 0
        with ndf.RawVolumeRW(self.img.path) as v:
            dno = v._resolve('/big')
            for i in range(1500):
                nm = f'z{i:04d}.new'.encode('utf-16-le')
                nf = bytearray(fn[:66])
                nf[64] = len(nm) // 2
                nf += nm
                try:
                    v.insert_index_entry(dno, mref, bytes(nf))
                    done += 1
                except ndf.NtfsError:
                    pass  # cascade / grow limit -> library-only, atomic
        expect = sorted([f'f{i:04d}.dat' for i in range(400)]
                        + [f'z{i:04d}.new' for i in range(done)])
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir('/big')
                           if e['status'] != 'dir-self')
        self.assertEqual(names, expect, 'every insert was atomic (applied or not)')

    # -- phase 4c: bulk-load rebuild (native torn-index recovery) --

    def test_native_rebuild_two_level(self) -> None:
        files = {f'bigdir/file_{i:03d}.dat': f'c{i}\n'.encode() for i in range(60)}
        self.img.populate(files, dirs=('bigdir/subdir',))
        expect = sorted(self.img.list_dir('bigdir'))
        with ndf.RawVolume(self.img.path) as v:
            dno = v._resolve('/bigdir')
        tear_index_block(self.img.path, 'file_')
        with ndf.RawVolume(self.img.path) as v:
            self.assertFalse(v.probe_dir_no(dno)['readable'], 'index should be torn')
        with ndf.RawVolumeRW(self.img.path) as v:
            res = v.rebuild_index(dno)
        self.assertEqual(res['entries'], 61)
        self.assertGreaterEqual(res['blocks'], 2)
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir_no(dno)
                           if e['status'] != 'dir-self')
            bad = [e for e in v.scan_dir_no(dno) if e['status'] not in ('ok', 'dir-self')]
        self.assertEqual(names, expect)
        self.assertEqual(len(names), len(set(names)), 'duplicate key!')
        self.assertEqual(bad, [])

    def test_native_rebuild_multilevel(self) -> None:
        '''A torn dir large enough to need 3+ index levels rebuilds natively.'''
        files = {f'bigdir/file_{i:05d}.dat': f'c{i}\n'.encode() for i in range(1500)}
        self.img.dispose()                     # setUp's 64 MB image is too small
        self.img = NtfsImage(size=192 * 1024 * 1024)
        self.img.populate(files, dirs=('bigdir/sub',))
        expect = sorted(self.img.list_dir('bigdir'))
        with ndf.RawVolume(self.img.path) as v:
            dno = v._resolve('/bigdir')
        tear_index_block(self.img.path, 'file_')
        with ndf.RawVolumeRW(self.img.path) as v:
            res = v.rebuild_index(dno)
        self.assertGreater(res['blocks'], 40, 'expected a multi-level tree')
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir_no(dno)
                           if e['status'] != 'dir-self')
            bad = [e for e in v.scan_dir_no(dno) if e['status'] not in ('ok', 'dir-self')]
        self.assertEqual(names, expect)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(bad, [])

    def test_native_rebuild_small_root(self) -> None:
        self.img.populate({'d/a.txt': b'a', 'd/b.txt': b'b', 'd/c.txt': b'c'})
        with ndf.RawVolume(self.img.path) as v:
            dno = v._resolve('/d')
        with ndf.RawVolumeRW(self.img.path) as v:
            res = v.rebuild_index(dno)   # small: packs the resident root
        self.assertEqual(res['blocks'], 0)
        self.assertEqual(self.img.list_dir('d'), ['a.txt', 'b.txt', 'c.txt'])

    # -- phase 4d: small→large conversion + attribute creation --

    def test_native_small_to_large_insert(self) -> None:
        '''Inserting past a small dir's root capacity converts it to a large
           index natively ($INDEX_ALLOCATION + $BITMAP created), and stays
           driver-consistent.

           Each inserted entry points at a real MFT record that genuinely
           carries a $FILE_NAME(parent=/d, name) — the same shape a true
           reconnect produces — so the result is cross-link-clean. To get
           real records without growing the
           MFT (unimplemented), a decoy /pad directory is populated to grow the
           MFT, its children are orphaned (dirents removed), and those real
           record slots are repurposed into /d. Every name is 9 characters, so
           a cloned record can be renamed in place without resizing any
           attribute.'''
        self.img.dispose()
        self.img = NtfsImage(size=192 * 1024 * 1024)
        self.img.populate({'d/aaa00.txt': b'x', 'd/aaa01.txt': b'y',
                           'd/aaa02.txt': b'z',
                           **{f'pad/p{i:04d}.bin': b'.' for i in range(400)}})
        with ndf.RawVolume(self.img.path) as v:
            dno = v._resolve('/d')
            e = next(x for x in v.scan_dir('/d') if x['name'] == 'aaa00.txt')
            template = name_abs = None
            for fr, a, _l in v._record_attrs(e['record']):   # a real /d child
                if struct.unpack_from('<I', fr, a)[0] == ndf.AT_FILE_NAME and fr[a + 8] == 0:
                    vo = struct.unpack_from('<H', fr, a + 20)[0]
                    vl = struct.unpack_from('<I', fr, a + 16)[0]
                    fn = bytes(fr[a + vo:a + vo + vl])   # value: parent=/d + name
                    template = bytes(fr)                 # the fixed-up record
                    name_abs = a + vo + 66               # name bytes in the record
                    break
            self.assertEqual(fn[64], 9, 'template name must be 9 chars')
            pad = [e['record'] for e in v.scan_dir('/pad')
                   if e['status'] == 'ok'][:300]         # real record slots
        self.assertEqual(len(pad), 300)
        with ndf.RawVolumeRW(self.img.path) as vol:
            for i in range(400):                          # orphan the decoys
                vol.remove_dirent('/pad', f'p{i:04d}.bin', really=True)

        def has_ia():
            with ndf.RawVolumeRW(self.img.path) as v:
                r = bytearray(v.read_record(dno))
                ndf._apply_fixups(r)
                return v._base_attr(r, ndf.AT_INDEX_ALLOCATION, v.I30) is not None

        self.assertFalse(has_ia(), 'dir should start small (no $INDEX_ALLOCATION)')
        done = 0
        with ndf.RawVolumeRW(self.img.path) as v:
            for i, rno in enumerate(pad):
                nm = f'n{i:04d}.txt'.encode('utf-16-le')     # 9 chars, 18 bytes
                # repurpose a real orphaned slot into a /d child carrying nm
                rec = bytearray(template)
                rec[name_abs:name_abs + 18] = nm
                seq = struct.unpack_from('<H', rec, 0x10)[0]
                v.write_record(rno, rec)
                mref = (seq << 48) | rno
                nf = bytearray(fn[:66])
                nf[64] = len(nm) // 2
                nf += nm
                v.insert_index_entry(dno, mref, bytes(nf))
                done += 1
        self.assertTrue(has_ia(), 'small→large conversion should have fired')
        expect = sorted(['aaa00.txt', 'aaa01.txt', 'aaa02.txt']
                        + [f'n{i:04d}.txt' for i in range(done)])
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir('/d')
                           if e['status'] != 'dir-self')
            bad = [e for e in v.scan_dir('/d') if e['status'] not in ('ok', 'dir-self')]
        self.assertEqual(names, expect)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(bad, [])

    def test_index_schema_i30(self) -> None:
        '''The B+ write engine is parameterized by an _IndexSchema; the $I30
           schema must reproduce the raw filename-collation/entry helpers exactly
           (so the directory path stays byte-identical), and self._ix must honour
           an override and fall back to $I30 when it is cleared.'''
        self.img.populate({'d/alpha.txt': b'x', 'd/Beta.TXT': b'y'})
        with ndf.RawVolumeRW(self.img.path) as v:
            e = next(x for x in v.scan_dir('/d') if x['name'] == 'alpha.txt')
            fn = None
            for fr, a, _l in v._record_attrs(e['record']):
                if struct.unpack_from('<I', fr, a)[0] == ndf.AT_FILE_NAME and fr[a + 8] == 0:
                    vo = struct.unpack_from('<H', fr, a + 20)[0]
                    vl = struct.unpack_from('<I', fr, a + 16)[0]
                    fn = bytes(fr[a + vo:a + vo + vl])
                    break
            s = v._ix
            assert s.name == v.I30
            assert s.collation == 0x01                       # COLLATION_FILE_NAME
            assert s.sort_key(fn) == v._upcase_seq(v._fn_key_name(fn))
            leaf = s.build_leaf(0x1234, fn)
            assert leaf == v._build_leaf_entry(0x1234, fn)
            assert ndf._IndexSchema.stored_key(leaf) == fn
            assert s.entry_sort_key(leaf) == s.sort_key(fn)
            # the active schema follows an override and reverts to $I30
            sentinel = ndf._IndexSchema(b'X\x00', 0x10, lambda k: k,
                                        lambda val, key: key)
            v._ix_override = sentinel
            assert v._ix is sentinel
            v._ix_override = None
            assert v._ix is v._i30

    def test_add_attr_roundtrip(self) -> None:
        '''_add_attr must produce an attribute the reader parses back.'''
        self.img.populate({'x/f.txt': b'ok\n'})
        with ndf.RawVolumeRW(self.img.path) as v:
            scratch = v.alloc_record()
            rec = bytearray(v._rec_size)
            rec[:4] = b'FILE'
            struct.pack_into('<HH', rec, 4, v._rec_size - 2, 1)
            struct.pack_into('<H', rec, 16, 1)          # sequence
            struct.pack_into('<H', rec, 20, 56)         # attrs offset
            struct.pack_into('<H', rec, 22, 1)          # in use
            struct.pack_into('<I', rec, 56, 0xFFFFFFFF)
            struct.pack_into('<I', rec, 0x18, 60)       # bytes_in_use
            struct.pack_into('<I', rec, 0x1C, v._rec_size)
            struct.pack_into('<H', rec, 0x28, 0)        # next_attr_id
            off = v._add_attr(rec, ndf.AT_DATA, b'', resident=True, value=b'hello')
            self.assertEqual(struct.unpack_from('<I', rec, off)[0], ndf.AT_DATA)
            vo = struct.unpack_from('<H', rec, off + 0x14)[0]
            vl = struct.unpack_from('<I', rec, off + 0x10)[0]
            self.assertEqual(bytes(rec[off + vo:off + vo + vl]), b'hello')
            v.free_record(scratch)

    def test_native_cascade_multilevel_consistent(self) -> None:
        '''Remove and reconnect many random files in a large dir (drives
           multi-level cascade splits): the result must be exact and clean.'''
        self.img.dispose()
        self.img = NtfsImage(size=192 * 1024 * 1024)
        self.img.populate({f'big/f{i:05d}.dat': b'x' for i in range(2500)})
        import random
        rng = random.Random(3)
        victims = [f'f{i:05d}.dat' for i in sorted(rng.sample(range(2500), 900))]
        with ndf.RawVolumeRW(self.img.path) as vol:
            for n in victims:
                vol.remove_dirent('/big', n, really=True)

        def lost(vol):
            refs, st, seen = set(), [ndf.FILE_ROOT], {ndf.FILE_ROOT}
            while st:
                p = vol.probe_dir_no(st.pop())
                if not p['readable']:
                    continue
                for e in p['entries']:
                    if e['status'] == 'ok':
                        refs.add(e['record'])
                        if e.get('is_dir') and e['record'] not in seen:
                            seen.add(e['record'])
                            st.append(e['record'])
            return refs

        with ndf.RawVolumeRW(self.img.path) as vol:
            for lf in [l for l in vol.find_lost_files(lost(vol)) if l['parent_ok']]:
                vol.reconnect_lost(lf)          # cascade splits; must not refuse
        expect = sorted(f'f{i:05d}.dat' for i in range(2500))
        with ndf.RawVolume(self.img.path) as v:
            names = sorted(e['name'] for e in v.scan_dir('/big')
                           if e['status'] != 'dir-self')
            bad = [e for e in v.scan_dir('/big') if e['status'] not in ('ok', 'dir-self')]
        self.assertEqual(names, expect)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(bad, [])


if __name__ == '__main__':
    unittest.main()
