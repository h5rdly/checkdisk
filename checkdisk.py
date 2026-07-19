'''A self-contained, pure-Python NTFS repair tool — the parts of chkdsk /f that
matter for a crashed volume, with no dependency beyond the standard library.

A crash can leave a directory's B+ tree ($I30 index) holding entries whose MFT
record is dead or reused (sequence-number mismatch). The ntfs3 kernel driver then
returns ESTALE/EINVAL on those names forever, and `ntfsfix` cannot repair indexes.
Windows chkdsk fixes this in stage 2 by validating each index entry against the
MFT and deleting the dangling ones. This tool does that and the other repairs
below with its own native read/write engine: it parses and rewrites the on-disk
NTFS structures directly (records, runlists, B+ tree splits/merges, $Bitmap,
$Secure, the USN journal), with multi-sector fixups and plan-then-commit
atomicity.

Commands (device = partition or image file; dir = path INSIDE the volume):
    scan    <device> <dir>                    read-only: every entry health-checked
    inspect <device> <dir> <name>             read-only triage: free/reused/orphan?
    rm      <device> <dir> <name> [--really]  drop one dangling entry
    purge   <device> <dir> <name> [--really]  true orphan: free dirent+record+clusters
    rebuild <device> <dir> [--really]         torn INDX: rebuild the whole index
                                              from the children's MFT records
    fix|/f  <device> [--really]               chkdsk /f flow — stage 1: verify MFT
                                              records + attribute runlists (repairs
                                              torn empty-attribute truncates);
                                              stage 2: walk every directory index,
                                              repair dangling entries, rebuild torn
                                              indexes; stage 5: reconcile $Bitmap
                                              cluster accounting
    backup  <device> <outdir> [dir ...]       dump boot sectors, $MFT, $MFTMirr and
                                              the given directories' raw $I30 indexes
                                              (targeted pre-repair backup)
    usn     <device> [--really] [--reset]     validate the USN change journal
                                              ($UsnJrnl: $Max sanity + full $J record
                                              walk); --really resets a corrupt
                                              journal, --reset forces the reset
    secure  <device> [--really]               chkdsk stage 3: validate $Secure —
                                              every $SDS descriptor (header, hash,
                                              256KiB mirror), the $SII/$SDH indexes
                                              against $SDS, and every file's
                                              security_id; --really repairs mirrors
                                              and rebuilds the indexes
    surface <device>                          chkdsk stage 4, report-only: read every
                                              cluster, attribute unreadable ones to
                                              their owning files (also available as
                                              `/r` or `fix --surface`)
All writing commands are dry-run unless --really is provided.
'''

from __future__ import annotations

import argparse, array, bisect, errno, hashlib, os, struct, subprocess, sys, time


# Positioned I/O. os.pread/os.pwrite are POSIX-only; on Windows fall back to
# lseek + read/write — the tool is single-threaded, so the atomicity a real
# pread would give over a separate seek is moot here. _O_BINARY keeps Windows
# from CRLF/EOF-translating a raw disk image (it is 0, a no-op, on POSIX).
_O_BINARY = getattr(os, 'O_BINARY', 0)
if hasattr(os, 'pread'):
    _pread, _pwrite = os.pread, os.pwrite
else:
    def _pread(fd, n, offset):
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, n)

    def _pwrite(fd, data, offset):
        os.lseek(fd, offset, os.SEEK_SET)
        return os.write(fd, data)


MREF_MASK = (1 << 48) - 1  # low 48 bits = record number, high 16 = sequence


# UTF-16LE attribute/stream names (plain bytes; the reader matches names
# as bytes).
INDEX_I30 = '$I30'.encode('utf-16-le')
USN_MAX_NAME = '$Max'.encode('utf-16-le')
USN_J_NAME = '$J'.encode('utf-16-le')
SDS_NAME = '$SDS'.encode('utf-16-le')
SII_NAME = '$SII'.encode('utf-16-le')
SDH_NAME = '$SDH'.encode('utf-16-le')
R_NAME = '$R'.encode('utf-16-le')
O_NAME = '$O'.encode('utf-16-le')

SDS_BLOCK = 0x40000  # $SDS entries mirror in alternating 256 KiB blocks

AT_FILE_NAME = 0x30
AT_DATA = 0x80
AT_INDEX_ROOT = 0x90
AT_INDEX_ALLOCATION = 0xA0
AT_BITMAP = 0xB0
AT_STANDARD_INFORMATION = 0x10
AT_ATTRIBUTE_LIST = 0x20
FILE_ROOT = 5
FILE_BITMAP = 6
FILE_LOGFILE = 2
FILE_SECURE = 9
FILE_UPCASE = 10

AT_UNNAMED = None

NTFS_DT_DIR = 4  # readdir dt_type for a directory (mirrors DT_DIR)


class NtfsError(OSError):
    pass


# ── raw MFT record helpers (read-only parsing for the rebuild census) ────────

def _apply_fixups(rec: bytearray) -> bool:
    '''Undo the multi-sector transfer protection; False = the record is torn '''

    usa_ofs = struct.unpack_from('<H', rec, 4)[0]
    usa_count = struct.unpack_from('<H', rec, 6)[0]
    if not usa_ofs or usa_ofs + 2 * usa_count > len(rec):
        return False
    usn = bytes(rec[usa_ofs:usa_ofs + 2])
    for i in range(1, usa_count):
        end = i * 512
        if end > len(rec) or bytes(rec[end - 2:end]) != usn:
            return False
        rec[end - 2:end] = rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2]
    return True


def _attrs(rec):
    '''Yield (offset, attr_type, attr_len) along a fixed-up record's attribute
       chain, stopping silently at the 0xFFFFFFFF terminator or any malformed
       header — the shared walk. The one caller that must REPORT a broken
       chain rather than stop (mft_survey) keeps its own loop.'''
    offset = struct.unpack_from('<H', rec, 20)[0]
    while offset + 8 <= len(rec):
        attr_type = struct.unpack_from('<I', rec, offset)[0]
        if attr_type == 0xFFFFFFFF:
            return
        length = struct.unpack_from('<I', rec, offset + 4)[0]
        if length < 24 or offset + length > len(rec):
            return
        yield offset, attr_type, length
        offset += length


def _has_attr(rec: bytes, want: int) -> bool:
    '''True if the fixed-up MFT record carries an attribute of this type '''
    return any(t == want for _off, t, _len in _attrs(rec))


def _seal_fixups(rec: bytearray) -> None:
    '''Inverse of _apply_fixups: bump the update sequence number, stash each
       sector's real last word into the USA, and stamp the USN over the
       sector ends — the multi-sector transfer protection, applied.'''
    usa_ofs = struct.unpack_from('<H', rec, 4)[0]
    usa_count = struct.unpack_from('<H', rec, 6)[0]
    usn = (struct.unpack_from('<H', rec, usa_ofs)[0] + 1) & 0xFFFF or 1
    struct.pack_into('<H', rec, usa_ofs, usn)
    for i in range(1, usa_count):
        end = i * 512
        rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2] = rec[end - 2:end]
        struct.pack_into('<H', rec, end - 2, usn)


def _file_name_attrs(rec: bytes):
    '''Yield each resident $FILE_NAME attribute value in a fixed-up MFT record '''
    for offset, attr_type, _length in _attrs(rec):
        if attr_type == AT_FILE_NAME and rec[offset + 8] == 0:  # resident only
            value_len = struct.unpack_from('<I', rec, offset + 16)[0]
            value_ofs = struct.unpack_from('<H', rec, offset + 20)[0]
            fn = rec[offset + value_ofs:offset + value_ofs + value_len]
            if len(fn) >= 66 and len(fn) >= 66 + 2 * fn[64]:
                yield fn


def _check_mapping_pairs(rec: bytes, attr_off: int, length: int,
                         nr_clusters: int) -> tuple[str | None, bool, list]:
    '''Validate and decode a non-resident attribute's mapping pairs: sane pair 
       headers, no overrun, positive run lengths,
       LCNs inside the volume, total clusters matching the highest_vcn header.
       Returns (problem, is_phantom_empty, runs) — runs is the decoded
       [(lcn, run_len, vcn), ...] for allocated (non-sparse) runs, the shared
       source for the stage-5 used-cluster map; is_phantom_empty marks the one
       safely auto-repairable case: a header that says "empty" (highest_vcn
       == -1) while well-formed pairs still describe runs (torn truncate).'''

    lowest = struct.unpack_from('<q', rec, attr_off + 16)[0]
    highest = struct.unpack_from('<q', rec, attr_off + 24)[0]
    mp_ofs = struct.unpack_from('<H', rec, attr_off + 32)[0]
    end = attr_off + length
    pos = attr_off + mp_ofs
    out: list[tuple[int, int]] = []
    if pos >= end:
        return f'mapping pairs offset {mp_ofs} outside attribute', False, out
    clusters, lcn, vcn = 0, 0, lowest
    while pos < end and rec[pos]:
        header = rec[pos]
        len_sz, ofs_sz = header & 0xF, header >> 4
        if not 1 <= len_sz <= 8 or ofs_sz > 8:
            return f'bad pair header {header:#x} at +{pos - attr_off}', False, out
        if pos + 1 + len_sz + ofs_sz > end:
            return f'pair overruns attribute at +{pos - attr_off}', False, out
        run_len = int.from_bytes(rec[pos + 1:pos + 1 + len_sz], 'little',
                                 signed=True)
        if run_len <= 0:
            return f'non-positive run length {run_len} at +{pos - attr_off}', False, out
        if ofs_sz:  # 0 = sparse run, lcn unchanged
            lcn += int.from_bytes(rec[pos + 1 + len_sz:pos + 1 + len_sz + ofs_sz],
                                  'little', signed=True)
            if lcn < 0:
                return f'negative LCN {lcn} at +{pos - attr_off}', False, out
            if lcn + run_len > nr_clusters:
                return (f'run [{lcn}, {lcn + run_len}) beyond volume '
                        f'({nr_clusters} clusters)', False, out)
            out.append((lcn, run_len, vcn))
        clusters += run_len
        vcn += run_len
        pos += 1 + len_sz + ofs_sz
    if pos >= end:
        return 'runlist not terminated inside attribute', False, out
    if highest == -1 and lowest == 0:
        if clusters:
            return (f'{len(out) or 1} phantom run(s) on an empty attribute '
                    '(torn truncate)', True, out)
    elif highest >= lowest >= 0 and clusters != highest - lowest + 1:
        return (f'runlist covers {clusters} clusters, '
                f'header says {highest - lowest + 1}'), False, out
    return None, False, out


def _min_bytes_signed(v: int) -> bytes:
    n = 1
    while not -(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1)):
        n += 1
    return v.to_bytes(n, 'little', signed=True)


def _encode_mapping_pairs(runs) -> bytes:
    '''Encode VCN-contiguous [(lcn, length), ...] into NTFS mapping pairs —
       the inverse of _check_mapping_pairs' decode. lcn < 0 marks a sparse run
       (the offset field is omitted). Terminated by a 0 header byte.'''
    out = bytearray()
    prev = 0
    for lcn, length in runs:
        if length <= 0:
            raise NtfsError(0, f'non-positive run length {length}')
        # both fields are signed varints: a length of 128 must be encoded as
        # 80 00 (two bytes) — the driver sign-extends the top byte and treats
        # a lone 80 as -128, refusing the whole runlist
        len_bytes = _min_bytes_signed(length)
        if lcn < 0:  # sparse
            out.append(len(len_bytes))
            out += len_bytes
        else:
            off_bytes = _min_bytes_signed(lcn - prev)
            out.append((len(off_bytes) << 4) | len(len_bytes))
            out += len_bytes + off_bytes
            prev = lcn
    out.append(0)
    return bytes(out)


def _walk_usn_records(read, start: int, end: int) -> tuple[int, list[str]]:
    '''Validate the USN $J stream in [start, end): every record's length is
       sane and 8-aligned, its Usn field equals its own byte offset, names stay
       inside the record, and zero fill appears only as tail padding up to the
       next 4 KiB page boundary. `read(pos, count) -> bytes`. Returns
       (records_walked, problems); stops at the first structural problem — a
       corrupt journal gets reset wholesale, so one finding is enough.'''

    problems: list[str] = []
    count, pos = 0, start
    if pos & 7:
        return 0, [f'journal start {pos} not 8-byte aligned']
    while pos < end and not problems:
        chunk = read(pos, min(1 << 20, end - pos))
        if not chunk:
            problems.append(f'$J read failed at usn {pos}')
            break
        off, n = 0, len(chunk)
        while off + 4 <= n and not problems:
            reclen = struct.unpack_from('<I', chunk, off)[0]
            if reclen == 0:
                # zero fill is only valid up to the next 4 KiB page boundary
                nxt = min((pos + off + 4096) & ~4095, end) - pos
                if chunk[off:min(nxt, n)].strip(b'\0'):
                    problems.append(f'garbage inside zero padding at usn {pos + off}')
                off = min(nxt, n)
                continue
            if reclen & 7 or not 60 <= reclen <= 8192:
                problems.append(f'bad record length {reclen} at usn {pos + off}')
                break
            if off + reclen > n:
                break  # record crosses the chunk edge — refill from here
            major = struct.unpack_from('<H', chunk, off + 4)[0]
            if major not in (2, 3, 4):
                problems.append(f'unknown USN record version {major} at usn {pos + off}')
                break
            usn_field = {2: 24, 3: 40}.get(major)  # v4 carries no Usn to cross-check
            if usn_field is not None:
                claimed = struct.unpack_from('<q', chunk, off + usn_field)[0]
                if claimed != pos + off:
                    problems.append(f'record at offset {pos + off} claims usn {claimed}')
                    break
            if major == 2:
                nlen, nofs = struct.unpack_from('<HH', chunk, off + 56)
                if nofs + nlen > reclen:
                    problems.append(f'file name overruns record at usn {pos + off}')
                    break
            count += 1
            off += reclen
        if problems:
            break
        if off == 0:
            problems.append(f'truncated record at usn {pos} (overruns journal end)')
            break
        pos += off
    return count, problems


def _security_hash(descriptor: bytes) -> int:
    '''The $Secure descriptor hash: over each little-endian u32 word,
       hash = word + rol32(hash, 3). Trailing 1-3 bytes are ignored.'''
    h = 0
    for (word,) in struct.iter_unpack('<I', descriptor[:len(descriptor) & ~3]):
        h = (word + ((h << 3) | (h >> 29))) & 0xFFFFFFFF
    return h


def _parse_sds(sds: bytes) -> tuple[dict, list[str], list[tuple]]:
    '''Walk $SDS: entries live in even 256 KiB blocks, each mirrored into the
       following odd block. Returns ({security_id: (hash, offset, length)},
       problems, mirror_fixes) where each mirror fix is (offset, length, source)
       with source 'primary' or 'mirror' — the side whose hash verifies.'''

    entries: dict[int, tuple] = {}
    problems: list[str] = []
    fixes: list[tuple] = []
    pos, end = 0, len(sds)
    while pos + 20 <= end:
        block = pos // SDS_BLOCK
        if block & 1:  # mirror region — validated alongside its primary
            pos = (block + 1) * SDS_BLOCK
            continue
        hash_, sid, off, length = struct.unpack_from('<IIQI', sds, pos)
        if length == 0:  # end of entries in this block
            pos = (block + 2) * SDS_BLOCK
            continue
        if length < 20 or pos + length > min(end, (block + 1) * SDS_BLOCK):
            problems.append(f'bad $SDS entry length {length} at offset {pos}')
            break
        if off != pos:
            problems.append(f'$SDS entry at {pos} claims offset {off}')
            break
        primary_ok = _security_hash(sds[pos + 20:pos + length]) == hash_
        mirror_pos = pos + SDS_BLOCK
        mirror_ok = None
        if mirror_pos + length <= end:
            mirror = sds[mirror_pos:mirror_pos + length]
            # a faithful mirror matches byte-for-byte; tolerate an offset field
            # that points at itself instead of the primary
            same = (mirror[:8] == sds[pos:pos + 8]
                    and mirror[16:] == sds[pos + 16:pos + length]
                    and struct.unpack_from('<Q', mirror, 8)[0] in (pos, mirror_pos))
            if same:
                mirror_ok = True
            else:
                mhash = struct.unpack_from('<I', mirror, 0)[0]
                mirror_ok = (_security_hash(mirror[20:]) == mhash
                             and struct.unpack_from('<I', mirror, 4)[0] == sid)
                if primary_ok:
                    fixes.append((pos, length, 'primary'))
                elif mirror_ok:
                    fixes.append((pos, length, 'mirror'))
                else:
                    problems.append(f'$SDS entry id {sid} at {pos}: both copies corrupt')
        if not primary_ok and mirror_ok is not True:
            if mirror_ok is None:
                problems.append(f'$SDS entry id {sid} at {pos}: hash mismatch, no mirror')
        if sid in entries:
            problems.append(f'duplicate security id {sid} in $SDS')
        entries[sid] = (hash_, pos, length)
        pos = (pos + length + 15) & ~15
    return entries, problems, fixes


def _walk_index_node(buf: bytes, hdr_off: int, entries: list, problems: list,
                     label: str, dir_index: bool = False, key_fn=None) -> None:
    '''Collect (key, data) from one index node whose INDEX_HEADER sits at
       hdr_off — works for $INDEX_ROOT values and fixed-up INDX blocks alike.'''
    if hdr_off + 16 > len(buf):
        problems.append(f'{label}: truncated index header')
        return
    prev = None
    entries_ofs, index_len = struct.unpack_from('<II', buf, hdr_off)
    pos = hdr_off + entries_ofs
    limit = min(hdr_off + index_len, len(buf))
    while pos + 16 <= limit:
        data_ofs, data_len = struct.unpack_from('<HH', buf, pos)
        length, key_len, flags = struct.unpack_from('<HHH', buf, pos + 8)
        if length < 16 or pos + length > limit:
            problems.append(f'{label}: bad index entry length {length} at +{pos}')
            return
        if not flags & 2:  # not the END entry
            if key_fn is not None and 16 + key_len <= length:
                cur = key_fn(buf[pos + 16:pos + 16 + key_len])
                if prev is not None and cur < prev:
                    problems.append(f'{label}: keys out of order at +{pos}')
                prev = cur
            if dir_index:
                if 16 + key_len > length:
                    problems.append(f'{label}: entry bounds corrupt at +{pos}')
                    return
                entries.append((buf[pos + 16:pos + 16 + key_len],
                                struct.unpack_from('<Q', buf, pos)[0]))
            else:
                if 16 + key_len > length or data_ofs + data_len > length:
                    problems.append(f'{label}: entry bounds corrupt at +{pos}')
                    return
                entries.append((buf[pos + 16:pos + 16 + key_len],
                                buf[pos + data_ofs:pos + data_ofs + data_len]))
        if flags & 2:
            return
        pos += length
    problems.append(f'{label}: node not terminated by an END entry')


def _view_index_entries(root: bytes, alloc: bytes | None, bitmap: bytes | None,
                        label: str, dir_index: bool = False,
                        key_fn=None) -> tuple[list, list]:
    '''All (key, data) pairs of a view index: the $INDEX_ROOT node plus every
       in-use, fixup-verified INDX block of $INDEX_ALLOCATION.'''
    entries: list[tuple[bytes, bytes]] = []
    problems: list[str] = []
    if len(root) < 32:
        return [], [f'{label}: $INDEX_ROOT too small ({len(root)} bytes)']
    _walk_index_node(root, 16, entries, problems, f'{label} root', dir_index, key_fn)
    if alloc:
        block_size = struct.unpack_from('<I', root, 8)[0]
        if block_size not in (512, 1024, 2048, 4096, 8192):
            return entries, [f'{label}: implausible index block size {block_size}']
        for i in range(len(alloc) // block_size):
            if bitmap is not None and not (i >> 3) < len(bitmap):
                break
            if bitmap is not None and not bitmap[i >> 3] & (1 << (i & 7)):
                continue  # free block — stale content is fine
            blk = bytearray(alloc[i * block_size:(i + 1) * block_size])
            if blk[:4] != b'INDX':
                problems.append(f'{label} block {i}: bad magic')
                continue
            if not _apply_fixups(blk):
                problems.append(f'{label} block {i}: torn (fixup mismatch)')
                continue
            _walk_index_node(bytes(blk), 24, entries, problems,
                             f'{label} block {i}', dir_index, key_fn)
    return entries, problems


def _surface_scan(pread, end: int, cluster_size: int, progress=None) -> list[int]:
    '''Read [0, end) sequentially in large chunks; when a chunk read fails,
       bisect it down to single clusters. pread(pos, count) -> bytes and raises
       OSError on unreadable media. Returns sorted unreadable cluster numbers.'''

    bad: list[int] = []

    def probe(pos: int, length: int) -> None:
        if length <= cluster_size:
            try:
                pread(pos, length)
            except OSError:
                bad.append(pos // cluster_size)
            return
        half = (length // 2) // cluster_size * cluster_size or cluster_size
        for p, n in ((pos, half), (pos + half, length - half)):
            if n <= 0:
                continue
            try:
                pread(p, n)
            except OSError:
                probe(p, n)

    pos, chunk = 0, 64 << 20
    while pos < end:
        want = min(chunk, end - pos)
        try:
            got = len(pread(pos, want))
        except OSError:
            probe(pos, want)
            pos += want
            got = None
        if got is not None:
            if got == 0:  # outside the try: NtfsError subclasses OSError
                raise NtfsError(0, f'device ends prematurely at byte {pos}')
            pos += got
        if progress:
            progress(pos, end)
    return sorted(set(bad))


def _set_run(bitmap: bytearray, lcn: int, length: int) -> None:
    '''Mark clusters [lcn, lcn+length) used in an LSB-first bitmap.'''
    end = lcn + length
    first_full = (lcn + 7) // 8
    last_full = end // 8
    for c in range(lcn, min(first_full * 8, end)):
        bitmap[c >> 3] |= 1 << (c & 7)
    if last_full > first_full:
        bitmap[first_full:last_full] = b'\xff' * (last_full - first_full)
    for c in range(max(last_full * 8, lcn), end):
        bitmap[c >> 3] |= 1 << (c & 7)


# ── volume handling ──────────────────────────────────────────────────────────

def _mount_table(mounts: str) -> list[tuple[str, str]]:
    '''(source, mountpoint) pairs — /proc/mounts where it exists, the mount(8)
       "SRC on MNT (opts)" output on macOS/FreeBSD.'''
    if os.path.exists(mounts):
        with open(mounts) as fh:
            return [tuple(line.split()[:2]) for line in fh]
    out = subprocess.run(['mount'], capture_output=True, text=True).stdout
    pairs = []
    for line in out.splitlines():
        if ' on ' in line:
            src, _, rest = line.partition(' on ')
            mnt = rest.rsplit(' (', 1)[0].split(' type ')[0]
            pairs.append((src.strip(), mnt.strip()))
    return pairs


def assert_not_mounted(device: str, mounts: str = '/proc/mounts',
                       sys_block: str = '/sys/class/block') -> None:
    real = os.path.realpath(device)
    for src, mnt in _mount_table(mounts):
        if not src.startswith('/'):
            continue
        src_real = os.path.realpath(src)
        if src_real == real:
            raise SystemExit(f'{device} is mounted ({mnt}) — unmount it first')
        # An image file attached to a loop device mounts as /dev/loopN (or
        # a partition /dev/loopNpM); the origin is only visible in the
        # loop's sysfs backing_file. The ../ variant reaches the parent
        # loop device from a partition's sysfs node.
        name = os.path.basename(src_real)
        for backing in (f'{sys_block}/{name}/loop/backing_file',
                        f'{sys_block}/{name}/../loop/backing_file'):
            try:
                with open(backing) as bf:
                    backing_real = os.path.realpath(bf.read().strip())
            except OSError:
                continue
            if backing_real == real:
                raise SystemExit(f'{device} is mounted via {src_real} on {mnt} '
                                 '— detach/unmount it first')


class RawVolume:
    '''Read-only NTFS access: boot-sector bootstrap, $MFT runlist (including
       $ATTRIBUTE_LIST-spanning $DATA), raw attribute and $I30 index walking,
       path resolution, and all the analysis passes (MFT survey, cluster audit,
       $Secure and USN validation). Pure Python — no external library. Every
       write refuses here; the RawVolumeRW subclass adds the repair engine.'''


    def _invalidate_mft_cache(self) -> None:
        '''Any repair may rewrite MFT records — drop the raw-read cache.'''
        getattr(self, '_mft_chunk_cache', {}).clear()


    def _load_record(self, rec_no: int) -> bytearray | None:
        '''read_record + FILE magic + fixups — the standard triple. None when
           the record is unreadable, not a FILE record, or torn.'''
        raw = self.read_record(rec_no)
        if raw is None or raw[:4] != b'FILE':
            return None
        rec = bytearray(raw)
        return rec if _apply_fixups(rec) else None


    def _mref_live(self, mref: int) -> bool:
        '''True iff the referenced record is readable, in use, and still carries
           the reference's sequence number (i.e. the reference is not stale).'''
        rec = self._load_record(mref & MREF_MASK)
        return (rec is not None
                and bool(struct.unpack_from('<H', rec, 22)[0] & 1)
                and struct.unpack_from('<H', rec, 16)[0] == mref >> 48)


    def nr_clusters(self) -> int:
        if getattr(self, '_nr_clusters', None) is None:
            with open(self.device, 'rb') as fh:
                boot = fh.read(72)
            bps = struct.unpack_from('<H', boot, 11)[0]
            spc = boot[13]
            spc = 2 ** (256 - spc) if spc > 0x80 else spc
            sectors = struct.unpack_from('<Q', boot, 40)[0]
            self._cluster_size = bps * spc
            self._nr_clusters = sectors // spc
        return self._nr_clusters


    def cluster_size(self) -> int:
        self.nr_clusters()
        return self._cluster_size


    # -- chkdsk stage-5: rebuild the true cluster map, diff against $Bitmap --

    def cluster_audit(self, survey: dict | None = None) -> dict:
        '''Rebuild the true used-cluster map and diff it against $Bitmap.
           missing > 0 means live data sits on clusters marked free (danger);
           extra > 0 is leaked space. `failures` non-empty means the map is
           incomplete and MUST NOT be written back.

           The map comes from the raw runlist decode of a single $MFT
           pass (mft_survey, reusable across stages).'''

        nc = self.nr_clusters()
        s = survey if survey and survey.get('used') is not None \
            else self.mft_survey(want_used=True)
        return self._bitmap_diff(nc, s['used'], list(s['map_failures']))


    def _bitmap_diff(self, nc: int, used: bytearray, failures: list[str]) -> dict:
        ondisk = self._read_whole_attr(FILE_BITMAP, AT_DATA)
        n = len(used)
        if len(ondisk) < n:
            failures.append(f'$Bitmap shorter than expected ({len(ondisk)} < {n})')
            ondisk = ondisk.ljust(n, b'\0')
        mask = (1 << nc) - 1  # ignore padding bits past the last real cluster
        u = int.from_bytes(bytes(used), 'little') & mask
        d = int.from_bytes(ondisk[:n], 'little') & mask
        extra, missing = d & ~u, u & ~d
        return {'nr_clusters': nc, 'used_count': u.bit_count(),
                'bitmap_count': d.bit_count(),
                'extra': extra.bit_count(), 'missing': missing.bit_count(),
                'used_bytes': bytes(used), 'ondisk_tail': ondisk[n - 1] if n else 0,
                'failures': failures}


    # -- chkdsk stage 3: $Secure ($SDS stream + $SII/$SDH indexes) --

    def secure_check(self, survey: dict | None = None) -> dict:
        '''Validate the security descriptor store: every $SDS entry's header,
           hash and 256 KiB mirror; the $SII (id) and $SDH (hash) indexes agree
           with $SDS entry-for-entry; and every in-use file's security_id
           references an existing descriptor.'''

        info = {'present': False, 'problems': [], 'notes': [], 'mirror_fixes': [],
                'index_problems': [], 'ref_missing': [], 'sds_entries': {},
                'descriptors': 0, 'files_checked': 0}
        try:
            sds = self._read_whole_attr(FILE_SECURE, AT_DATA, SDS_NAME, 4)
        except NtfsError:
            info['notes'].append('no $Secure/$SDS — pre-NTFS-3.0 style volume')
            return info
        info['present'] = True

        entries, sds_problems, fixes = _parse_sds(sds)
        info['sds_entries'] = entries
        info['descriptors'] = len(entries)
        info['problems'].extend(sds_problems)
        info['mirror_fixes'] = fixes

        for label, name, key_fmt in (('$SII', SII_NAME, '<I'), ('$SDH', SDH_NAME, '<II')):
            try:
                root = self._read_whole_attr(FILE_SECURE, AT_INDEX_ROOT, name, 4)
            except NtfsError:
                info['index_problems'].append(f'{label}: $INDEX_ROOT missing')
                continue
            alloc = bmp = None
            try:
                alloc = self._read_whole_attr(FILE_SECURE, AT_INDEX_ALLOCATION, name, 4)
                bmp = self._read_whole_attr(FILE_SECURE, AT_BITMAP, name, 4)
            except NtfsError:
                pass  # small index — resident root only
            key_fn = (lambda k, f=key_fmt: struct.unpack_from(f, k)
                      if len(k) >= struct.calcsize(f) else ())
            idx, idx_problems = _view_index_entries(root, alloc, bmp, label,
                                                    key_fn=key_fn)
            info['index_problems'].extend(idx_problems)
            seen = set()
            for key, data in idx:
                if len(data) < 20:
                    info['index_problems'].append(f'{label}: entry data too short')
                    continue
                h, sid, off, length = struct.unpack_from('<IIQI', data, 0)
                if label == '$SII':
                    kid = struct.unpack_from('<I', key, 0)[0] if len(key) >= 4 else -1
                    ok = kid == sid
                else:
                    kh, kid = (struct.unpack_from('<II', key, 0)
                               if len(key) >= 8 else (-1, -1))
                    ok = kid == sid and kh == h
                if not ok:
                    info['index_problems'].append(f'{label}: key does not match its '
                                                  f'entry data (id {sid})')
                    continue
                seen.add(sid)
                if entries.get(sid) != (h, off, length):
                    info['index_problems'].append(f'{label}: entry for id {sid} '
                                                  'disagrees with $SDS')
            for sid in entries.keys() - seen:
                info['index_problems'].append(f'{label}: id {sid} missing from index')

        # every in-use file's security_id must exist in $SDS (id 0 = none) —
        # the referenced-id map comes from the shared $MFT survey
        s = survey if survey and survey.get('sec_refs') is not None \
            else self.mft_survey(want_security=True)
        info['files_checked'] = sum(len(r) for r in s['sec_refs'].values())
        for sid, records in sorted(s['sec_refs'].items()):
            if sid not in entries:
                info['ref_missing'].append(
                    f'security id {sid} referenced by {len(records)} file(s) '
                    f'(e.g. record {records[0]}) but absent from $SDS')
        return info


    # -- $Extend view indexes: $Reparse ($R) and $ObjId ($O) vs the records --

    def view_index_check(self, survey: dict | None = None) -> dict:
        '''Walk the $Reparse and $ObjId view indexes (key-ordered) and check
           both directions: every entry points at a live record carrying the
           matching attribute, and every record carrying it has an entry.'''
        out = {'problems': [], 'notes': [], 'checked': 0}
        s = survey or self.mft_survey()
        for path, name_const, attr_want, kind, recs in (
                ('/$Extend/$Reparse', R_NAME, 0xC0, '$Reparse', s['reparse_recs']),
                ('/$Extend/$ObjId', O_NAME, 0x40, '$ObjId', s['objid_recs'])):
            try:
                no = self.resolve(path)
                root = self._read_whole_attr(no, AT_INDEX_ROOT, name_const, 2)
            except NtfsError:
                out['notes'].append(f'{kind}: absent')
                if recs:
                    out['problems'].append(f'{kind}: index absent but {len(recs)} '
                                           'record(s) carry the attribute')
                continue
            alloc = bmp = None
            try:
                alloc = self._read_whole_attr(no, AT_INDEX_ALLOCATION, name_const, 2)
                bmp = self._read_whole_attr(no, AT_BITMAP, name_const, 2)
            except NtfsError:
                pass
            key_fn = (lambda k: struct.unpack_from(f'<{len(k) // 4}I', k)
                      if len(k) >= 4 else ())
            entries, probs = _view_index_entries(root, alloc, bmp, kind, key_fn=key_fn)
            out['problems'] += probs
            seen: set[int] = set()
            for key, data in entries:
                out['checked'] += 1
                if kind == '$Reparse' and len(key) >= 12:
                    mref = struct.unpack_from('<Q', key, 4)[0]
                elif kind == '$ObjId' and len(data) >= 8:
                    mref = struct.unpack_from('<Q', data, 0)[0]
                else:
                    out['problems'].append(f'{kind}: malformed entry')
                    continue
                m_no = mref & MREF_MASK
                r = self._load_record(m_no)
                ok = (r is not None
                      and struct.unpack_from('<H', r, 22)[0] & 1
                      and struct.unpack_from('<H', r, 16)[0] == mref >> 48
                      and _has_attr(r, attr_want))
                if ok:
                    seen.add(m_no)
                else:
                    out['problems'].append(f'{kind}: entry points at record {m_no} '
                                           'which is dead, reused or lacks the attribute')
            for m_no in sorted(recs - seen)[:8]:
                out['problems'].append(f'{kind}: record {m_no} carries the attribute '
                                       'but has no index entry')
        return out


    # -- lost files: in-use records no index entry references (chkdsk's
    #    "recovering orphaned file") --

    def find_lost_files(self, referenced: set[int]) -> list[dict]:
        '''Every in-use base record (past the system range) carrying $FILE_NAME
           attributes but absent from `referenced` — the set of records that
           some valid index entry points at. parent_ok means the claimed parent
           is a live directory with a matching sequence, i.e. reconnectable.'''
        lost: list[dict] = []
        rec_size = self.mft_record_size()
        chunk_size, offset = 1 << 20, 0
        while True:
            chunk = self._mft_bulk(offset, chunk_size)
            usable = len(chunk) - (len(chunk) % rec_size)
            if not usable:
                break
            chunk = chunk[:usable]
            for rec_off in range(0, usable, rec_size):
                rec_no = (offset + rec_off) // rec_size
                if rec_no < 24 or rec_no in referenced:
                    continue  # system range is never index-reconnected
                raw = chunk[rec_off:rec_off + rec_size]
                if raw[:4] != b'FILE':
                    continue
                rec = bytearray(raw)
                if not _apply_fixups(rec):
                    continue
                flags = struct.unpack_from('<H', rec, 22)[0]
                base = struct.unpack_from('<Q', rec, 32)[0]
                if not flags & 1 or base & MREF_MASK:
                    continue
                frozen = bytes(rec)
                names = list(_file_name_attrs(frozen))
                if not names:
                    continue
                seq = struct.unpack_from('<H', frozen, 16)[0]
                parent = struct.unpack_from('<Q', names[0], 0)[0]
                p_no, p_seq = parent & MREF_MASK, parent >> 48
                # reconnectable = the claimed parent is a live DIRECTORY whose
                # sequence still matches (stricter than _mref_live)
                p_rec = self._load_record(p_no)
                parent_ok = False
                if p_rec is not None:
                    p_flags = struct.unpack_from('<H', p_rec, 22)[0]
                    parent_ok = bool(p_flags & 1 and p_flags & 2
                                     and struct.unpack_from('<H', p_rec, 16)[0] == p_seq)
                lost.append({
                    'record': rec_no, 'seq': seq, 'parent': p_no,
                    'parent_ok': parent_ok, 'fn_list': [bytes(fn) for fn in names],
                    'name': names[0][66:66 + 2 * names[0][64]].decode(
                        'utf-16-le', 'replace')})
            offset += usable
        return lost


    # -- chkdsk stage 4 support: attribute bad clusters to their owners --

    def surface_owners(self, bad: set[int]) -> list[dict]:
        '''Attribute unreadable clusters to their owning records by decoding
           every in-use record's runlists raw (one bulk $MFT pass); whatever
           no record claims is reported as free space.'''
        order = sorted(bad)
        owners: list[dict] = []
        claimed: set[int] = set()
        nc = self.nr_clusters()
        rec_size = self.mft_record_size()
        chunk_size, offset = 1 << 20, 0
        while True:
            chunk = self._mft_bulk(offset, chunk_size)
            usable = len(chunk) - (len(chunk) % rec_size)
            if not usable:
                break
            chunk = chunk[:usable]
            for rec_off in range(0, usable, rec_size):
                raw = chunk[rec_off:rec_off + rec_size]
                if raw[:4] != b'FILE':
                    continue
                rec = bytearray(raw)
                if not _apply_fixups(rec):
                    continue
                if not struct.unpack_from('<H', rec, 22)[0] & 1:
                    continue
                frozen = bytes(rec)
                rec_no = (offset + rec_off) // rec_size
                a_off = struct.unpack_from('<H', frozen, 20)[0]
                while a_off + 24 <= len(frozen):
                    attr_type = struct.unpack_from('<I', frozen, a_off)[0]
                    if attr_type == 0xFFFFFFFF:
                        break
                    length = struct.unpack_from('<I', frozen, a_off + 4)[0]
                    if length < 24 or a_off + length > len(frozen):
                        break
                    if frozen[a_off + 8] == 1:
                        _p, _ph, runs = _check_mapping_pairs(frozen, a_off, length, nc)
                        for lcn, run_len, _vcn in runs:
                            lo = bisect.bisect_left(order, lcn)
                            hi = bisect.bisect_right(order, lcn + run_len - 1)
                            if hi > lo:
                                hits = order[lo:hi]
                                names = ', '.join(
                                    repr(fn[66:66 + 2 * fn[64]].decode('utf-16-le',
                                                                       'replace'))
                                    for fn in _file_name_attrs(frozen)) or '(no name)'
                                owners.append({'record': rec_no, 'attr': attr_type,
                                               'names': names, 'clusters': hits})
                                claimed.update(hits)
                    a_off += length
            offset += usable
        free = sorted(bad - claimed)
        if free:
            owners.append({'record': None, 'attr': None,
                           'names': '(free space)', 'clusters': free})
        return owners


    def __enter__(self):
        return self


    def __exit__(self, *_exc):
        self.close()


    # -- NTFS name equality: this volume's $UpCase table, not Python casing --

    def _upcase_table(self) -> array.array | None:
        if self._upcase is None:
            self._upcase = False  # sticky: don't retry a failed load
            try:
                raw = self._read_whole_attr(FILE_UPCASE, AT_DATA)
            except NtfsError:
                raw = b''
            if len(raw) >= 512:
                table = array.array('H', raw[:len(raw) & ~1])
                if sys.byteorder == 'big':
                    table.byteswap()
                self._upcase = table
        return self._upcase or None


    def names_equal(self, a: str, b: str) -> bool:
        '''Case-insensitive equality the way THIS volume defines it ($UpCase);
           degrades to Python casing only if $UpCase cannot be read.'''
        table = self._upcase_table()
        if table is None:
            return a.lower() == b.lower()
        ea, eb = a.encode('utf-16-le'), b.encode('utf-16-le')
        if len(ea) != len(eb):
            return False
        n = len(table)
        return all((table[x] if x < n else x) == (table[y] if y < n else y)
                   for x, y in zip(struct.unpack(f'<{len(ea) // 2}H', ea),
                                   struct.unpack(f'<{len(eb) // 2}H', eb)))


    # -- the unified $MFT sweep: one bulk pass serves stages 1, 3 and 5 --
    def mft_survey(self, want_used: bool = False, want_security: bool = False) -> dict:
        '''One pass over $MFT computing stage-1 health (record counts, torn
           records, attribute-chain and runlist problems — entries with a
           'fix_mp_off' are safely auto-repairable torn truncates), and
           optionally the stage-5 used-cluster map from the decoded runlists
           and the stage-3 map of referenced security ids. Reading $MFT once
           instead of once per stage (and decoding runlists raw instead of
           729k per-inode round-trips) is the main /f speedup.'''
        nc = self.nr_clusters()
        rec_size = self.mft_record_size()
        total = in_use = dirs = torn = 0
        problems: list[dict] = []
        used = bytearray((nc + 7) // 8) if want_used else None
        # per-RECORD in-use bits (for the $MFT $BITMAP reconciliation) — not
        # to be confused with `used`, which is the per-CLUSTER map for stage 5
        n_slots = self._mft_size // rec_size
        rec_used = bytearray((n_slots + 7) // 8) if want_used else None
        map_failures: list[str] = []
        sec_refs: dict[int, list[int]] = {}
        reparse_recs: set[int] = set()
        objid_recs: set[int] = set()
        chunk_size, offset = 1 << 20, 0
        while True:
            chunk = self._mft_bulk(offset, chunk_size)
            usable = len(chunk) - (len(chunk) % rec_size)
            if not usable:
                break
            chunk = chunk[:usable]
            for rec_off in range(0, usable, rec_size):
                raw = chunk[rec_off:rec_off + rec_size]
                if raw[:4] != b'FILE':
                    continue
                total += 1
                rec_no = (offset + rec_off) // rec_size
                rec = bytearray(raw)
                if not _apply_fixups(rec):
                    torn += 1
                    # flags live in the first sector — readable even when torn
                    if struct.unpack_from('<H', raw, 22)[0] & 1 and want_used:
                        map_failures.append(f'record {rec_no}: torn but in use — '
                                            'its clusters are unknowable')
                        # keep its bitmap bit set: clearing a slot that still
                        # claims in-use would invite reuse under a live record
                        rec_used[rec_no >> 3] |= 1 << (rec_no & 7)
                    continue
                flags = struct.unpack_from('<H', rec, 22)[0]
                in_use += flags & 1
                dirs += bool(flags & 1) and bool(flags & 2)
                if flags & 1 and want_used:
                    rec_used[rec_no >> 3] |= 1 << (rec_no & 7)
                if not flags & 1:
                    continue
                frozen = bytes(rec)
                base = struct.unpack_from('<Q', frozen, 32)[0]
                if base & MREF_MASK and not self._mref_live(base):
                    # extension record whose base is dead or reused
                    problems.append({'record': rec_no, 'attr_type': 0,
                                     'fix_mp_off': None, 'frozen': frozen,
                                     'problem': f'orphaned extension record: base '
                                                f'{base & MREF_MASK} is dead or reused'})
                fn_count, has_attr_list = 0, False
                a_off = struct.unpack_from('<H', frozen, 20)[0]
                while a_off + 8 <= len(frozen):
                    attr_type = struct.unpack_from('<I', frozen, a_off)[0]
                    if attr_type == 0xFFFFFFFF:
                        break
                    length = struct.unpack_from('<I', frozen, a_off + 4)[0]
                    if length < 24 or a_off + length > len(frozen):
                        problems.append({'record': rec_no, 'attr_type': attr_type,
                                         'fix_mp_off': None, 'frozen': frozen,
                                         'problem': f'broken attribute chain at +{a_off}'})
                        if want_used:
                            map_failures.append(f'record {rec_no}: broken attribute chain')
                        break
                    if attr_type == AT_FILE_NAME and frozen[a_off + 8] == 0:
                        fn_count += 1
                    elif attr_type == 0xC0:
                        reparse_recs.add(rec_no)
                    elif attr_type == 0x40:
                        objid_recs.add(rec_no)
                    elif attr_type == AT_ATTRIBUTE_LIST and frozen[a_off + 8] == 0:
                        has_attr_list = True
                        v_len = struct.unpack_from('<I', frozen, a_off + 16)[0]
                        v_ofs = struct.unpack_from('<H', frozen, a_off + 20)[0]
                        listing = frozen[a_off + v_ofs:a_off + v_ofs + v_len]
                        pos = 0
                        while pos + 26 <= len(listing):
                            e_len = struct.unpack_from('<H', listing, pos + 4)[0]
                            if e_len < 26:
                                problems.append({'record': rec_no, 'attr_type': 0x20,
                                                 'fix_mp_off': None, 'frozen': frozen,
                                                 'problem': 'broken $ATTRIBUTE_LIST entry'})
                                break
                            lref = struct.unpack_from('<Q', listing, pos + 16)[0]
                            l_no = lref & MREF_MASK
                            if l_no != rec_no and not self._mref_live(lref):
                                problems.append(
                                    {'record': rec_no, 'attr_type': 0x20,
                                     'fix_mp_off': None, 'frozen': frozen,
                                     'problem': '$ATTRIBUTE_LIST points at dead/'
                                                f'reused extension record {l_no}'})
                            pos += e_len
                    elif attr_type == AT_ATTRIBUTE_LIST:
                        has_attr_list = True  # non-resident listing: skip content
                    if (want_security and attr_type == AT_STANDARD_INFORMATION
                            and frozen[a_off + 8] == 0):
                        value_len = struct.unpack_from('<I', frozen, a_off + 16)[0]
                        value_ofs = struct.unpack_from('<H', frozen, a_off + 20)[0]
                        if value_len >= 72:
                            sid = struct.unpack_from('<I', frozen,
                                                     a_off + value_ofs + 52)[0]
                            if sid:
                                sec_refs.setdefault(sid, []).append(rec_no)
                    if frozen[a_off + 8] == 1:  # non-resident
                        problem, phantom, runs = _check_mapping_pairs(
                            frozen, a_off, length, nc)
                        if problem:
                            fix = None
                            if phantom:
                                sizes = struct.unpack_from('<QQQ', frozen, a_off + 40)
                                mp_abs = a_off + struct.unpack_from(
                                    '<H', frozen, a_off + 32)[0]
                                if sizes == (0, 0, 0) and mp_abs % 512 < 510:
                                    fix = mp_abs
                            problems.append({'record': rec_no, 'attr_type': attr_type,
                                             'problem': problem, 'fix_mp_off': fix,
                                             'frozen': frozen})
                            # phantom runs are never live data (header says empty)
                            # so they don't make the used map incomplete
                            if want_used and not phantom:
                                map_failures.append(
                                    f'record {rec_no} attr {attr_type:#x}: {problem}')
                        elif want_used:
                            for lcn, run_len, _vcn in runs:
                                _set_run(used, lcn, run_len)
                    a_off += length
                # hard-link count vs the record's own $FILE_NAME attrs (spilled
                # attr lists skipped: names may live in extension records)
                if not has_attr_list and fn_count and not base & MREF_MASK:
                    link_count = struct.unpack_from('<H', frozen, 18)[0]
                    if link_count != fn_count:
                        problems.append({'record': rec_no, 'attr_type': AT_FILE_NAME,
                                         'fix_mp_off': None, 'frozen': frozen,
                                         'problem': f'hard-link count {link_count} but '
                                                    f'{fn_count} $FILE_NAME attribute(s)'})
            offset += usable
        for prob in problems:
            prob['names'] = ', '.join(
                repr(fn[66:66 + 2 * fn[64]].decode('utf-16-le', 'replace'))
                for fn in _file_name_attrs(prob.pop('frozen'))) or '(no name)'
        return {'total': total, 'in_use': in_use, 'dirs': dirs, 'torn': torn,
                'runlist_problems': problems, 'used': used,
                'rec_used': rec_used, 'n_slots': n_slots,
                'map_failures': map_failures, 'sec_refs': sec_refs,
                'reparse_recs': reparse_recs, 'objid_recs': objid_recs}


    def _entry_status(self, dir_mft_no: int, entry: dict) -> str:
        '''Validate one index entry against the raw MFT record — chkdsk stage-2
           semantics. Deliberately NOT ntfs_inode_open(mref): a cached inode hit
           skips the sequence check, so a stale entry can scan "ok" whenever the
           record's current owner was opened earlier on this volume handle.'''

        raw = self.read_record(entry['record'])
        if raw is None or raw[:4] != b'FILE':
            return 'DANGLING (record unreadable)'
        rec = bytearray(raw)
        if not _apply_fixups(rec):
            return 'DANGLING (torn record)'
        flags = struct.unpack_from('<H', rec, 22)[0]
        entry['is_dir'] = bool(flags & 2)
        if not flags & 1:
            return 'DANGLING (record not in use)'
        rec_seq = struct.unpack_from('<H', rec, 16)[0]
        if rec_seq != entry['seq']:
            return f'DANGLING (seq mismatch: dirent {entry["seq"]} vs record {rec_seq})'
        frozen = bytes(rec)
        for fn in _file_name_attrs(frozen):
            parent = struct.unpack_from('<Q', fn, 0)[0]
            fn_name = fn[66:66 + 2 * fn[64]].decode('utf-16-le', 'replace')
            if parent & MREF_MASK == dir_mft_no and self.names_equal(fn_name, entry['name']):
                return 'ok'
        # $FILE_NAME may live in an extension record when an $ATTRIBUTE_LIST
        # exists — fall back to the full attr-list enumeration for those.
        if _has_attr(frozen, AT_ATTRIBUTE_LIST):
            info = self.record_info(entry['record'])
            if any(self.names_equal(n['name'], entry['name'])
                   and n['parent_record'] == dir_mft_no
                   for n in info.get('names', [])):
                return 'ok'
        return 'DANGLING (cross-linked: record does not carry this name)'


    def _classify_found(self, dir_mft_no: int, name: str, found: dict) -> dict:
        result = {'name': name, 'dir_record': dir_mft_no,
                  'dirent_record': found['record'], 'dirent_seq': found['seq']}

        # Healthy = the record header matches the dirent's (record, seq) AND the
        # record carries this (name, parent) in a $FILE_NAME — chkdsk validates
        # both. Deliberately NOT ntfs_inode_open(mref): a prior seq-bypass open
        # (ours, below) leaves the inode cached and a cached hit skips the seq
        # check, so that test would go stale after the first classify.
        record = self.record_info(found['record'])
        result['record_info'] = record
        names_match = record.get('open') and any(
            self.names_equal(entry['name'], name)
            and entry['parent_record'] == dir_mft_no for entry in record['names'])
        if record['open'] and record.get('in_use') and record['seq'] == found['seq']:
            if names_match:
                result.update(state='healthy', action='nothing to do')
            else:
                result.update(
                    state='cross-linked',
                    action='rm ONLY — the dirent points into a live record that does '
                           'not carry this name; the real file lives elsewhere')
        elif not record['open'] or not record.get('in_use'):
            result.update(
                state='record-free',
                action='rm — the entry is the only leftover; nothing else to clean')
        elif names_match:
            result.update(
                state='orphan',
                action='purge — record still belongs to this name; one call frees '
                       'dirent, record and clusters')
        else:
            names = ', '.join(repr(entry['name']) for entry in record['names']) or '(none)'
            result.update(
                state='record-reused',
                action=f'rm ONLY — the record now belongs to a live file ({names}); '
                       'do not touch it')
        return result


    # -- chkdsk-style index rebuild: recover a directory from the MFT side --

    def probe_dir_no(self, mft_no: int) -> dict:
        try:
            entries = [e for e in self.scan_dir_no(mft_no) if e['status'] != 'dir-self']
            return {'readable': True, 'entries': entries}
        except NtfsError as exc:
            return {'readable': False, 'error': str(exc)}


    def probe_dir(self, path: str) -> dict:
        '''Try to walk the index; a torn INDX block surfaces as a readdir error '''

        try:
            return self.probe_dir_no(self._resolve(path))
        except NtfsError as exc:
            return {'readable': False, 'error': str(exc)}


    def children_from_mft(self, dir_mft_no: int) -> dict:
        '''Every in-use base MFT record whose $FILE_NAME claims dir_mft_no as
           parent — the same redundancy chkdsk rebuilds a torn index from '''

        children: list[dict] = []
        unreadable = 0
        dir_seq = None
        rec_size = self.mft_record_size()
        chunk_size, offset = 1 << 20, 0
        while True:
            chunk = self._mft_bulk(offset, chunk_size)
            # Only advance by whole records: a short read must not shift
            # every subsequent record off its alignment.
            usable = len(chunk) - (len(chunk) % rec_size)
            if not usable:
                break  # tail shorter than one record
            chunk = chunk[:usable]
            for rec_off in range(0, usable, rec_size):
                raw = chunk[rec_off:rec_off + rec_size]
                if raw[:4] != b'FILE':
                    continue
                rec_no = (offset + rec_off) // rec_size
                rec = bytearray(raw)
                if not _apply_fixups(rec):
                    unreadable += 1
                    continue
                flags = struct.unpack_from('<H', rec, 22)[0]
                base = struct.unpack_from('<Q', rec, 32)[0]
                seq = struct.unpack_from('<H', rec, 16)[0]
                if rec_no == dir_mft_no:
                    dir_seq = seq
                if not flags & 1 or base & MREF_MASK:  # free, or extension record
                    continue
                for fn in _file_name_attrs(rec):
                    parent = struct.unpack_from('<Q', fn, 0)[0]
                    if parent & MREF_MASK != dir_mft_no or rec_no == dir_mft_no:
                        continue
                    n_len, n_type = fn[64], fn[65]
                    children.append({
                        'record': rec_no, 'seq': seq, 'type': n_type,
                        'parent_seq': parent >> 48,
                        'name': fn[66:66 + 2 * n_len].decode('utf-16-le', 'replace'),
                        'fn_bytes': bytes(fn),
                    })
            offset += usable
        if dir_seq is None:
            raise NtfsError(0, f'directory record {dir_mft_no} not found in the $MFT scan')
        # A name whose parent reference carries a stale sequence belongs to a
        # previous incarnation of this directory — chkdsk would not resurrect
        # it into the rebuilt index, and neither do we.
        live = [c for c in children if c['parent_seq'] == dir_seq]
        return {'children': live, 'dir_seq': dir_seq,
                'stale_parent': len(children) - len(live),
                'unreadable_records': unreadable}


    def __init__(self, device: str, readonly: bool = True, base: int = 0):
        if not readonly:
            raise SystemExit('RawVolume is read-only — use RawVolumeRW for repairs')
        self.device = device
        self._upcase = None
        self._base = base       # byte offset of the volume within the device
        self._fd = os.open(device, os.O_RDONLY | _O_BINARY)
        boot = _pread(self._fd, 512, self._base)
        if boot[3:7] != b'NTFS':
            raise NtfsError(0, f'{device}: no NTFS boot sector')
        bps = struct.unpack_from('<H', boot, 11)[0]
        spc = boot[13]
        spc = 2 ** (256 - spc) if spc > 0x80 else spc
        self._cluster_size = bps * spc
        self._nr_clusters = struct.unpack_from('<Q', boot, 40)[0] // spc
        mft_lcn = struct.unpack_from('<Q', boot, 48)[0]
        raw = struct.unpack_from('<b', boot, 64)[0]
        self._rec_size = 2 ** -raw if raw < 0 else raw * self._cluster_size
        if self._rec_size not in (1024, 2048, 4096):
            raise NtfsError(0, f'implausible MFT record size {self._rec_size}')
        # bootstrap caches + provisional $MFT map (just its first clusters,
        # enough to read record 0 and discover the real runlist)
        import collections
        self._blk_cache = collections.OrderedDict()
        self._attr_memo = {}
        self._mft_runs = [(mft_lcn, 4, 0)]
        self._mft_size = 4 * self._cluster_size
        self._mft_starts = [0]
        rec0 = self.read_record(0)
        if rec0 is None or rec0[:4] != b'FILE':
            raise NtfsError(0, 'cannot read $MFT record 0')
        self._mft_runs = self._stream_runs(0, AT_DATA, None)[1]
        self._mft_size = sum(r[1] for r in self._mft_runs) * self._cluster_size
        self._mft_starts = [r[2] * self._cluster_size for r in self._mft_runs]
        self._blk_cache.clear()   # drop blocks read via the provisional map
        self._attr_memo.clear()
        try:
            vi = self._attr_value(3, 0x70, None)
            if vi and len(vi) >= 12 and struct.unpack_from('<H', vi, 10)[0] & 1:
                print(f'WARNING: {device} is marked dirty (unreplayed $LogFile) '
                      '— read results may be slightly stale', file=sys.stderr)
        except NtfsError:
            pass

    def close(self) -> None:
        if getattr(self, '_fd', None) is not None:
            os.close(self._fd)
            self._fd = None

    # -- dirty flag: $VOLUME_INFORMATION (0x70) of $Volume (record 3) --

    def _volume_info(self):
        rec = self._load_record(3)
        if rec is None:
            raise NtfsError(errno.EIO, '$Volume record unreadable')
        for a, t, _ln in _attrs(rec):
            if t == 0x70 and rec[a + 8] == 0:
                v_ofs = struct.unpack_from('<H', rec, a + 20)[0]
                return rec, a + v_ofs + 10  # u16 flags inside the value
        raise NtfsError(errno.ENOENT, '$VOLUME_INFORMATION not found')

    def _dirty_flag(self) -> bool:
        rec, off = self._volume_info()
        return bool(struct.unpack_from('<H', rec, off)[0] & 1)

    def volume_label(self) -> str:
        '''$VOLUME_NAME (0x60) of $Volume — UTF-16LE, may be absent (no label).'''
        rec = self._load_record(3)
        if rec is None:
            return ''
        for a, t, _ln in _attrs(rec):
            if t == 0x60 and rec[a + 8] == 0:
                vlen = struct.unpack_from('<I', rec, a + 16)[0]
                vofs = struct.unpack_from('<H', rec, a + 20)[0]
                return bytes(rec[a + vofs:a + vofs + vlen]).decode('utf-16-le',
                                                                   'replace')
        return ''

    # -- primitives --

    def _dev_read(self, offset: int, size: int) -> bytes:
        return _pread(self._fd, size, self._base + offset)

    def _runs_read(self, runs, offset: int, size: int) -> bytes:
        '''Read [offset, offset+size) of a stream laid out by vcn-ordered runs;
           holes (vcns no run covers) read as zeros. One pread per overlapping
           run, bisected start, zero-copy when one run covers the whole range.'''
        csz = self._cluster_size
        end = offset + size
        first = 0
        if len(runs) > 8:  # skip straight to the first candidate run
            starts = (self._mft_starts if runs is self._mft_runs
                      else [r[2] * csz for r in runs])
            first = max(bisect.bisect_right(starts, offset) - 1, 0)
        out = None
        for lcn, run_len, vcn in runs[first:]:
            r_start = vcn * csz
            if r_start >= end:
                break  # runs are vcn-sorted: nothing further can overlap
            r_end = r_start + run_len * csz
            lo, hi = max(offset, r_start), min(end, r_end)
            if lo >= hi:
                continue
            data = _pread(self._fd, hi - lo, self._base + lcn * csz + (lo - r_start))
            if lo == offset and hi == end:
                return data  # common case: whole range inside one run
            if out is None:
                out = bytearray(size)
            out[lo - offset:lo - offset + len(data)] = data
        return bytes(out) if out is not None else b'\x00' * size

    def mft_record_size(self) -> int:
        return self._rec_size

    BLOCK = 1 << 16  # record-read granularity: 64 KiB, LRU-cached

    def _mft_bulk(self, offset: int, size: int) -> bytes:
        if offset >= self._mft_size:
            return b''
        return self._runs_read(self._mft_runs, offset,
                               min(size, self._mft_size - offset))

    def read_record(self, rec_no: int) -> bytes | None:
        '''64 KiB block-cached record reads. Unlike a naive chunk cache
           (whose misses re-read everything), a miss here
           is one pread served by the kernel page cache — amplification is a
           memcpy, and the OrderedDict LRU evicts one block, not everything.'''
        off = rec_no * self._rec_size
        bno, boff = divmod(off, self.BLOCK)
        cache = self._blk_cache
        blk = cache.get(bno)
        if blk is None:
            want = min(self.BLOCK, self._mft_size - bno * self.BLOCK)
            if want <= 0:
                return None
            if len(cache) >= 512:  # 32 MiB cap
                cache.popitem(last=False)
            blk = cache[bno] = self._mft_bulk(bno * self.BLOCK, want)
        else:
            cache.move_to_end(bno)
        rec = blk[boff:boff + self._rec_size]
        return rec if len(rec) == self._rec_size else None

    # -- raw attribute access (follows $ATTRIBUTE_LIST) --

    def _record_attrs(self, rec_no: int) -> list:
        memo = self._attr_memo
        got = memo.get(rec_no)
        if got is None:
            if len(memo) >= 2048:
                memo.clear()
            got = memo[rec_no] = list(self._record_attrs_uncached(rec_no))
        return got

    def _record_attrs_uncached(self, rec_no: int):
        '''Yield (frozen_record, attr_off, attr_len) for every attribute of
           this inode, base record first, then extension records in $ATTRIBUTE_
           LIST order (each extension yields its own attributes).'''
        rec = self._load_record(rec_no)
        if rec is None:
            raise NtfsError(errno.EIO, f'record {rec_no} unreadable or torn')
        frozen = bytes(rec)
        attr_list = None
        for a, t, length in _attrs(frozen):
            if t == AT_ATTRIBUTE_LIST:
                attr_list = (frozen, a, length)
            yield (frozen, a, length)
        if attr_list is None:
            return
        frozen0, a, length = attr_list
        if frozen0[a + 8] == 0:  # resident list value
            v_len = struct.unpack_from('<I', frozen0, a + 16)[0]
            v_ofs = struct.unpack_from('<H', frozen0, a + 20)[0]
            listing = frozen0[a + v_ofs:a + v_ofs + v_len]
        else:
            _p, _ph, runs = _check_mapping_pairs(frozen0, a, length, self.nr_clusters())
            size = struct.unpack_from('<q', frozen0, a + 48)[0]
            listing = self._runs_read(runs, 0, size)
        pos, seen = 0, set()
        while pos + 26 <= len(listing):
            e_len = struct.unpack_from('<H', listing, pos + 4)[0]
            if e_len < 26:
                break
            mref = struct.unpack_from('<Q', listing, pos + 16)[0] & MREF_MASK
            if mref != rec_no and mref not in seen:
                seen.add(mref)
                ext = self._load_record(mref)
                if ext is not None:
                    eb = bytes(ext)
                    for ea, _et, el in _attrs(eb):
                        yield (eb, ea, el)
            pos += e_len

    def _stream_runs(self, rec_no: int, attr_type: int, name: bytes | None):
        '''(data_size, vcn-ordered runs) of a non-resident attribute, pieces
           merged across extension records. Raises ENOENT when absent.'''
        data_size, runs, found = None, [], False
        for frozen, a, length in self._record_attrs(rec_no):
            if struct.unpack_from('<I', frozen, a)[0] != attr_type:
                continue
            nlen = frozen[a + 9]
            nofs = struct.unpack_from('<H', frozen, a + 10)[0]
            aname = frozen[a + nofs:a + nofs + 2 * nlen] if nlen else None
            if (name or None) != (aname or None):
                continue
            found = True
            if frozen[a + 8] == 0:
                return None, None  # resident — caller reads the value instead
            if struct.unpack_from('<q', frozen, a + 16)[0] == 0:  # lowest_vcn
                data_size = struct.unpack_from('<q', frozen, a + 48)[0]
            _p, _ph, r = _check_mapping_pairs(frozen, a, length, self.nr_clusters())
            runs.extend(r)
        if not found:
            raise NtfsError(errno.ENOENT, f'record {rec_no}: attr {attr_type:#x} absent')
        runs.sort(key=lambda t: t[2])
        return data_size if data_size is not None else 0, runs

    def _attr_value(self, rec_no: int, attr_type: int, name: bytes | None) -> bytes:
        for frozen, a, _length in self._record_attrs(rec_no):
            if struct.unpack_from('<I', frozen, a)[0] != attr_type:
                continue
            nlen = frozen[a + 9]
            nofs = struct.unpack_from('<H', frozen, a + 10)[0]
            aname = frozen[a + nofs:a + nofs + 2 * nlen] if nlen else None
            if (name or None) != (aname or None):
                continue
            if frozen[a + 8] == 0:
                v_len = struct.unpack_from('<I', frozen, a + 16)[0]
                v_ofs = struct.unpack_from('<H', frozen, a + 20)[0]
                return frozen[a + v_ofs:a + v_ofs + v_len]
            size, runs = self._stream_runs(rec_no, attr_type, name)
            return self._runs_read(runs, 0, size)
        raise NtfsError(errno.ENOENT, f'record {rec_no}: attr {attr_type:#x} absent')

    def _read_whole_attr(self, mft_no: int, attr_type: int,
                         name=None, name_len: int = 0) -> bytes:
        return self._attr_value(mft_no, attr_type, name)

    # -- directories: raw $I30 walk + path resolution --

    I30 = '$I30'.encode('utf-16-le')

    def _dir_entries(self, mft_no: int) -> list[dict]:
        root = self._attr_value(mft_no, AT_INDEX_ROOT, self.I30)
        alloc = bmp = None
        try:
            alloc = self._attr_value(mft_no, AT_INDEX_ALLOCATION, self.I30)
            bmp = self._attr_value(mft_no, AT_BITMAP, self.I30)
        except NtfsError:
            pass
        pairs, problems = _view_index_entries(root, alloc, bmp, f'mft#{mft_no}',
                                              dir_index=True)
        if problems:
            raise NtfsError(errno.EIO, f'$I30 of record {mft_no}: {problems[0]}')
        entries = []
        for key, mref in pairs:
            if len(key) < 66:
                continue
            n_len, n_type = key[64], key[65]
            attrs = struct.unpack_from('<I', key, 56)[0]
            entries.append({'name': key[66:66 + 2 * n_len].decode('utf-16-le', 'replace'),
                            'name_type': n_type, 'mref': mref,
                            'dt_type': NTFS_DT_DIR if attrs & 0x10000000 else 8})
        return entries

    def _resolve(self, path: str) -> int:
        cur = FILE_ROOT
        for comp in path.strip('/').split('/'):
            if not comp:
                continue
            for e in self._dir_entries(cur):
                if self.names_equal(e['name'], comp):
                    cur = e['mref'] & MREF_MASK
                    break
            else:
                raise NtfsError(errno.ENOENT, f'{comp!r} not found resolving {path!r}')
        return cur

    def scan_dir_no(self, mft_no: int) -> list[dict]:
        entries = self._dir_entries(mft_no)
        for entry in entries:
            entry['record'] = entry['mref'] & MREF_MASK
            entry['seq'] = entry['mref'] >> 48
            entry['status'] = self._entry_status(mft_no, entry)
        return entries

    def scan_dir(self, path: str) -> list[dict]:
        return self.scan_dir_no(self._resolve(path))

    def resolve(self, path: str) -> int:
        return self._resolve(path)

    def record_info(self, record_no: int) -> dict:
        try:
            attrs = list(self._record_attrs(record_no & MREF_MASK))
        except NtfsError as exc:
            return {'open': False, 'errno': exc.errno or errno.EIO, 'error': str(exc)}
        frozen = attrs[0][0] if attrs else self.read_record(record_no & MREF_MASK)
        info = {'open': True,
                'seq': struct.unpack_from('<H', frozen, 16)[0],
                'link_count': struct.unpack_from('<H', frozen, 18)[0],
                'in_use': bool(struct.unpack_from('<H', frozen, 22)[0] & 1),
                'is_dir': bool(struct.unpack_from('<H', frozen, 22)[0] & 2),
                'names': []}
        for rec, a, _length in attrs:
            if struct.unpack_from('<I', rec, a)[0] != AT_FILE_NAME or rec[a + 8]:
                continue
            v_len = struct.unpack_from('<I', rec, a + 16)[0]
            v_ofs = struct.unpack_from('<H', rec, a + 20)[0]
            fn = rec[a + v_ofs:a + v_ofs + v_len]
            if len(fn) < 66:
                continue
            parent = struct.unpack_from('<Q', fn, 0)[0]
            info['names'].append({
                'name': fn[66:66 + 2 * fn[64]].decode('utf-16-le', 'replace'),
                'type': fn[65], 'parent_record': parent & MREF_MASK,
                'parent_seq': parent >> 48})
        return info

    def classify_dirent(self, path: str, name: str) -> dict:
        dir_no = self._resolve(path)
        for e in self._dir_entries(dir_no):
            if self.names_equal(e['name'], name):
                found = {'name': name, 'record': e['mref'] & MREF_MASK,
                         'seq': e['mref'] >> 48}
                return self._classify_found(dir_no, name, found)
        raise NtfsError(errno.ENOENT, f'index entry {name!r} not found in {path!r}')

    def remove_dirent(self, path: str, name: str, really: bool) -> dict:
        if really:
            raise NtfsError(0, 'RawVolume is read-only — use RawVolumeRW')
        dir_no = self._resolve(path)
        for e in self._dir_entries(dir_no):
            if self.names_equal(e['name'], name):
                return {'name': name, 'record': e['mref'] & MREF_MASK,
                        'seq': e['mref'] >> 48}
        raise NtfsError(errno.ENOENT, f'index entry {name!r} not found in {path!r}')

    def usn_check(self, path: str = '/$Extend/$UsnJrnl') -> dict:
        info = {'present': False, 'problems': [], 'notes': [], 'records': 0,
                'journal_id': None, 'lowest': None, 'next_usn': None}
        try:
            jrnl = self._resolve(path)
        except NtfsError:
            return info
        info['present'] = True
        problems = info['problems']
        lowest = 0
        try:
            blob = self._attr_value(jrnl, AT_DATA, '$Max'.encode('utf-16-le'))
        except NtfsError:
            problems.append('$Max stream missing')
            blob = None
        if blob is not None:
            if len(blob) != 32:
                problems.append(f'$Max is {len(blob)} bytes, expected 32')
            else:
                max_size, _d, jid, lowest = struct.unpack('<QQQQ', blob)
                info.update(journal_id=jid, lowest=lowest)
                if not 0 < max_size < 1 << 40:
                    problems.append(f'implausible journal MaximumSize {max_size}')
        jn = '$J'.encode('utf-16-le')
        try:
            data_size, runs = self._stream_runs(jrnl, AT_DATA, jn)
            if data_size is None:  # resident $J
                value = self._attr_value(jrnl, AT_DATA, jn)
                data_size, runs = len(value), None
        except NtfsError:
            problems.append('$J stream missing')
            return info
        info['next_usn'] = data_size
        if lowest > data_size:
            problems.append(f'LowestValidUsn {lowest} beyond journal end {data_size}')
            return info
        if lowest & 7:
            problems.append(f'LowestValidUsn {lowest} not 8-byte aligned')
            return info
        start = lowest
        if runs:
            first_alloc = runs[0][2] * self.cluster_size()
            if first_alloc > start:
                info['notes'].append(
                    f'LowestValidUsn {start} lags the first allocated byte '
                    f'{first_alloc} (purged region)')
                start = first_alloc
            read = lambda pos, count: self._runs_read(runs, pos, count)
        else:
            read = lambda pos, count: value[pos:pos + count]
        count, walk_problems = _walk_usn_records(read, start, data_size)
        info['records'] = count
        problems.extend(walk_problems)
        return info


class _IndexSchema:
    '''How one NTFS index type names itself, orders its keys, and frames its
       entries — the B+ write engine is otherwise generic over it. $I30
       (directory indexes) is the reference schema; the $Secure view indexes
       $SII/$SDH will plug in the same way.

       name        UTF-16LE attribute name ($I30, $SII, $SDH)
       collation   the COLLATION_* rule id (goes in the $INDEX_ROOT header)
       sort_key    stored-key bytes -> a Python-comparable ordering key
       build_leaf  (value, key_bytes) -> a leaf INDEX_ENTRY

       An INDEX_ENTRY stores its key as `key_length` bytes at offset 16; the
       collation key is derived from those bytes by `sort_key` (for $I30 the
       stored key is the whole $FILE_NAME and the collation key is its upcased
       name; for a view index the stored key is the collation key directly).'''

    __slots__ = ('name', 'collation', 'sort_key', 'build_leaf')

    def __init__(self, name, collation, sort_key, build_leaf):
        self.name = name
        self.collation = collation
        self.sort_key = sort_key
        self.build_leaf = build_leaf

    @staticmethod
    def stored_key(entry) -> bytes:
        return bytes(entry[16:16 + struct.unpack_from('<H', entry, 10)[0]])

    def entry_sort_key(self, entry):
        return self.sort_key(self.stored_key(entry))


class RawVolumeRW(RawVolume):
    ''' The native write engine: sealed record writes, $MFTMirr sync, dirty-flag
       lifecycle, allocators, B+ tree index edits (remove / insert with splits /
       bulk-load rebuild), $Secure and USN repairs '''

    def __init__(self, device: str, base: int = 0):
        super().__init__(device, readonly=True, base=base)
        os.close(self._fd)
        self._fd = os.open(device, os.O_RDWR | _O_BINARY)
        self._mirror = None
        self._was_dirty = self._dirty_flag()
        if not self._was_dirty:
            self._set_dirty(True)   # crash mid-op leaves the volume flagged

    def close(self) -> None:
        if getattr(self, '_fd', None) is not None and not self._was_dirty:
            self._set_dirty(False)  # clean close: clear only what we set
        super().close()

    # -- dirty flag write side ($VOLUME_INFORMATION probe lives in RawVolume) --

    def _set_dirty(self, on: bool) -> None:
        rec, off = self._volume_info()
        flags = struct.unpack_from('<H', rec, off)[0]
        struct.pack_into('<H', rec, off, flags | 1 if on else flags & ~1)
        self.write_record(3, rec)

    # -- write plumbing --

    def _runs_write(self, runs, offset: int, data: bytes) -> None:
        csz = self._cluster_size
        end, written = offset + len(data), 0
        for lcn, run_len, vcn in runs:
            r_start = vcn * csz
            if r_start >= end:
                break
            r_end = r_start + run_len * csz
            lo, hi = max(offset, r_start), min(end, r_end)
            if lo >= hi:
                continue
            chunk = data[lo - offset:hi - offset]
            if _pwrite(self._fd, chunk, self._base + lcn * csz + (lo - r_start)) != len(chunk):
                raise NtfsError(errno.EIO, f'short write at stream offset {lo}')
            written += len(chunk)
        if written != len(data):
            raise NtfsError(errno.EIO, f'write spans a hole ({written}/{len(data)})')

    def _mirror_runs(self):
        if self._mirror is None:
            self._mirror = self._stream_runs(1, AT_DATA, None)[1]  # $MFTMirr
        return self._mirror

    def write_record(self, rec_no: int, logical) -> None:
        '''Seal fixups over LOGICAL (fixed-up) record content and write it.
           Records 0-3 are mirrored into $MFTMirr, as the driver verifies.'''
        rec = bytearray(logical)
        if rec[:4] != b'FILE' or len(rec) != self._rec_size:
            raise NtfsError(errno.EINVAL, 'refusing to write a non-FILE record')
        _seal_fixups(rec)
        blob = bytes(rec)
        self._runs_write(self._mft_runs, rec_no * self._rec_size, blob)
        if rec_no < 4:
            self._runs_write(self._mirror_runs(), rec_no * self._rec_size, blob)
        self._blk_cache.clear()
        self._attr_memo.clear()

    # -- phase 2: allocators ($Bitmap clusters + $MFT record slots) --

    def _bitmap_state(self):
        if getattr(self, '_bm', None) is None:
            size, runs = self._stream_runs(FILE_BITMAP, AT_DATA, None)
            self._bm = bytearray(self._runs_read(runs, 0, size))
            self._bm_runs = runs
        return self._bm

    def _bitmap_flush(self, bits) -> None:
        lo, hi = min(bits) >> 3, (max(bits) >> 3) + 1
        self._runs_write(self._bm_runs, lo, bytes(self._bm[lo:hi]))

    def apply_bitmap(self, audit: dict) -> None:
        '''Rewrite $Bitmap with the computed truth (the chkdsk stage-5 fix).'''
        if audit['failures']:
            raise NtfsError(0, 'refusing to write $Bitmap: usage map is incomplete')
        nc = audit['nr_clusters']
        data = bytearray(audit['used_bytes'])
        if nc & 7:  # preserve the on-disk padding-bit convention in the tail
            data[-1] |= audit['ondisk_tail'] & (0xFF ^ ((1 << (nc & 7)) - 1))
        self._bitmap_state()                     # populate self._bm_runs
        self._runs_write(self._bm_runs, 0, bytes(data))
        self._bm = None                          # drop the cached map; reload lazily

    def secure_fix_mirrors(self, fixes: list) -> int:
        '''Copy the hash-verified side of each mismatched $SDS entry pair over
           the corrupt side (both copies end up canonical: offset = primary).'''
        name = '$SDS'.encode('utf-16-le')
        size, runs = self._stream_runs(FILE_SECURE, AT_DATA, name)
        done = 0
        for pos, length, source in fixes:
            src = pos if source == 'primary' else pos + SDS_BLOCK
            blob = bytearray(self._runs_read(runs, src, length))
            struct.pack_into('<Q', blob, 8, pos)     # canonical offset field
            for dst in (pos, pos + SDS_BLOCK):
                self._runs_write(runs, dst, bytes(blob))
            done += 1
        return done

    def usn_reset(self, path: str = '/$Extend/$UsnJrnl') -> int:
        '''The chkdsk/fsutil-style journal reset: truncate $J to zero (freeing
           its clusters) and stamp $Max with a fresh journal id and
           LowestValidUsn 0. Consumers detect the id change and rescan.
           Returns the new journal id.'''
        jrnl = self._resolve(path)
        jn = '$J'.encode('utf-16-le')
        found = self._find_attr(jrnl, AT_DATA, jn)
        if found is None:
            raise NtfsError(errno.ENOENT, 'open $J')
        rno, rec, a = found
        rec = bytearray(rec)
        if rec[a + 8] == 1:                              # non-resident: free + zero
            length = struct.unpack_from('<I', rec, a + 4)[0]
            _p, _ph, r = _check_mapping_pairs(rec, a, length, self.nr_clusters())
            runs = [(lcn, rlen) for lcn, rlen, _v in r]
            struct.pack_into('<q', rec, a + 0x10, 0)     # lowest_vcn
            struct.pack_into('<q', rec, a + 0x18, -1)    # highest_vcn (0 clusters)
            struct.pack_into('<Q', rec, a + 0x28, 0)     # allocated_size
            struct.pack_into('<Q', rec, a + 0x30, 0)     # data_size
            struct.pack_into('<Q', rec, a + 0x38, 0)     # initialized_size
            mp_off = struct.unpack_from('<H', rec, a + 0x20)[0]
            rec[a + mp_off] = 0                          # runlist terminator
            self.write_record(rno, rec)                 # clear ref before freeing
            if runs:
                self.free_clusters(runs)
        else:                                            # resident: empty the value
            self._replace_resident_value(rec, a, b'')
            self.write_record(rno, rec)

        mn = '$Max'.encode('utf-16-le')
        try:
            old = self._attr_value(jrnl, AT_DATA, mn)
        except NtfsError:
            old = b''
        max_size, delta = struct.unpack_from('<QQ', old) if len(old) >= 16 else (0, 0)
        if not 0 < max_size < 1 << 40 or not 0 < delta < 1 << 40:
            max_size, delta = 32 * 1024 * 1024, 8 * 1024 * 1024
        new_id = int((time.time() + 11644473600) * 10 ** 7)  # NTFS FILETIME
        blob = struct.pack('<QQQQ', max_size, delta, new_id, 0)
        mfound = self._find_attr(jrnl, AT_DATA, mn)
        if mfound is None:
            raise NtfsError(errno.ENOENT, 'open $Max')
        mrno, mrec, ma = mfound
        mrec = bytearray(mrec)
        if mrec[ma + 8] == 0:                            # resident (typical)
            self._replace_resident_value(mrec, ma, blob)
            self.write_record(mrno, mrec)
        else:                                            # non-resident: overwrite
            _size, mruns = self._stream_runs(jrnl, AT_DATA, mn)
            self._runs_write(mruns, 0, blob)
        return new_id

    def rebuild_secure_indexes(self, sds_entries: dict) -> dict:
        '''Native $SII/$SDH rebuild: wipe each index and re-add one entry per
           $SDS descriptor. `sds_entries` maps security_id -> (hash, sds_offset,
           length). Bulk-loads a resident root, a single INDX block, or a
           multi-level tree as needed (via the shared _bulk_write_index engine),
           with the two view collations — $SII by security-id (ULONG), $SDH by
           (hash, id) (SECURITY_HASH).'''
        orders = (
            (self._sii, sorted(sds_entries),
             lambda sid: struct.pack('<I', sid)),
            (self._sdh, sorted(sds_entries, key=lambda i: (sds_entries[i][0], i)),
             lambda sid: struct.pack('<II', sds_entries[sid][0], sid)))
        built = 0
        for schema, order, key_of in orders:
            entries = []
            for sid in order:
                h, off, length = sds_entries[sid]
                data = struct.pack('<IIQI', h, sid, off, length)
                entries.append(schema.build_leaf(data, key_of(sid)))
            self._write_view_index(FILE_SECURE, schema, entries)
            built += len(entries)
        return {'added': built}

    def _write_view_index(self, owner: int, schema, entries: list) -> None:
        '''Replace `schema`'s index on `owner` with `entries` (already in
           collation order) — the $SII/$SDH ($Secure) analogue of the $I30
           rebuild: resident root, single INDX block, or a bulk-loaded
           multi-level tree, all through the shared _bulk_write_index engine.'''
        self._ix_override = schema
        try:
            self._bulk_write_index(owner, entries)
        finally:
            self._ix_override = None

    def alloc_clusters(self, count: int, near_lcn: int = 0) -> list[tuple[int, int]]:
        '''First-fit from the hint (byte-skipping full bytes), wrapping once.
           Sets the bits, flushes $Bitmap, returns [(lcn, run_len)] runs. The
           stage-5 audit is the oracle: freshly allocated, unreferenced
           clusters must show up as exactly `count` extra bits.'''
        bm = self._bitmap_state()
        nc = self.nr_clusters()
        picked: list[int] = []
        c = min(max(near_lcn, 0), nc - 1)
        scanned = 0
        while len(picked) < count and scanned <= nc:
            if c >= nc:
                c = 0
            if not c & 7 and bm[c >> 3] == 0xFF and c + 8 <= nc:
                c += 8
                scanned += 8
                continue
            if not bm[c >> 3] & (1 << (c & 7)):
                picked.append(c)
            c += 1
            scanned += 1
        if len(picked) < count:
            raise NtfsError(errno.ENOSPC, 'volume full')
        for c in picked:
            bm[c >> 3] |= 1 << (c & 7)
        self._bitmap_flush(picked)
        picked.sort()
        runs, start, prev = [], picked[0], picked[0]
        for c in picked[1:]:
            if c != prev + 1:
                runs.append((start, prev - start + 1))
                start = c
            prev = c
        runs.append((start, prev - start + 1))
        return runs

    def free_clusters(self, runs) -> None:
        bm = self._bitmap_state()
        bits, seen = [], set()
        for lcn, run_len in runs:
            for c in range(lcn, lcn + run_len):
                if c in seen or not bm[c >> 3] & (1 << (c & 7)):
                    raise NtfsError(errno.EIO, f'double free of cluster {c}')
                seen.add(c)
                bits.append(c)
        for c in bits:
            bm[c >> 3] &= ~(1 << (c & 7))
        self._bitmap_flush(bits)

    def _mft_bitmap(self):
        '''(bitmap_bytes, writer) for $MFT's own $BITMAP — resident on small
           volumes (rewrite record 0, mirrored), non-resident on real ones.'''
        for frozen, a, _l in self._record_attrs(0):
            if (struct.unpack_from('<I', frozen, a)[0] != AT_BITMAP
                    or frozen[a + 9] != 0):
                continue  # unnamed only
            if frozen[a + 8] == 0:
                v_len = struct.unpack_from('<I', frozen, a + 16)[0]
                v_ofs = struct.unpack_from('<H', frozen, a + 20)[0]
                blob = frozen[a + v_ofs:a + v_ofs + v_len]

                def write_res(data: bytes, a=a, v_ofs=v_ofs, v_len=v_len):
                    rec = self._load_record(0)
                    assert rec is not None
                    rec[a + v_ofs:a + v_ofs + v_len] = data
                    self.write_record(0, rec)
                return blob, write_res
            _p, _ph, runs = _check_mapping_pairs(frozen, a,
                                                 struct.unpack_from('<I', frozen,
                                                                    a + 4)[0],
                                                 self.nr_clusters())
            size = struct.unpack_from('<q', frozen, a + 48)[0]
            blob = self._runs_read(runs, 0, size)

            def write_nonres(data: bytes, runs=runs):
                self._runs_write(runs, 0, data)
            return blob, write_nonres
        raise NtfsError(errno.ENOENT, "$MFT's $BITMAP not found")

    def alloc_record(self) -> int:
        '''Reuse a free MFT record slot (bit clear AND record not in use);
           growing the MFT is deliberately unimplemented — ENOSPC instead.'''
        bm, write = self._mft_bitmap()
        new = bytearray(bm)
        for rec_no in range(24, self._mft_size // self._rec_size):
            if new[rec_no >> 3] & (1 << (rec_no & 7)):
                continue
            rec = self._load_record(rec_no)
            if rec is not None and struct.unpack_from('<H', rec, 22)[0] & 1:
                continue  # bitmap stale: record actually live — never take it
            new[rec_no >> 3] |= 1 << (rec_no & 7)
            write(bytes(new))
            return rec_no
        raise NtfsError(errno.ENOSPC, 'no free MFT records (growth unimplemented)')

    def apply_mft_bitmap(self, used: bytes, nbits: int) -> int:
        '''Rewrite $MFT's $BITMAP so bit i matches record i's surveyed in-use
           flag, for records [0, nbits); bits past nbits keep their on-disk
           value. The crash shape this repairs: alloc_record's bitmap write
           reached the disk but the record write never did — a leaked set bit
           that chkdsk reports as "the MFT BITMAP attribute is incorrect".'''
        bm, write = self._mft_bitmap()
        new = bytearray(bm)
        changed = 0
        for i in range(min(nbits, len(new) * 8)):
            want = bool(used[i >> 3] & (1 << (i & 7)))
            if bool(new[i >> 3] & (1 << (i & 7))) != want:
                changed += 1
                if want:
                    new[i >> 3] |= 1 << (i & 7)
                else:
                    new[i >> 3] &= ~(1 << (i & 7)) & 0xFF
        if changed:
            write(bytes(new))
        return changed

    def free_record(self, rec_no: int) -> None:
        bm, write = self._mft_bitmap()
        if not bm[rec_no >> 3] & (1 << (rec_no & 7)):
            raise NtfsError(errno.EIO, f'record {rec_no} already free in bitmap')
        new = bytearray(bm)
        new[rec_no >> 3] &= ~(1 << (rec_no & 7))
        write(bytes(new))

    # -- phase 3/3b: index-entry removal (leaf splice + internal promotion) --

    def _write_index_block(self, ia_runs, block_index: int, block_size: int,
                           blk: bytearray) -> None:
        _seal_fixups(blk)
        self._runs_write(ia_runs, block_index * block_size, bytes(blk))
        self._blk_cache.clear()
        self._attr_memo.clear()

    @staticmethod
    def _find_entry(buf, hdr_off: int, matches):
        '''(pos, length, flags) of the first non-END entry for which
           matches(name) is true, else None. Does not mutate.'''
        entries_ofs, index_len = struct.unpack_from('<II', buf, hdr_off)
        pos, limit = hdr_off + entries_ofs, hdr_off + index_len
        while pos + 16 <= limit:
            length = struct.unpack_from('<H', buf, pos + 8)[0]
            flags = struct.unpack_from('<H', buf, pos + 12)[0]
            if length < 16 or pos + length > limit:
                return None
            if not flags & 2:
                n_len = buf[pos + 16 + 64]
                nm = bytes(buf[pos + 16 + 66:pos + 16 + 66 + 2 * n_len]).decode(
                    'utf-16-le', 'replace')
                if matches(nm):
                    return pos, length, flags
            if flags & 2:
                break
            pos += length
        return None


    @staticmethod
    def _splice_at(buf, hdr_off: int, pos: int, length: int) -> None:
        ''' Remove the entry at pos '''
        
        _eo, index_len = struct.unpack_from('<II', buf, hdr_off)
        limit = hdr_off + index_len
        tail = bytes(buf[pos + length:limit])
        buf[pos:pos + len(tail)] = tail
        new_len = index_len - length
        for i in range(hdr_off + new_len, limit):
            buf[i] = 0
        struct.pack_into('<I', buf, hdr_off + 4, new_len)


    def _read_indx_by_vcn(self, alloc, block_size, vcn):
        '''(block_index, fixed-up block) whose header VCN == vcn, matched by the
           block's own index_block_vcn field (VCN-unit-agnostic) '''

        for i in range(len(alloc) // block_size):
            if alloc[i * block_size:i * block_size + 4] != b'INDX':
                continue
            if struct.unpack_from('<q', alloc, i * block_size + 16)[0] != vcn:
                continue
            blk = bytearray(alloc[i * block_size:(i + 1) * block_size])
            if _apply_fixups(blk):
                return i, blk
        return None, None


    def _rightmost_leaf(self, alloc, block_size, start_vcn):
        '''Descend the rightmost (END-entry) subnode pointers from start_vcn to
           a leaf block — the subtree's maximum lives there.'''
        vcn, seen = start_vcn, set()
        while True:
            if vcn in seen:
                raise NtfsError(errno.EIO, 'cyclic index subnode chain')
            seen.add(vcn)
            i, blk = self._read_indx_by_vcn(alloc, block_size, vcn)
            if blk is None:
                raise NtfsError(errno.EIO, f'index block VCN {vcn} unreadable')
            eo, il = struct.unpack_from('<II', blk, 24)
            pos, end = 24 + eo, 24 + il
            while pos + 16 <= end:
                length = struct.unpack_from('<H', blk, pos + 8)[0]
                flags = struct.unpack_from('<H', blk, pos + 12)[0]
                if length < 16:
                    raise NtfsError(errno.EIO, 'corrupt index node')
                if flags & 2:  # END entry
                    if flags & 1:  # has a subnode — descend rightmost
                        vcn = struct.unpack_from('<q', blk, pos + length - 8)[0]
                        break
                    return i, blk  # leaf
                pos += length
            else:
                raise NtfsError(errno.EIO, 'index node without END entry')


    @staticmethod
    def _last_real_entry(buf, hdr_off):
        '''(pos, length) of the last non-END entry — the node's maximum key.'''
        eo, il = struct.unpack_from('<II', buf, hdr_off)
        pos, limit, last = hdr_off + eo, hdr_off + il, None
        while pos + 16 <= limit:
            length = struct.unpack_from('<H', buf, pos + 8)[0]
            flags = struct.unpack_from('<H', buf, pos + 12)[0]
            if length < 16:
                break
            if flags & 2:
                break
            last = (pos, length)
            pos += length
        return last


    def _remove_internal(self, node, hdr_off, ie_pos, ie_len, write_node,
                         ia_runs, block_size, alloc) -> None:
        '''Delete an internal (subnode-bearing) entry by promoting its in-order
           predecessor — the maximum key of its left subtree — into its slot,
           then removing that predecessor from its leaf. Faithful to a B-tree
           internal delete; no rebalancing (underfull nodes stay valid).

           Order matters for crash safety: remove the predecessor from the leaf
           FIRST, then promote. A crash between the two leaves the target entry
           in place (repair simply re-runs) and turns the predecessor into a
           reconnectable lost file — never a duplicate key.'''
        ie_vcn = struct.unpack_from('<q', node, ie_pos + ie_len - 8)[0]
        leaf_i, leaf = self._rightmost_leaf(alloc, block_size, ie_vcn)
        pred = self._last_real_entry(leaf, 24)
        if pred is None:
            # legal shape (removals emptied the subtree) that predecessor
            # promotion cannot cross — the caller rebuilds instead
            raise NtfsError(errno.ENOTSUP, 'empty subtree under an internal entry')
        p_pos, p_len = pred
        p_bytes = bytes(leaf[p_pos:p_pos + p_len])
        p_flags = struct.unpack_from('<H', p_bytes, 12)[0]
        if p_flags & 1:
            raise NtfsError(errno.ENOTSUP, 'predecessor unexpectedly has a subnode')

        # build the promoted separator: predecessor key/data + the deleted
        # entry's own subnode VCN, marked as a NODE entry
        key_len = struct.unpack_from('<H', p_bytes, 10)[0]
        content = p_bytes[:16 + key_len]
        content += b'\x00' * (-len(content) % 8)          # 8-byte align
        repl = bytearray(content + struct.pack('<q', ie_vcn))
        struct.pack_into('<H', repl, 8, len(repl))
        struct.pack_into('<H', repl, 12, (p_flags | 1) & ~2)  # NODE, not END

        eo, index_len = struct.unpack_from('<II', node, hdr_off)
        alloc_size = struct.unpack_from('<I', node, hdr_off + 8)[0]
        new_index_len = index_len - ie_len + len(repl)
        if new_index_len > alloc_size:
            raise NtfsError(errno.ENOTSUP,
                            'promoted separator does not fit — node split needed')

        # 1) drop the predecessor from its leaf (crash-safe half)
        self._splice_at(leaf, 24, p_pos, p_len)
        self._write_index_block(ia_runs, leaf_i, block_size, leaf)
        # 2) replace the target entry with the promoted separator
        tail = bytes(node[ie_pos + ie_len:hdr_off + index_len])
        node[ie_pos:ie_pos + len(repl)] = repl
        node[ie_pos + len(repl):ie_pos + len(repl) + len(tail)] = tail
        for i in range(hdr_off + new_index_len, hdr_off + index_len):
            node[i] = 0
        struct.pack_into('<I', node, hdr_off + 4, new_index_len)
        write_node()

    def remove_index_entry(self, dir_no: int, name: str) -> bool:
        '''Remove one $I30 entry by name — leaf via splice, internal via
           predecessor promotion; shapes the promotion cannot cross (emptied
           subtree, overfull node) fall back to a bulk rebuild of the index
           from its own surviving entries. Raises ENOENT when absent.'''
        try:
            return self._remove_index_entry_structural(dir_no, name)
        except NtfsError as exc:
            if exc.errno != errno.ENOTSUP:
                raise
            self._rebuild_without(dir_no, name)
            return True

    def _rebuild_without(self, dir_no: int, name: str) -> None:
        '''Bulk-rebuild the index from its own current entries minus `name` —
           always yields a canonical tree, reclaiming emptied blocks.'''
        root = self._attr_value(dir_no, AT_INDEX_ROOT, self._ix.name)
        try:
            alloc = self._attr_value(dir_no, AT_INDEX_ALLOCATION, self._ix.name)
        except NtfsError:
            alloc = b''
        block_size = struct.unpack_from('<I', root, 8)[0]
        nodes = [(bytes(root), 16)]
        for i in range(len(alloc) // block_size):
            blk = bytearray(alloc[i * block_size:(i + 1) * block_size])
            if blk[:4] == b'INDX' and _apply_fixups(blk):
                nodes.append((bytes(blk), 24))
        items = []
        for buf, hdr in nodes:
            reals, _end = self._decode_node(buf, hdr)
            for e in reals:
                klen = struct.unpack_from('<H', e, 10)[0]
                fn = e[16:16 + klen]
                nm = self._fn_key_name(fn).decode('utf-16-le', 'replace')
                if self.names_equal(nm, name):
                    continue
                mref = struct.unpack_from('<Q', e, 0)[0]
                leaf = self._ix.build_leaf(mref, fn)
                items.append((self._ix.entry_sort_key(leaf), leaf))
        items.sort(key=lambda t: t[0])
        self._bulk_write_index(dir_no, [e for _, e in items])

    def _remove_index_entry_structural(self, dir_no: int, name: str) -> bool:
        rec = self._load_record(dir_no)
        if rec is None:
            raise NtfsError(errno.EIO, f'directory record {dir_no} unreadable')
        loc = self._base_attr(rec, AT_INDEX_ROOT, self._ix.name)
        if loc is None:
            raise NtfsError(errno.ENOENT, f'record {dir_no} has no $I30 index root')
        a, _ln = loc
        vofs = struct.unpack_from('<H', rec, a + 20)[0]
        root_vofs = a + vofs
        block_size = struct.unpack_from('<I', rec, a + vofs + 8)[0]

        alloc = ia_runs = None

        def _index_alloc():
            nonlocal alloc, ia_runs
            if alloc is None:
                alloc = self._attr_value(dir_no, AT_INDEX_ALLOCATION, self._ix.name)
                _, ia_runs = self._stream_runs(dir_no, AT_INDEX_ALLOCATION, self._ix.name)
            return alloc, ia_runs

        match = lambda nm: self.names_equal(nm, name)
        ent = self._find_entry(rec, root_vofs + 16, match)
        if ent:
            pos, length, flags = ent
            if not flags & 1:  # leaf entry in the root
                self._splice_at(rec, root_vofs + 16, pos, length)
                self.write_record(dir_no, rec)
            else:              # internal entry in the root
                al, runs = _index_alloc()
                self._remove_internal(rec, root_vofs + 16, pos, length,
                                      lambda: self.write_record(dir_no, rec),
                                      runs, block_size, al)
            return True

        try:
            al, runs = _index_alloc()
        except NtfsError:
            raise NtfsError(errno.ENOENT, f'{name!r} not found in directory {dir_no}')
        for i in range(len(al) // block_size):
            blk = bytearray(al[i * block_size:(i + 1) * block_size])
            if blk[:4] != b'INDX' or not _apply_fixups(blk):
                continue
            ent = self._find_entry(blk, 24, match)
            if not ent:
                continue
            pos, length, flags = ent
            if not flags & 1:  # leaf entry in an INDX block
                self._splice_at(blk, 24, pos, length)
                self._write_index_block(runs, i, block_size, blk)
            else:              # internal entry in an INDX block
                def _write(bi=i, bb=blk):
                    self._write_index_block(runs, bi, block_size, bb)
                self._remove_internal(blk, 24, pos, length, _write,
                                      runs, block_size, al)
            return True
        raise NtfsError(errno.ENOENT, f'{name!r} not found in directory {dir_no}')

    def remove_dirent(self, path: str, name: str, really: bool) -> dict:
        info = super().remove_dirent(path, name, really=False)   # name, record, seq
        if not really:
            return info
        self.remove_index_entry(self._resolve(path), name)
        info['removed'] = True
        return info

    # -- phase 4: index-entry insertion (leaf insert + root grow; split deferred) --

    @staticmethod
    def _fn_key_name(fn_bytes) -> bytes:
        return bytes(fn_bytes[66:66 + 2 * fn_bytes[64]])

    def _upcase_seq(self, name_u16: bytes):
        '''UTF-16LE name upcased through $UpCase as a tuple of code units —
           the collation key. memoryview.cast avoids struct.unpack, and the
           full 65536-entry table needs no per-unit bounds check.'''
        vals = memoryview(name_u16).cast('H')
        up = self._upcase_table()
        if up is None:
            return tuple(vals)
        if len(up) >= 0x10000:
            return tuple([up[v] for v in vals])
        n = len(up)
        return tuple([up[v] if v < n else v for v in vals])

    @staticmethod
    def _build_leaf_entry(mref: int, fn_bytes: bytes) -> bytes:
        klen = len(fn_bytes)
        elen = (16 + klen + 7) & ~7
        e = bytearray(elen)
        struct.pack_into('<QHHH', e, 0, mref, elen, klen, 0)  # ref,len,keylen,flags
        e[16:16 + klen] = fn_bytes
        return bytes(e)

    @property
    def _i30(self) -> _IndexSchema:
        '''The $I30 directory-index schema (COLLATION_FILE_NAME): the stored key
           is the whole $FILE_NAME, ordered by its upcased name; the entry value
           is the 8-byte MFT reference.'''
        s = self.__dict__.get('_i30_cache')
        if s is None:
            s = self.__dict__['_i30_cache'] = _IndexSchema(
                name=self.I30, collation=0x01,
                sort_key=lambda fn: self._upcase_seq(fn[66:66 + 2 * fn[64]]),
                build_leaf=self._build_leaf_entry)
        return s

    @staticmethod
    def _build_view_leaf(data: bytes, key: bytes, magic: bool = False) -> bytes:
        '''A leaf INDEX_ENTRY for a $Secure view index: {data_offset, data_length}
           header, the key at offset 16, then the 20-byte SDS locator as the
           entry data. $SDH carries a 4-byte "II" (UTF-16LE) magic after the
           data; $SII does not.'''
        klen = len(key)
        doff = 16 + klen
        tail = b'\x49\x00\x49\x00' if magic else b''
        elen = (doff + len(data) + len(tail) + 7) & ~7
        e = bytearray(elen)
        struct.pack_into('<HH', e, 0, doff, len(data))   # data_offset, data_length
        struct.pack_into('<HHH', e, 8, elen, klen, 0)     # entry_len, key_len, flags
        e[16:16 + klen] = key
        e[doff:doff + len(data)] = data
        e[doff + len(data):doff + len(data) + len(tail)] = tail
        return bytes(e)

    @property
    def _sii(self) -> _IndexSchema:
        '''$Secure $SII: key = security_id (u32), COLLATION_NTOFS_ULONG.'''
        s = self.__dict__.get('_sii_cache')
        if s is None:
            s = self.__dict__['_sii_cache'] = _IndexSchema(
                name='$SII'.encode('utf-16-le'), collation=0x10,
                sort_key=lambda k: int.from_bytes(k[:4], 'little'),
                build_leaf=lambda data, key: self._build_view_leaf(data, key))
        return s

    @property
    def _sdh(self) -> _IndexSchema:
        '''$Secure $SDH: key = {hash u32, id u32}, COLLATION_NTOFS_SECURITY_HASH.'''
        s = self.__dict__.get('_sdh_cache')
        if s is None:
            s = self.__dict__['_sdh_cache'] = _IndexSchema(
                name='$SDH'.encode('utf-16-le'), collation=0x12,
                sort_key=lambda k: struct.unpack_from('<II', k),
                build_leaf=lambda data, key: self._build_view_leaf(data, key, magic=True))
        return s

    @property
    def _ix(self) -> _IndexSchema:
        '''The index schema the B+ write engine currently operates on — $I30 by
           default. (A generic view-index insert will scope self._ix_override.)'''
        return getattr(self, '_ix_override', None) or self._i30

    def _resident_grow_root(self, rec: bytearray, root_attr_off: int,
                            delta: int) -> None:
        '''Resize the resident $INDEX_ROOT attribute by delta bytes in place
           (negative shrinks), shifting the attributes after it and the
           record's used size. Refuses if the record has no room for a grow
           (that needs small→large conversion).'''
        in_use = struct.unpack_from('<I', rec, 0x18)[0]
        if in_use + delta > len(rec):
            raise NtfsError(errno.ENOTSUP,
                            'directory record full — cannot grow the resident index root')
        attr_len = struct.unpack_from('<I', rec, root_attr_off + 4)[0]
        tail = bytes(rec[root_attr_off + attr_len:in_use])
        rec[root_attr_off + attr_len + delta:
            root_attr_off + attr_len + delta + len(tail)] = tail
        for i in range(root_attr_off + attr_len, root_attr_off + attr_len + delta):
            rec[i] = 0                             # grow: zero the inserted gap
        for i in range(in_use + delta, in_use):
            rec[i] = 0                             # shrink: zero the freed tail
        vlen = struct.unpack_from('<I', rec, root_attr_off + 0x10)[0]
        vofs = struct.unpack_from('<H', rec, root_attr_off + 0x14)[0]
        struct.pack_into('<I', rec, root_attr_off + 4, attr_len + delta)
        struct.pack_into('<I', rec, root_attr_off + 0x10, vlen + delta)
        struct.pack_into('<I', rec, 0x18, in_use + delta)
        hdr = root_attr_off + vofs + 16  # INDEX_HEADER.allocated_size
        asz = struct.unpack_from('<I', rec, hdr + 8)[0]
        struct.pack_into('<I', rec, hdr + 8, asz + delta)

    # -- phase 4d: attribute creation + small→large conversion --

    def _add_attr(self, rec: bytearray, attr_type: int, name_u16: bytes,
                  resident: bool, value: bytes = b'', runs=None,
                  data_size: int = 0) -> int:
        '''Build an attribute and insert it into the base record in (type, name)
           order. resident: uses `value`. non-resident: uses `runs` (encoded as
           mapping pairs) + data_size. Returns the attribute's record offset;
           raises ENOTSUP if the record is full ($ATTRIBUTE_LIST spill needed).'''
        name_len = len(name_u16) // 2
        if resident:
            name_off = 0x18
            val_off = ((name_off + len(name_u16) + 7) & ~7) if name_len else 0x18
            alen = (val_off + len(value) + 7) & ~7
            attr = bytearray(alen)
            struct.pack_into('<IIBBH', attr, 0, attr_type, alen, 0, name_len,
                             name_off if name_len else 0)
            struct.pack_into('<IH', attr, 0x10, len(value), val_off)
            if name_len:
                attr[name_off:name_off + len(name_u16)] = name_u16
            attr[val_off:val_off + len(value)] = value
        else:
            name_off = 0x40
            mp_off = ((name_off + len(name_u16) + 7) & ~7) if name_len else 0x40
            mp = _encode_mapping_pairs(runs)
            alen = (mp_off + len(mp) + 7) & ~7
            total = sum(n for _lcn, n in runs)
            attr = bytearray(alen)
            struct.pack_into('<IIBBH', attr, 0, attr_type, alen, 1, name_len,
                             name_off if name_len else 0)
            struct.pack_into('<qq', attr, 0x10, 0, total - 1)   # lowest/highest vcn
            struct.pack_into('<H', attr, 0x20, mp_off)
            struct.pack_into('<qqq', attr, 0x28, data_size, data_size, data_size)
            if name_len:
                attr[name_off:name_off + len(name_u16)] = name_u16
            attr[mp_off:mp_off + len(mp)] = mp
        inst = struct.unpack_from('<H', rec, 0x28)[0]
        struct.pack_into('<H', attr, 0x0E, inst)
        struct.pack_into('<H', rec, 0x28, inst + 1)

        in_use = struct.unpack_from('<I', rec, 0x18)[0]
        if in_use + alen > len(rec):
            raise NtfsError(errno.ENOTSUP, 'record full — $ATTRIBUTE_LIST spill needed')
        a = struct.unpack_from('<H', rec, 0x14)[0]
        while a + 4 <= in_use:                              # (type, name) order
            t = struct.unpack_from('<I', rec, a)[0]
            if t == 0xFFFFFFFF or t > attr_type:
                break
            a += struct.unpack_from('<I', rec, a + 4)[0]
        tail = bytes(rec[a:in_use])
        rec[a + alen:a + alen + len(tail)] = tail
        rec[a:a + alen] = attr
        struct.pack_into('<I', rec, 0x18, in_use + alen)
        return a

    def _replace_resident_value(self, rec: bytearray, attr_off: int,
                                new_value: bytes) -> None:
        '''Replace a resident attribute's value (any length), shifting the
           attributes after it and the record's used size. Shrinking frees
           record space; growing needs room (else the caller must spill).'''
        vofs = struct.unpack_from('<H', rec, attr_off + 0x14)[0]
        old_alen = struct.unpack_from('<I', rec, attr_off + 4)[0]
        new_alen = (vofs + len(new_value) + 7) & ~7
        in_use = struct.unpack_from('<I', rec, 0x18)[0]
        if in_use + (new_alen - old_alen) > len(rec):
            raise NtfsError(errno.ENOTSUP, 'record full')
        tail = bytes(rec[attr_off + old_alen:in_use])
        rec[attr_off + new_alen:attr_off + new_alen + len(tail)] = tail
        rec[attr_off + vofs:attr_off + vofs + len(new_value)] = new_value
        struct.pack_into('<I', rec, attr_off + 4, new_alen)
        struct.pack_into('<I', rec, attr_off + 0x10, len(new_value))
        new_in_use = in_use + (new_alen - old_alen)
        struct.pack_into('<I', rec, 0x18, new_in_use)
        for i in range(new_in_use, in_use):                 # zero any freed tail
            rec[i] = 0

    def _small_to_large(self, dir_no: int, block_size: int, vpb: int) -> None:
        '''Convert a SMALL_INDEX (resident $INDEX_ROOT only) into a LARGE index:
           shrink the root to a single END→block pointer (freeing record space),
           create the $INDEX_ALLOCATION and $BITMAP attributes in that space,
           and move the root's entries into the new block.'''
        rec = self._load_record(dir_no)
        if rec is None:
            raise NtfsError(errno.EIO, f'directory record {dir_no} unreadable')
        ra, _l = self._base_attr(rec, AT_INDEX_ROOT, self._ix.name)
        rvofs = ra + struct.unpack_from('<H', rec, ra + 0x14)[0]
        reals, end = self._decode_node(rec, rvofs + 16)     # leaf entries + END
        # 1) shrink the root to a minimal LARGE root: prefix + header + END→0
        prefix = bytes(rec[rvofs:rvofs + 16])
        end_node = self._end_node(0)
        vlen = 32 + len(end_node)
        ih = struct.pack('<IIIBxxx', 16, 16 + len(end_node), vlen - 16, 1)
        self._replace_resident_value(rec, ra, prefix + ih + end_node)
        # 2) create $INDEX_ALLOCATION (1 block) and $BITMAP in the freed space
        cpb = block_size // self._cluster_size
        runs = self.alloc_clusters(cpb)
        try:
            self._add_attr(rec, AT_INDEX_ALLOCATION, self._ix.name, resident=False,
                           runs=[(l, n) for l, n in runs], data_size=block_size)
            bm = bytearray(8)                                # 1 bit/block; 8 = 64 blocks
            bm[0] = 1                                        # block 0 in use
            self._add_attr(rec, AT_BITMAP, self._ix.name, resident=True, value=bytes(bm))
        except NtfsError:
            self.free_clusters(runs)
            raise
        self.write_record(dir_no, rec)
        if getattr(self, '_ia_cache', None):
            self._ia_cache.pop(dir_no, None)
        # 3) move the old root entries into block 0
        blk = self._new_indx_block(0, block_size)
        self._pack_node(blk, 24, reals, end)
        self._write_block(dir_no, 0, block_size, blk)

    # -- phase 4b: node split — insertion never refuses (large indexes) --

    @staticmethod
    def _leaf_end() -> bytes:
        return struct.pack('<QHHHH', 0, 16, 0, 2, 0)  # END, no subnode

    @staticmethod
    def _end_node(vcn: int) -> bytes:
        return struct.pack('<QHHHH', 0, 24, 0, 3, 0) + struct.pack('<q', vcn)

    @staticmethod
    def _entry_subnode(e: bytes) -> int:
        return struct.unpack_from('<q', e, len(e) - 8)[0]

    @staticmethod
    def _set_subnode(e: bytes, vcn: int) -> bytes:
        b = bytearray(e)
        struct.pack_into('<q', b, len(b) - 8, vcn)
        return bytes(b)

    @staticmethod
    def _make_node_entry(e: bytes, vcn: int) -> bytes:
        '''Promote entry e to a NODE separator: the entry followed by the
           8-byte subnode VCN. A $Secure view-index entry carries its 20-byte
           data (+ $SDH magic) into the separator — NTFS keeps the median's data
           in the internal node — while a directory ($I30) entry is just
           header+key+pad, so this is byte-identical to the old header+key form
           there. An entry that is already a separator (multi-level split)
           must first shed its own subnode VCN, or the ghost 8 bytes make
           entry_length non-canonical — chkdsk flags that as an index error.'''
        elen = struct.unpack_from('<H', e, 8)[0]
        flags = struct.unpack_from('<H', e, 12)[0]
        if flags & 1:
            elen -= 8
        base = bytes(e[:elen])
        base += b'\x00' * (-len(base) % 8)
        b = bytearray(base + struct.pack('<q', vcn))
        struct.pack_into('<H', b, 8, len(b))
        struct.pack_into('<H', b, 12, 1)  # NODE, not END
        return bytes(b)

    @staticmethod
    def _decode_node(buf, hdr_off):
        eo, il = struct.unpack_from('<II', buf, hdr_off)
        pos, limit, reals, end = hdr_off + eo, hdr_off + il, [], None
        while pos + 16 <= limit:
            length = struct.unpack_from('<H', buf, pos + 8)[0]
            flags = struct.unpack_from('<H', buf, pos + 12)[0]
            if length < 16:
                break
            e = bytes(buf[pos:pos + length])
            if flags & 2:
                end = e
                break
            reals.append(e)
            pos += length
        if end is None:
            raise NtfsError(errno.EIO, 'index node without END entry')
        return reals, end

    @staticmethod
    def _pack_node(buf, hdr_off, reals, end) -> bool:
        '''Write reals+end into the node; False if it overflows allocated_size.
           Also fixes the INDEX_HEADER node flag from the END entry.'''
        eo = struct.unpack_from('<I', buf, hdr_off)[0]
        asz = struct.unpack_from('<I', buf, hdr_off + 8)[0]
        old_il = struct.unpack_from('<I', buf, hdr_off + 4)[0]
        body = b''.join(reals) + end
        new_il = eo + len(body)
        if new_il > asz:
            return False
        p = hdr_off + eo
        buf[p:p + len(body)] = body
        for i in range(p + len(body), hdr_off + max(old_il, new_il)):
            buf[i] = 0
        struct.pack_into('<I', buf, hdr_off + 4, new_il)
        node_flag = struct.unpack_from('<H', end, 12)[0] & 1
        buf[hdr_off + 12] = node_flag  # INDEX_HEADER.flags: has children?
        return True

    def _new_indx_block(self, vcn: int, block_size: int):
        blk = bytearray(block_size)
        blk[:4] = b'INDX'
        usa_ofs, usa_count = 40, 1 + block_size // 512
        struct.pack_into('<HH', blk, 4, usa_ofs, usa_count)
        struct.pack_into('<q', blk, 16, vcn)
        entries_off = ((usa_ofs + 2 * usa_count + 7) & ~7) - 24
        struct.pack_into('<IIIB', blk, 24, entries_off, entries_off,
                         block_size - 24, 0)
        return blk

    def _ia(self, dir_no):
        '''Cached (size, runs) of $INDEX_ALLOCATION — invalidated only on grow.'''
        cache = getattr(self, '_ia_cache', None)
        if cache is None:
            cache = self._ia_cache = {}
        got = cache.get(dir_no)
        if got is None:
            got = cache[dir_no] = self._stream_runs(dir_no, AT_INDEX_ALLOCATION,
                                                    self._ix.name)
        return got

    def _read_block(self, dir_no, block_index, block_size):
        _size, runs = self._ia(dir_no)
        return bytearray(self._runs_read(runs, block_index * block_size, block_size))

    def _write_block(self, dir_no, block_index, block_size, blk) -> None:
        _s, runs = self._ia(dir_no)
        self._write_index_block(runs, block_index, block_size, blk)

    def _alloc_index_block(self, dir_no, block_size, vpb):
        '''(block_index, vcn) of a free INDX block — reusing a clear $BITMAP
           bit, else growing $INDEX_ALLOCATION by one block.'''
        bm = self._read_i30_bitmap(dir_no)
        size, _runs = self._ia(dir_no)
        n_blocks = size // block_size
        for i in range(n_blocks):
            if not bm[i >> 3] & (1 << (i & 7)):
                bm[i >> 3] |= 1 << (i & 7)
                self._write_i30_bitmap(dir_no, bm)
                return i, i * vpb
        return self._grow_index_alloc(dir_no, block_size, vpb, bm, n_blocks)

    def _base_attr(self, rec, atype, name):
        for a, t, ln in _attrs(rec):
            if t == atype:
                nlen = rec[a + 9]
                nofs = struct.unpack_from('<H', rec, a + 10)[0]
                aname = bytes(rec[a + nofs:a + nofs + 2 * nlen]) if nlen else b''
                if aname == (name or b''):
                    return a, ln
        return None

    def _read_i30_bitmap(self, dir_no):
        found = self._find_attr(dir_no, AT_BITMAP, self._ix.name)  # base or extension
        if not found:
            raise NtfsError(errno.ENOENT, 'directory has no $I30 $BITMAP')
        _no, rec, a = found
        ln = struct.unpack_from('<I', rec, a + 4)[0]
        if rec[a + 8] == 0:
            vo = struct.unpack_from('<H', rec, a + 20)[0]
            vl = struct.unpack_from('<I', rec, a + 16)[0]
            return bytearray(rec[a + vo:a + vo + vl])
        _p, _ph, runs = _check_mapping_pairs(bytes(rec), a, ln, self.nr_clusters())
        return bytearray(self._runs_read(runs, 0, struct.unpack_from('<q', rec, a + 48)[0]))

    def _write_i30_bitmap(self, dir_no, bm):
        rec_no, rec, a = self._find_attr(dir_no, AT_BITMAP, self._ix.name)
        ln = struct.unpack_from('<I', rec, a + 4)[0]
        if rec[a + 8] == 0:
            vo = struct.unpack_from('<H', rec, a + 20)[0]
            vl = struct.unpack_from('<I', rec, a + 16)[0]
            rec[a + vo:a + vo + vl] = bytes(bm)[:vl]
            self.write_record(rec_no, rec)
        else:
            _p, _ph, runs = _check_mapping_pairs(bytes(rec), a, ln, self.nr_clusters())
            self._runs_write(runs, 0, bytes(bm))

    def _grow_i30_bitmap(self, dir_no, want_bytes: int):
        '''Extend the $I30 $BITMAP to at least want_bytes. If its record is full,
           spill $INDEX_ALLOCATION + $BITMAP to an extension record (only when
           the bitmap still lives in the base) and retry there.'''
        rec_no, rec, a = self._find_attr(dir_no, AT_BITMAP, self._ix.name)
        if rec[a + 8] != 0:
            raise NtfsError(errno.ENOTSUP, 'non-resident $I30 $BITMAP growth not implemented')
        vo = struct.unpack_from('<H', rec, a + 0x14)[0]
        vl = struct.unpack_from('<I', rec, a + 0x10)[0]
        if want_bytes <= vl:
            return
        cur = bytes(rec[a + vo:a + vo + vl])
        try:
            self._replace_resident_value(rec, a, cur + b'\x00' * (want_bytes - vl))
        except NtfsError:                              # record full
            if rec_no != dir_no:
                raise NtfsError(errno.ENOTSUP, 'extension $BITMAP record full — '
                                'further spill not implemented')
            self._spill_index_alloc(dir_no)            # frees the base (or re-raises)
            return self._grow_i30_bitmap(dir_no, want_bytes)
        self.write_record(rec_no, rec)

    # -- phase 4e: $ATTRIBUTE_LIST spill (base record full → extension records) --

    def _find_attr(self, dir_no, attr_type, name):
        '''(record_no, fixed-up record, attr_off) of an attribute — searching the
           base record, then extension records via $ATTRIBUTE_LIST. None if
           absent. name is UTF-16LE (or b'' for unnamed).'''
        base = self._load_record(dir_no)
        if base is None:
            raise NtfsError(errno.EIO, f'record {dir_no} unreadable')
        loc = self._base_attr(base, attr_type, name)
        if loc:
            return dir_no, base, loc[0]
        for ext_no in self._extension_records(dir_no):
            ext = self._load_record(ext_no)
            if ext is None:
                continue
            loc = self._base_attr(ext, attr_type, name)
            if loc:
                return ext_no, ext, loc[0]
        return None

    def _build_extension_record(self, base_no, base_seq, ext_seq, attrs):
        '''A minimal extension FILE record holding `attrs` (each re-instanced),
           with base_reference pointing back at the base. Returns the record.'''
        rs = self._rec_size
        rec = bytearray(rs)
        rec[:4] = b'FILE'
        usa_ofs, usa_count = 0x30, 1 + rs // 512
        struct.pack_into('<HH', rec, 4, usa_ofs, usa_count)
        struct.pack_into('<H', rec, 0x10, ext_seq)              # sequence
        struct.pack_into('<H', rec, 0x12, 0)                    # hard_link_count
        attrs_off = (usa_ofs + 2 * usa_count + 7) & ~7
        struct.pack_into('<H', rec, 0x14, attrs_off)            # attrs offset
        struct.pack_into('<H', rec, 0x16, 1)                    # flags: in use
        struct.pack_into('<Q', rec, 0x20, base_no | (base_seq << 48))
        off = attrs_off
        for inst, attr in enumerate(attrs):
            a = bytearray(attr)
            struct.pack_into('<H', a, 0x0E, inst)               # instance id
            rec[off:off + len(a)] = a
            off += len(a)
        struct.pack_into('<I', rec, off, 0xFFFFFFFF)
        struct.pack_into('<I', rec, 0x18, off + 4)             # bytes_in_use
        struct.pack_into('<I', rec, 0x1C, rs)                  # bytes_allocated
        struct.pack_into('<H', rec, 0x28, len(attrs))         # next_attr_id
        struct.pack_into('<I', rec, 0x2C, 0)                  # record number (unused)
        return rec

    @staticmethod
    def _al_entry(atype, name_u16, vcn, ref_no, ref_seq, inst):
        nl = len(name_u16) // 2
        rlen = (0x1A + len(name_u16) + 7) & ~7
        e = bytearray(rlen)
        struct.pack_into('<IHBB', e, 0, atype, rlen, nl, 0x1A if nl else 0)
        struct.pack_into('<Q', e, 8, vcn)
        struct.pack_into('<Q', e, 16, ref_no | (ref_seq << 48))
        struct.pack_into('<H', e, 24, inst)
        if nl:
            e[0x1A:0x1A + len(name_u16)] = name_u16
        return atype, name_u16, bytes(e)

    def _spill_index_alloc(self, dir_no):
        '''Move $INDEX_ALLOCATION and $BITMAP out of a full base record into a
           fresh extension record, adding an $ATTRIBUTE_LIST to the base so both
           can keep growing in the roomy extension. First spill only (a base
           that already has a list is refused). Atomic: the extension
           record is freed if anything fails.'''
        base = self._load_record(dir_no)
        if base is None:
            raise NtfsError(errno.EIO, f'record {dir_no} unreadable')
        if self._base_attr(base, AT_ATTRIBUTE_LIST, b''):
            raise NtfsError(errno.ENOTSUP, 'directory already has an '
                            '$ATTRIBUTE_LIST — further spill not implemented')
        base_seq = struct.unpack_from('<H', base, 0x10)[0]
        # attributes to relocate, by record offset (removed high→low)
        move = []
        for atype in (AT_INDEX_ALLOCATION, AT_BITMAP):
            loc = self._base_attr(base, atype, self._ix.name)
            if loc:
                a = loc[0]
                alen = struct.unpack_from('<I', base, a + 4)[0]
                move.append((a, atype, bytes(base[a:a + alen])))
        if not any(m[1] == AT_INDEX_ALLOCATION for m in move):
            raise NtfsError(errno.ENOTSUP, '$INDEX_ALLOCATION not in base record')

        ext_no = self.alloc_record()
        try:
            old = self.read_record(ext_no)
            ext_seq = 1
            if old and old[:4] == b'FILE':
                ext_seq = (struct.unpack_from('<H', old, 0x10)[0] + 1) & 0xFFFF or 1
            moved_bytes = [b for _a, _t, b in move]
            ext = self._build_extension_record(dir_no, base_seq, ext_seq, moved_bytes)
            ext_inst = {t: i for i, (_a, t, _b) in enumerate(move)}   # instance in ext

            # remove the moved attributes from the base (high offset first)
            for a, _t, blob in sorted(move, key=lambda m: -m[0]):
                in_use = struct.unpack_from('<I', base, 0x18)[0]
                alen = len(blob)
                tail = bytes(base[a + alen:in_use])
                base[a:a + len(tail)] = tail
                struct.pack_into('<I', base, 0x18, in_use - alen)
                for i in range(in_use - alen, in_use):
                    base[i] = 0

            # $ATTRIBUTE_LIST: remaining base attrs → base, moved → extension
            entries, off = [], struct.unpack_from('<H', base, 0x14)[0]
            end = struct.unpack_from('<I', base, 0x18)[0]
            while off + 4 <= end:
                t = struct.unpack_from('<I', base, off)[0]
                if t == 0xFFFFFFFF:
                    break
                ln = struct.unpack_from('<I', base, off + 4)[0]
                nl = base[off + 9]
                nofs = struct.unpack_from('<H', base, off + 10)[0]
                nm = bytes(base[off + nofs:off + nofs + 2 * nl]) if nl else b''
                inst = struct.unpack_from('<H', base, off + 0x0E)[0]
                entries.append(self._al_entry(t, nm, 0, dir_no, base_seq, inst))
                off += ln
            for _a, t, _b in move:
                entries.append(self._al_entry(t, self._ix.name, 0, ext_no, ext_seq,
                                              ext_inst[t]))
            entries.sort(key=lambda x: (x[0], x[1]))
            al_value = b''.join(e for _t, _n, e in entries)
            self._add_attr(base, AT_ATTRIBUTE_LIST, b'', resident=True, value=al_value)

            self.write_record(ext_no, ext)
            self.write_record(dir_no, base)
        except NtfsError:
            self.free_record(ext_no)                # undo the extension allocation
            raise
        if getattr(self, '_ia_cache', None):
            self._ia_cache.pop(dir_no, None)
        if getattr(self, '_attr_memo', None):
            self._attr_memo.clear()

    def _grow_index_alloc(self, dir_no, block_size, vpb, bm, n_blocks):
        '''Append one INDX block to $INDEX_ALLOCATION and set its $BITMAP bit,
           growing the resident $BITMAP if needed. When the $INDEX_ALLOCATION
           mapping pairs would overflow the base record, spill it to an
           extension record (via $ATTRIBUTE_LIST) and retry.'''
        if (n_blocks >> 3) >= len(bm):
            self._grow_i30_bitmap(dir_no, (n_blocks // 8 + 8) & ~7)
            bm = self._read_i30_bitmap(dir_no)
        cpb = block_size // self._cluster_size
        found = self._find_attr(dir_no, AT_INDEX_ALLOCATION, self._ix.name)
        if not found:
            raise NtfsError(errno.EIO, '$INDEX_ALLOCATION not found')
        ia_no, rec, a = found
        ln = struct.unpack_from('<I', rec, a + 4)[0]
        _p, _ph, existing = _check_mapping_pairs(bytes(rec), a, ln, self.nr_clusters())
        merged = [(l, n) for l, n, _v in existing]
        hint = merged[-1][0] + merged[-1][1] if merged else 0
        new_runs = self.alloc_clusters(cpb, near_lcn=hint)
        for lcn, rl in new_runs:
            if merged and merged[-1][0] + merged[-1][1] == lcn:
                merged[-1] = (merged[-1][0], merged[-1][1] + rl)
            else:
                merged.append((lcn, rl))
        mp = _encode_mapping_pairs(merged)
        mp_off = struct.unpack_from('<H', rec, a + 32)[0]
        if mp_off + len(mp) > ln:
            # the attribute is sized tightly, so a runlist that fragments
            # routinely needs a few more bytes: grow it in place while its
            # record has room, spilling only when the record is truly full
            delta = (mp_off + len(mp) - ln + 7) & ~7
            in_use = struct.unpack_from('<I', rec, 0x18)[0]
            if in_use + delta <= len(rec):
                tail = bytes(rec[a + ln:in_use])
                rec[a + ln + delta:a + ln + delta + len(tail)] = tail
                for i in range(a + ln, a + ln + delta):
                    rec[i] = 0
                struct.pack_into('<I', rec, a + 4, ln + delta)
                struct.pack_into('<I', rec, 0x18, in_use + delta)
                ln += delta
            elif ia_no == dir_no:               # still in the base — spill and retry
                self.free_clusters(new_runs)
                self._spill_index_alloc(dir_no)
                return self._grow_index_alloc(dir_no, block_size, vpb,
                                              self._read_i30_bitmap(dir_no), n_blocks)
            else:
                self.free_clusters(new_runs)
                raise NtfsError(errno.ENOTSUP, 'extension $INDEX_ALLOCATION record '
                                'full — further spill not implemented')
        for i in range(a + mp_off, a + ln):
            rec[i] = 0
        rec[a + mp_off:a + mp_off + len(mp)] = mp
        new_size = (n_blocks + 1) * block_size
        struct.pack_into('<q', rec, a + 24, (n_blocks + 1) * vpb - 1)   # highest_vcn
        struct.pack_into('<q', rec, a + 40, new_size)                   # allocated
        struct.pack_into('<q', rec, a + 48, new_size)                   # data
        struct.pack_into('<q', rec, a + 56, new_size)                   # initialized
        self.write_record(ia_no, rec)                                   # base or extension
        bm[n_blocks >> 3] |= 1 << (n_blocks & 7)
        self._write_i30_bitmap(dir_no, bm)
        getattr(self, '_ia_cache', {}).pop(dir_no, None)
        return n_blocks, n_blocks * vpb

    def _node_buf(self, dir_no, ref, block_size):
        '''(buf, hdr_off, root_attr_off|None) for a node reference.'''
        if ref[0] == 'root':
            rec = self._load_record(dir_no)
            if rec is None:
                raise NtfsError(errno.EIO, f'directory record {dir_no} unreadable')
            a, _ln = self._base_attr(rec, AT_INDEX_ROOT, self._ix.name)
            vofs = struct.unpack_from('<H', rec, a + 20)[0]
            return rec, a + vofs + 16, a
        i = ref[1]
        blk = self._read_block(dir_no, i, block_size)
        if blk[:4] != b'INDX' or not _apply_fixups(blk):
            raise NtfsError(errno.EIO, f'index block {i} unreadable')
        return blk, 24, None

    def _node_flush(self, dir_no, ref, buf, block_size):
        if ref[0] == 'root':
            self.write_record(dir_no, buf)
        else:
            self._write_block(dir_no, ref[1], block_size, buf)

    def _pack_or_grow(self, dir_no, ref, buf, hdr_off, root_attr_off,
                      reals, end, block_size) -> bool:
        '''Pack and flush; grow a resident root if it overflows. Returns True if
           it fit (done), False for a block that must split. Root that can't
           grow → ENOTSUP (small→large / root split not implemented here).'''
        if self._pack_node(buf, hdr_off, reals, end):
            self._node_flush(dir_no, ref, buf, block_size)
            return True
        if ref[0] != 'root':
            return False
        eo = struct.unpack_from('<I', buf, hdr_off)[0]
        asz = struct.unpack_from('<I', buf, hdr_off + 8)[0]
        need = eo + len(b''.join(reals) + end)
        delta = (need - asz + 7) & ~7
        self._resident_grow_root(buf, root_attr_off, delta)  # raises ENOTSUP if full
        if not self._pack_node(buf, hdr_off, reals, end):
            raise NtfsError(errno.ENOTSUP, 'root would need a height increase '
                            '(small→large / root split) here — not implemented')
        self._node_flush(dir_no, ref, buf, block_size)
        return True

    @staticmethod
    def _would_pack(hdr_off_asz_eo, reals, end) -> bool:
        asz, eo = hdr_off_asz_eo
        return eo + len(b''.join(reals) + end) <= asz

    def insert_index_entry(self, dir_no: int, mref: int, fn_bytes: bytes) -> bool:
        '''Insert a $FILE_NAME leaf entry into a directory's $I30 in collation
           order. A full leaf splits and promotes its median to the parent
           (which grows if it is the resident root). Plan-then-commit and
           bounded: the whole operation is verified feasible BEFORE any write,
           and a split that would cascade past the immediate parent, need a root
           height increase, or overflow the $INDEX_ALLOCATION attribute record
           raises ENOTSUP with nothing written. EEXIST on a
           duplicate name.'''
        rec = self._load_record(dir_no)
        if rec is None:
            raise NtfsError(errno.EIO, f'directory record {dir_no} unreadable')
        loc = self._base_attr(rec, AT_INDEX_ROOT, self._ix.name)
        if not loc:
            raise NtfsError(errno.ENOENT, f'record {dir_no} has no $I30 index root')
        a, _ln = loc
        vofs = struct.unpack_from('<H', rec, a + 20)[0]
        block_size = struct.unpack_from('<I', rec, a + vofs + 8)[0]
        vpb = max(block_size // self._cluster_size, 1)
        new_key = self._ix.sort_key(fn_bytes)   # collation key of the new entry
        entry = self._ix.build_leaf(mref, fn_bytes)

        # -- descend, recording the path root→leaf --
        path, ref = [], ('root', dir_no)
        while True:
            buf, hdr_off, rao = self._node_buf(dir_no, ref, block_size)
            reals, end = self._decode_node(buf, hdr_off)
            idx, descend = None, None
            for k, e in enumerate(reals):
                ek = self._ix.entry_sort_key(e)
                if new_key == ek:
                    raise NtfsError(errno.EEXIST, 'name already present in index')
                if new_key < ek:
                    idx = k
                    if struct.unpack_from('<H', e, 12)[0] & 1:
                        descend = self._entry_subnode(e)
                    break
            if idx is None:
                idx = len(reals)
                if struct.unpack_from('<H', end, 12)[0] & 1:
                    descend = self._entry_subnode(end)
            asz = struct.unpack_from('<I', buf, hdr_off + 8)[0]
            eo = struct.unpack_from('<I', buf, hdr_off)[0]
            path.append({'ref': ref, 'buf': buf, 'hdr': hdr_off, 'rao': rao,
                         'reals': reals, 'end': end, 'idx': idx, 'cap': (asz, eo)})
            if descend is None:
                break
            ref = ('block', descend // vpb)

        leaf = path[-1]
        # small (root-only) index whose root can't hold the new entry even
        # grown → convert to a large index, then retry into the block tree
        if leaf['ref'][0] == 'root':
            body_len = len(b''.join(leaf['reals']) + [leaf['end']][0]) \
                + len(entry)
            if not self._root_body_room(leaf['buf'], leaf['rao'], body_len):
                self._small_to_large(dir_no, block_size, vpb)
                return self.insert_index_entry(dir_no, mref, fn_bytes)
        leaf['reals'].insert(leaf['idx'], entry)
        # fast path: fits in the leaf (grow the root if that is the leaf)
        if self._pack_or_grow(dir_no, leaf['ref'], leaf['buf'], leaf['hdr'],
                              leaf['rao'], leaf['reals'], leaf['end'], block_size):
            return True

        # leaf overflow → multi-level atomic cascade split. Plan the whole
        # cascade bottom-up, allocating one block per split; if any allocation
        # fails (e.g. $INDEX_ALLOCATION mapping-pairs overflow) free them all and
        # refuse — nothing else is written, so the refusal is atomic. Only once
        # every block is reserved do we commit the node writes (which can't fail).
        if leaf['ref'][0] != 'block':
            raise NtfsError(errno.EIO, 'root leaf overflow after conversion check')
        allocated, writes, carry = [], [], None
        i = len(path) - 1
        try:
            while i >= 0:
                node = path[i]
                if carry is not None:
                    self._insert_median_inplace(node, *carry)
                    carry = None
                if node['ref'][0] == 'root':                # root: grow or heighten
                    fresh = self._load_record(dir_no)
                    if fresh is None:
                        raise NtfsError(errno.EIO,
                                        f'directory record {dir_no} unreadable')
                    ra_f, _l = self._base_attr(fresh, AT_INDEX_ROOT, self._ix.name)
                    body_len = len(b''.join(node['reals']) + node['end'])
                    # keep the resident root small (a third of the record) so the
                    # base has room for $INDEX_ALLOCATION + $BITMAP — heighten to
                    # a tiny END→child pointer early rather than growing a fat 2-level 
                    # root that starves the base
                    if body_len <= self._rec_size // 3 \
                            and self._root_body_room(fresh, ra_f, body_len):
                        writes.append(('rootfit', node))
                    else:
                        b_i, b_vcn = self._alloc_index_block(dir_no, block_size, vpb)
                        allocated.append(b_i)
                        writes.append(('rootheighten', node, b_vcn))
                    break
                if self._would_pack(node['cap'], node['reals'], node['end']):
                    writes.append(('blockfit', node))
                    break
                end_is_node = bool(struct.unpack_from('<H', node['end'], 12)[0] & 1)
                mid = len(node['reals']) // 2
                median_e = node['reals'][mid]
                left, right = node['reals'][:mid], node['reals'][mid + 1:]
                if end_is_node:
                    left_end = self._end_node(self._entry_subnode(median_e))
                    right_end = node['end']
                else:
                    left_end = right_end = self._leaf_end()
                my_vcn = node['ref'][1] * vpb
                new_i, new_vcn = self._alloc_index_block(dir_no, block_size, vpb)
                allocated.append(new_i)
                writes.append(('split', node, left, left_end, right, right_end, new_vcn))
                carry = (self._make_node_entry(median_e, my_vcn), my_vcn, new_vcn)
                i -= 1
            else:
                raise NtfsError(errno.EIO, 'cascade ran off the top of the tree')
        except NtfsError:
            for bi in allocated:
                self._free_index_block(dir_no, bi)
            raise

        for w in writes:                                    # commit — cannot fail
            if w[0] == 'split':
                _, node, left, left_end, right, right_end, new_vcn = w
                if not self._pack_node(node['buf'], node['hdr'], left, left_end):
                    raise NtfsError(errno.EIO, 'left half overflow (unexpected)')
                self._write_block(dir_no, node['ref'][1], block_size, node['buf'])
                nb = self._new_indx_block(new_vcn, block_size)
                if not self._pack_node(nb, 24, right, right_end):
                    raise NtfsError(errno.EIO, 'upper half overflow (unexpected)')
                self._write_block(dir_no, new_vcn // vpb, block_size, nb)
            elif w[0] == 'blockfit':
                node = w[1]
                self._pack_node(node['buf'], node['hdr'], node['reals'], node['end'])
                self._write_block(dir_no, node['ref'][1], block_size, node['buf'])
            elif w[0] == 'rootfit':
                node = w[1]
                self._write_root_node(dir_no, node['reals'], node['end'], small=False)
            elif w[0] == 'rootheighten':
                _, node, b_vcn = w
                bblk = self._new_indx_block(b_vcn, block_size)
                self._pack_node(bblk, 24, node['reals'], node['end'])
                self._write_block(dir_no, b_vcn // vpb, block_size, bblk)
                self._write_root_node(dir_no, [], self._end_node(b_vcn), small=False)
        return True

    def _insert_median_inplace(self, node, median, left_vcn, right_vcn) -> None:
        '''Absorb a child's promoted median: find the pointer to the child that
           split (subnode == left_vcn), retarget it to the new right block, and
           insert the median (→left, the half that stayed) just before it.'''
        reals, end = node['reals'], node['end']
        for k, e in enumerate(reals):
            if struct.unpack_from('<H', e, 12)[0] & 1 \
                    and self._entry_subnode(e) == left_vcn:
                reals[k] = self._set_subnode(e, right_vcn)
                reals.insert(k, median)
                return
        if struct.unpack_from('<H', end, 12)[0] & 1 \
                and self._entry_subnode(end) == left_vcn:
            node['end'] = self._set_subnode(end, right_vcn)
            reals.append(median)
            return
        raise NtfsError(errno.EIO, 'cascade: parent pointer to child not found')

    def _free_index_block(self, dir_no, block_index) -> None:
        '''Clear an INDX block's $BITMAP bit (the block stays allocated in
           $INDEX_ALLOCATION — a benign leak a bitmap audit reclaims).'''
        bm = self._read_i30_bitmap(dir_no)
        bm[block_index >> 3] &= ~(1 << (block_index & 7))
        self._write_i30_bitmap(dir_no, bm)

    # -- phase 4c: bulk-load rebuild (torn-index recovery from the MFT census) --

    def _leaf_capacity(self, block_size: int) -> int:
        entries_off = ((40 + 2 * (1 + block_size // 512) + 7) & ~7) - 24
        return (block_size - 24) - entries_off  # bytes for entries incl END

    def _root_body_room(self, rec, root_attr_off: int, body_len: int) -> bool:
        vofs = struct.unpack_from('<H', rec, root_attr_off + 0x14)[0]
        cur_alen = struct.unpack_from('<I', rec, root_attr_off + 4)[0]
        in_use = struct.unpack_from('<I', rec, 0x18)[0]
        need_vlen = 16 + 16 + body_len              # prefix + INDEX_HEADER + body
        need_alen = (vofs + need_vlen + 7) & ~7
        return need_alen - cur_alen <= len(rec) - in_use

    def _write_root_node(self, dir_no, body, end, small: bool) -> None:
        rec = self._load_record(dir_no)
        if rec is None:
            raise NtfsError(errno.EIO, f'directory record {dir_no} unreadable')
        ra, _l = self._base_attr(rec, AT_INDEX_ROOT, self._ix.name)
        vofs = struct.unpack_from('<H', rec, ra + 0x14)[0]
        cur_vlen = struct.unpack_from('<I', rec, ra + 0x10)[0]
        body_bytes = b''.join(body) + end
        need_vlen = 16 + 16 + len(body_bytes)
        if need_vlen != cur_vlen:
            # keep the attribute exactly-sized either way: Windows writes
            # tight roots, and chkdsk flags slack as an index error
            self._resident_grow_root(rec, ra, ((need_vlen + 7) & ~7) - cur_vlen)
            vofs = struct.unpack_from('<H', rec, ra + 0x14)[0]
            cur_vlen = struct.unpack_from('<I', rec, ra + 0x10)[0]
        val = ra + vofs                              # INDEX_ROOT prefix (16) kept
        struct.pack_into('<III', rec, val + 16, 16, 16 + len(body_bytes), cur_vlen - 16)
        rec[val + 16 + 12] = 0 if small else 1       # INDEX_HEADER.flags
        rec[val + 16 + 13:val + 16 + 16] = b'\x00\x00\x00'
        rec[val + 32:val + 32 + len(body_bytes)] = body_bytes
        for i in range(val + 32 + len(body_bytes), val + cur_vlen):
            rec[i] = 0
        self.write_record(dir_no, rec)

    def _ensure_index_blocks(self, dir_no, block_size, vpb, nblocks) -> None:
        alloc = self._attr_value(dir_no, AT_INDEX_ALLOCATION, self._ix.name)
        have = len(alloc) // block_size
        while have < nblocks:
            self._grow_index_alloc(dir_no, block_size, vpb,
                                   self._read_i30_bitmap(dir_no), have)
            have += 1

    def _set_i30_bitmap_used(self, dir_no, nblocks) -> None:
        bm = self._read_i30_bitmap(dir_no)
        for i in range(len(bm) * 8):
            if i < nblocks:
                bm[i >> 3] |= 1 << (i & 7)
            else:
                bm[i >> 3] &= ~(1 << (i & 7))
        self._write_i30_bitmap(dir_no, bm)

    def rebuild_index(self, dir_no: int) -> dict:
        '''Rebuild a directory's $I30 from the MFT census (chkdsk stage-2 rebuild,
           native): build sorted $FILE_NAME leaf entries and bulk-load them.'''
        census = self.children_from_mft(dir_no)['children']
        items = []
        for c in census:
            e = self._ix.build_leaf(c['record'] | (c['seq'] << 48), c['fn_bytes'])
            items.append((self._ix.entry_sort_key(e), e))
        items.sort(key=lambda t: t[0])
        return self._bulk_write_index(dir_no, [e for _, e in items])

    def _bulk_write_index(self, owner: int, entries: list) -> dict:
        '''Write `entries` (already in self._ix collation order) as the index
           named self._ix.name on record `owner`: a resident root if they fit,
           else a bottom-up bulk-loaded tree — one INDX block, or several with
           the root a single END→internal pointer and separators one level down.
           Shared by the $I30 directory rebuild and the $SII/$SDH $Secure rebuild;
           schema-generic — the separator format follows self._ix.'''
        rec = self._load_record(owner)
        if rec is None:
            raise NtfsError(errno.EIO, f'record {owner} unreadable')
        loc = self._base_attr(rec, AT_INDEX_ROOT, self._ix.name)
        if not loc:
            raise NtfsError(errno.ENOENT, f'record {owner} has no index root')
        ra, _l = loc
        rvofs = ra + struct.unpack_from('<H', rec, ra + 0x14)[0]
        block_size = struct.unpack_from('<I', rec, rvofs + 8)[0]
        vpb = max(block_size // self._cluster_size, 1)
        has_ia = self._base_attr(rec, AT_INDEX_ALLOCATION, self._ix.name) is not None
        leaf_end = self._leaf_end()

        # small enough for the resident root, and no allocation to reconcile?
        if not has_ia:
            if self._root_body_room(rec, ra, len(b''.join(entries) + leaf_end)):
                self._write_root_node(owner, entries, leaf_end, small=True)
                return {'entries': len(entries), 'blocks': 0}
            # needs a large index but has none — create $INDEX_ALLOCATION +
            # $BITMAP, then fall through (the large build overwrites block 0)
            self._small_to_large(owner, block_size, vpb)
            if getattr(self, '_ia_cache', None):
                self._ia_cache.pop(owner, None)

        # large: pack leaves. Root stays a single END→child pointer; separators
        # live in an internal block one level down (keeps the resident root tiny).
        cap = self._leaf_capacity(block_size)
        leaves, cur, cur_len = [], [], 0
        for e in entries:
            if cur and cur_len + len(e) + 16 > cap:  # +16 keeps END room
                leaves.append(cur)
                cur, cur_len = [], 0
            cur.append(e)
            cur_len += len(e)
        leaves.append(cur)
        nleaves = len(leaves)

        if nleaves == 1:  # one leaf block; root → it
            self._ensure_index_blocks(owner, block_size, vpb, 1)
            blk = self._new_indx_block(0, block_size)
            self._pack_node(blk, 24, leaves[0], leaf_end)
            self._write_block(owner, 0, block_size, blk)
            self._set_i30_bitmap_used(owner, 1)
            self._write_root_node(owner, [], self._end_node(0), small=False)
            return {'entries': len(entries), 'blocks': 1}

        # build the tree bottom-up to arbitrary depth (root stays a single
        # END→child pointer; leaves are blocks 0..nleaves-1, internal levels
        # take the blocks above them).
        leaf_nodes = [{'vcn': i * vpb, 'entries': list(leaves[i]), 'end_vcn': None}
                      for i in range(nleaves)]
        planned = []                                  # (block_index, body, end)
        top_vcn, total = self._build_tree(leaf_nodes, block_size, vpb,
                                          nleaves, planned)
        self._ensure_index_blocks(owner, block_size, vpb, total)
        for bi, body, end in planned:
            blk = self._new_indx_block(bi * vpb, block_size)
            if not self._pack_node(blk, 24, body, end):
                raise NtfsError(errno.EIO, f'node {bi} body overflow (unexpected)')
            self._write_block(owner, bi, block_size, blk)
        self._set_i30_bitmap_used(owner, total)
        self._write_root_node(owner, [], self._end_node(top_vcn), small=False)
        return {'entries': len(entries), 'blocks': total}

    def _build_tree(self, nodes, block_size, vpb, next_bi, planned):
        '''Bottom-up bulk load. `nodes` is an ordered list of
           {vcn, entries, end_vcn} (end_vcn None marks a leaf). Records each
           node into `planned` and returns (top_vcn, total_block_count). The
           parent level is built by promoting the first entry of every non-first
           sibling as a separator (the standard NTFS B+ convention), recursing
           until one node remains.'''
        if len(nodes) == 1:
            n = nodes[0]
            end = self._leaf_end() if n['end_vcn'] is None else self._end_node(n['end_vcn'])
            planned.append((n['vcn'] // vpb, n['entries'], end))
            return n['vcn'], next_bi

        seps = []                                     # (first_entry, left_child_vcn)
        for i in range(1, len(nodes)):
            seps.append((nodes[i]['entries'].pop(0), nodes[i - 1]['vcn']))
        final_child = nodes[-1]['vcn']
        for n in nodes:                               # this level is now final
            end = self._leaf_end() if n['end_vcn'] is None else self._end_node(n['end_vcn'])
            planned.append((n['vcn'] // vpb, n['entries'], end))

        cap = self._leaf_capacity(block_size) - 24    # reserve the node END entry
        groups, cur, cur_len = [], [], 0
        for e, child in seps:
            ne = self._make_node_entry(e, child)
            if cur and cur_len + len(ne) > cap:
                groups.append(cur)
                cur, cur_len = [], 0
            cur.append((ne, child))
            cur_len += len(ne)
        groups.append(cur)

        parents, bi = [], next_bi
        for j, group in enumerate(groups):
            end_vcn = final_child if j == len(groups) - 1 else groups[j + 1][0][1]
            parents.append({'vcn': bi * vpb, 'end_vcn': end_vcn,
                            'entries': [ne for ne, _c in group]})
            bi += 1
        return self._build_tree(parents, block_size, vpb, bi, planned)

    def rebuild_dir(self, path: str) -> dict:
        '''Adapter so full_fix's rebuild step works on the native engine —
           returns the {added, duplicates, planned} shape full_fix expects.'''
        r = self.rebuild_index(self._resolve(path))
        return {'added': r['entries'], 'duplicates': 0, 'planned': r['entries']}

    def reconnect_lost(self, lost: dict) -> int:
        '''Lost-file reconnection: re-add each $FILE_NAME leaf entry into
           the live parent's index.'''
        self._invalidate_mft_cache()
        mref = lost['record'] | (lost['seq'] << 48)
        added = 0
        for fn in lost['fn_list']:
            try:
                self.insert_index_entry(lost['parent'], mref, fn)
                added += 1
            except NtfsError as exc:
                if exc.errno != errno.EEXIST:
                    raise
        return added

    # -- $LogFile reset (the ntfsfix/chkdsk approach — a reset, NOT a replay) --

    def reset_logfile(self) -> int:
        '''Empty $LogFile by filling it with 0xff, so the driver and Windows
           treat the journal as clean and replay nothing. This DISCARDS any
           pending crash-journal transactions — it is not a replay of them;
           the structural checks reconcile the on-disk state instead, exactly
           as chkdsk does (which also resets, not replays, the log).'''
        size, runs = self._stream_runs(FILE_LOGFILE, AT_DATA, None)
        if not runs:
            raise NtfsError(errno.ENOENT, '$LogFile has no non-resident $DATA')
        chunk = b'\xff' * (1 << 20)
        off = 0
        while off < size:
            self._runs_write(runs, off, chunk[:min(len(chunk), size - off)])
            off += len(chunk)
        return size

    def clear_dirty(self) -> None:
        '''Clear the volume dirty flag — only valid after checks pass clean.'''
        self._was_dirty = False  # so close() does not re-clear or preserve
        self._set_dirty(False)


    # -- phase 5: purge composition (unlink + free record + free clusters) --

    def _extension_records(self, rec_no: int) -> set:
        '''Extension record numbers a base record's $ATTRIBUTE_LIST references
           (empty if the file lives in a single record) '''
           
        rec = self._load_record(rec_no)
        if rec is None:
            return set()
        frozen = bytes(rec)
        exts, nc = set(), self.nr_clusters()
        for a, t, ln in _attrs(frozen):
            if t != AT_ATTRIBUTE_LIST:
                continue
            if frozen[a + 8] == 0:
                vo = struct.unpack_from('<H', frozen, a + 20)[0]
                vl = struct.unpack_from('<I', frozen, a + 16)[0]
                listing = frozen[a + vo:a + vo + vl]
            else:
                _p, _ph, r = _check_mapping_pairs(frozen, a, ln, nc)
                size = struct.unpack_from('<q', frozen, a + 48)[0]
                listing = self._runs_read(r, 0, size)
            pos = 0
            while pos + 26 <= len(listing):
                e_len = struct.unpack_from('<H', listing, pos + 4)[0]
                if e_len < 26:
                    break
                mref = struct.unpack_from('<Q', listing, pos + 16)[0] & MREF_MASK
                if mref != rec_no:
                    exts.add(mref)
                pos += e_len
        return exts


    def _record_alloc_runs(self, rec_no: int):
        '''(lcn, run_len) clusters owned by every non-resident attribute of the
           file — spanning extension records when an $ATTRIBUTE_LIST is present
           (_record_attrs follows the list) '''

        runs, nc = [], self.nr_clusters()
        for frozen, a, length in self._record_attrs(rec_no):
            if frozen[a + 8] == 1:  # non-resident
                _p, _ph, r = _check_mapping_pairs(frozen, a, length, nc)
                runs += [(lcn, rlen) for lcn, rlen, _v in r]
        return runs


    def _free_file_record(self, rec_no: int) -> None:
        '''Clear MFT_RECORD_IN_USE, bump the sequence (so stale refs detect as
           stale), and clear the $MFT bitmap bit '''

        rec = self._load_record(rec_no)
        if rec is None:
            raise NtfsError(errno.EIO, f'record {rec_no} unreadable')
        flags = struct.unpack_from('<H', rec, 22)[0]
        struct.pack_into('<H', rec, 22, flags & ~1)
        seq = struct.unpack_from('<H', rec, 16)[0]
        struct.pack_into('<H', rec, 16, (seq + 1) & 0xFFFF or 1)
        self.write_record(rec_no, rec)
        self.free_record(rec_no)


    def purge_orphan(self, path: str, name: str, really: bool) -> dict:
        ''' Reclaim a true orphan natively. crash-safe order : unlink, clear the 
            record's in-use flag, free clusters, so no live record ever references
            freed space '''

        verdict = self.classify_dirent(path, name)
        if verdict['state'] != 'orphan':
            raise SystemExit(f'refusing purge: entry is {verdict["state"]!r} '
                             f'— {verdict["action"]}')
        if not really:
            return verdict
        dir_no = self._resolve(path)
        rec_no = verdict['dirent_record']
        runs = self._record_alloc_runs(rec_no)     # all clusters (base + extensions)
        exts = self._extension_records(rec_no)     # extension records to free too
        # crash-safe order: unlink, free every record (in-use cleared) so no
        # live record references the clusters, then free the clusters
        self.remove_index_entry(dir_no, name)
        self._free_file_record(rec_no)
        for ext in sorted(exts):
            self._free_file_record(ext)
        if runs:
            self.free_clusters(runs)
        verdict['purged'] = True
        return verdict

    # -- op 1: the torn-truncate terminator (native) --

    def terminate_mapping_pairs(self, rec_no: int, mp_off: int) -> None:
        '''Zero the first mapping-pairs byte of a phantom-runs empty attribute.
           Whole-record sealed write, so fixup slots are no constraint — the
           sealer regenerates them.'''
        rec = self._load_record(rec_no)
        if rec is None:
            raise NtfsError(errno.EIO, f'record {rec_no} unreadable')
        if rec[mp_off] == 0:
            return  # already terminated
        rec[mp_off] = 0
        self.write_record(rec_no, rec)


def open_volume(device: str, readonly: bool = True):
    '''Open the volume: reads use RawVolume, writes use RawVolumeRW.'''
    return RawVolume(device) if readonly else RawVolumeRW(device)


# ── full-volume pass: the chkdsk /f flow (the parts this tool can do) ────────

def run_surface(device: str, vol: RawVolume, direct: bool = False) -> dict:
    '''chkdsk /r stage 4, report-only: read every cluster of the volume
       (sequential 64 MiB chunks, bisecting failures down to clusters), then
       attribute unreadable clusters to their owning files.

       direct=True opens with O_DIRECT (page-aligned mmap buffer + preadv) so
       a 500 GB scan does not evict the machine's page cache; falls back to
       buffered reads + posix_fadvise(DONTNEED) where O_DIRECT is refused.'''

    end = vol.nr_clusters() * vol.cluster_size()
    fd = None
    if direct and hasattr(os, 'O_DIRECT'):
        try:
            fd = os.open(device, os.O_RDONLY | os.O_DIRECT | _O_BINARY)
        except OSError:
            print('  (O_DIRECT refused here — using buffered reads + fadvise)')
    if fd is None:
        direct = False
        fd = os.open(device, os.O_RDONLY | _O_BINARY)
    last = [0]

    def progress(pos: int, total: int) -> None:
        if pos - last[0] >= (32 << 30):
            print(f'  ... {pos >> 30} / {total >> 30} GiB read')
            last[0] = pos

    if direct:
        import mmap
        dbuf = mmap.mmap(-1, 64 << 20)  # page-aligned, as O_DIRECT requires

        def pread(pos: int, count: int) -> bytes:
            got = os.preadv(fd, [memoryview(dbuf)[:count]], pos)
            return dbuf[:got]
    else:
        def pread(pos: int, count: int) -> bytes:
            data = _pread(fd, count, pos)
            if hasattr(os, 'posix_fadvise'):  # don't evict the page cache
                os.posix_fadvise(fd, pos, count, os.POSIX_FADV_DONTNEED)
            return data

    try:
        bad = _surface_scan(pread, end, vol.cluster_size(), progress)
    finally:
        os.close(fd)
    return {'bad': bad, 'bytes': end,
            'owners': vol.surface_owners(set(bad)) if bad else []}


def _print_surface(scan: dict, indent: str = '') -> None:
    print(f'{indent}{scan["bytes"] >> 20} MiB read, '
          f'{len(scan["bad"])} unreadable cluster(s)')
    for own in scan['owners'][:10]:
        heads = ', '.join(str(c) for c in own['clusters'][:6])
        more = '...' if len(own['clusters']) > 6 else ''
        if own['record'] is None:
            print(f'{indent}! {len(own["clusters"])} bad cluster(s) in free space '
                  f'({heads}{more})')
        else:
            print(f'{indent}! record {own["record"]} attr {own["attr"]:#x} '
                  f'({own["names"]}): bad cluster(s) {heads}{more}')
    if scan['bad']:
        print(f'{indent}report-only: reallocate via a real chkdsk /r, or restore '
              'the affected files from backup')


def full_fix(device: str, really: bool, surface: bool = False,
             direct: bool = False) -> int:
    '''The chkdsk /f flow, the parts this tool implements. Stage 1 verifies
       every MFT record and attribute runlist (auto-repairing torn empty-
       attribute truncates); stage 2 walks every directory index, repairing
       dangling entries and rebuilding torn indexes; stage 3 validates and
       repairs $Secure; stage 5 reconciles $Bitmap accounting; the USN journal
       is validated and reset. Stage 4 (surface scan) is report-only.'''

    extra_issues = extra_fixed = extra_failed = 0
    with open_volume(device, readonly=not really) as vol:
        print('stage 1: examining MFT records and attribute runlists ...')
        survey = vol.mft_survey(want_used=True, want_security=True)
        health = survey
        print(f'  {health["total"]} records, {health["in_use"]} in use '
              f'({health["dirs"]} directories), {health["torn"]} torn, '
              f'{len(health["runlist_problems"])} runlist problem(s)')
        for prob in health['runlist_problems']:
            extra_issues += 1
            print(f'! record {prob["record"]} attr {prob["attr_type"]:#x} '
                  f'({prob["names"]}): {prob["problem"]}')
            if prob['fix_mp_off'] is None:
                print('    no safe auto-repair — chkdsk territory')
                if really:
                    extra_failed += 1
                continue
            if not really:
                print('    (safe auto-repair available: terminate the phantom runlist)')
                continue
            try:
                vol.terminate_mapping_pairs(prob['record'], prob['fix_mp_off'])
                extra_fixed += 1
                print('    fixed (runlist terminated; any leaked clusters are '
                      'reclaimed in stage 5)')
            except NtfsError as exc:
                extra_failed += 1
                print(f'    FIX FAILED: {exc}')

        # $MFT's own $BITMAP (bit i = record i allocated): a crash between the
        # bitmap write and the record write leaks set bits — chkdsk's "the
        # master file table's (MFT) BITMAP attribute is incorrect". Reconcile
        # against the records' surveyed in-use flags, the on-disk truth.
        print('mft record bitmap: verifying ...')
        mft_bmp = bytes(vol._read_whole_attr(0, AT_BITMAP, None, None) or b'')
        rec_used = survey['rec_used']
        nbits = min(survey['n_slots'], len(mft_bmp) * 8)
        mft_mism = [i for i in range(nbits)
                    if bool(rec_used[i >> 3] & (1 << (i & 7)))
                    != bool(mft_bmp[i >> 3] & (1 << (i & 7)))]
        if len(mft_bmp) * 8 < survey['n_slots']:
            extra_issues += 1
            print(f'!   $BITMAP covers {len(mft_bmp) * 8} of '
                  f'{survey["n_slots"]} record slots — truncated (report-only)')
            if really:
                extra_failed += 1
        if mft_mism:
            extra_issues += 1
            print(f'!   {len(mft_mism)} record(s) disagree with the bitmap '
                  f'(first: {mft_mism[:8]})')
            if not really:
                print('    (repairable: --really rewrites the bitmap from the '
                      'surveyed in-use flags)')
            else:
                n = vol.apply_mft_bitmap(rec_used, nbits)
                again = bytes(vol._read_whole_attr(0, AT_BITMAP, None, None)
                              or b'')
                left = [i for i in range(nbits)
                        if bool(rec_used[i >> 3] & (1 << (i & 7)))
                        != bool(again[i >> 3] & (1 << (i & 7)))]
                if left:
                    extra_failed += 1
                    print('    REWRITE VERIFY FAILED')
                else:
                    extra_fixed += 1
                    print(f'    bitmap rewritten ({n} bit(s) corrected)')
        else:
            print('  consistent')

        print('stage 2: examining directory indexes ...')
        walked = dangling = torn = fixed = failed = 0
        stack, seen = [('/', FILE_ROOT)], {FILE_ROOT}
        referenced: set[int] = set()
        while stack:
            path, dir_no = stack.pop()
            walked += 1
            if walked % 2000 == 0:
                print(f'  ... {walked} directories walked, {len(stack)} queued')

            probe = vol.probe_dir_no(dir_no)
            if not probe['readable']:
                torn += 1
                print(f'! torn index: {path!r} — {probe["error"]}')
                if not really:
                    print('    (children not walked; --really will rebuild this index)')
                    continue
                try:
                    result = vol.rebuild_dir(path)
                    print(f'    rebuilt: {result["added"]} entries re-added')
                except (SystemExit, NtfsError) as exc:
                    failed += 1
                    print(f'    REBUILD FAILED: {exc}')
                    continue
                probe = vol.probe_dir_no(dir_no)
                if not probe['readable']:
                    failed += 1
                    print(f'    VERIFY FAILED: still unreadable — {probe["error"]}')
                    continue
                fixed += 1

            for entry in probe['entries']:
                full = (path.rstrip('/')) + '/' + entry['name']
                if entry['status'] == 'ok':
                    referenced.add(entry['record'])
                    if entry.get('is_dir') and entry['record'] not in seen:
                        seen.add(entry['record'])
                        stack.append((full, entry['record']))
                    continue
                dangling += 1
                try:
                    verdict = vol.classify_dirent(path, entry['name'])
                except NtfsError as exc:
                    if really and exc.errno == errno.ENOENT:
                        # A purge of a sibling name (WIN32/DOS twin) of the same
                        # file already removed this entry along with it.
                        print(f'! {full!r}: entry already removed with its twin name')
                        fixed += 1
                    else:
                        failed += 1
                        print(f'! {full!r}: triage failed: {exc}')
                    continue
                print(f'! {full!r}: {verdict["state"]} -> {verdict["action"]}')
                if not really or verdict['state'] == 'healthy':
                    continue
                try:
                    if verdict['state'] == 'orphan':
                        vol.purge_orphan(path, entry['name'], really=True)
                    else:
                        vol.remove_dirent(path, entry['name'], really=True)
                    fixed += 1
                    print('    fixed')
                except (SystemExit, NtfsError) as exc:
                    failed += 1
                    print(f'    FIX FAILED: {exc}')

        print('lost files: records no index entry references ...')
        lost = vol.find_lost_files(referenced)
        print(f'  {len(lost)} lost file(s)')
        for lf in lost:
            extra_issues += 1
            where = (f"live parent {lf['parent']}" if lf['parent_ok']
                     else f"parent {lf['parent']} is dead/reused — not reconnectable")
            print(f"! lost file {lf['name']!r} (record {lf['record']}): {where}")
            if not lf['parent_ok']:
                if really:
                    extra_failed += 1
                    print('    chkdsk territory (found.000-style recovery not implemented)')
                continue
            if not really:
                print('    (repairable: --really re-adds it to its parent directory)')
                continue
            try:
                added = vol.reconnect_lost(lf)
                if added:
                    extra_fixed += 1
                    print(f'    reconnected ({added} index entr'
                          f'{"y" if added == 1 else "ies"} re-added)')
                else:
                    extra_failed += 1
                    print('    NOT reconnected: name already taken in the parent')
            except NtfsError as exc:
                extra_failed += 1
                print(f'    RECONNECT FAILED: {exc}')

        print('stage 3: verifying security descriptors ($Secure) ...')
        sec = vol.secure_check(survey=survey)
        for note in sec['notes']:
            print(f'  note: {note}')
        if sec['present']:
            print(f'  {sec["descriptors"]} descriptors, {sec["files_checked"]} files '
                  f'checked: {len(sec["mirror_fixes"])} mirror mismatch(es), '
                  f'{len(sec["index_problems"])} index problem(s), '
                  f'{len(sec["problems"])} unrepairable, '
                  f'{len(sec["ref_missing"])} dangling reference(s)')
            for prob in (sec['problems'] + sec['index_problems']
                         + sec['ref_missing'])[:10]:
                print(f'!   {prob}')
            sec_issues = (bool(sec['mirror_fixes']) + bool(sec['index_problems'])
                          + bool(sec['problems']) + bool(sec['ref_missing']))
            extra_issues += sec_issues
            if sec_issues and really:
                if sec['mirror_fixes']:
                    try:
                        n = vol.secure_fix_mirrors(sec['mirror_fixes'])
                        extra_fixed += 1
                        print(f'    {n} $SDS mirror pair(s) repaired from the good copy')
                    except NtfsError as exc:
                        extra_failed += 1
                        print(f'    MIRROR FIX FAILED: {exc}')
                if sec['index_problems']:
                    try:
                        result = vol.rebuild_secure_indexes(sec['sds_entries'])
                        again = vol.secure_check()
                        if again['index_problems']:
                            extra_failed += 1
                            print('    REBUILD VERIFY FAILED: '
                                  + again['index_problems'][0])
                        else:
                            extra_fixed += 1
                            print(f'    $SII/$SDH rebuilt from $SDS '
                                  f'({result["added"]} descriptors)')
                    except NtfsError as exc:
                        extra_failed += 1
                        print(f'    REBUILD FAILED: {exc}')
                if sec['problems'] or sec['ref_missing']:
                    extra_failed += bool(sec['problems']) + bool(sec['ref_missing'])
                    print('    unrepairable descriptor damage / dangling references — '
                          'chkdsk territory')
            elif sec_issues:
                print('    (repairable with --really: mirror fixes + $SII/$SDH rebuild; '
                      'dangling references are report-only)')

        if surface:
            print('stage 4: surface scan — reading every cluster ...')
            scan = run_surface(device, vol, direct)
            _print_surface(scan, indent='  ')
            if scan['bad']:
                extra_issues += 1
                if really:
                    extra_failed += 1  # report-only: never repaired here

        print('stage 5: verifying $Bitmap cluster accounting ...')
        # the shared survey's used-map is stale the moment any repair writes
        # (purge frees clusters, rebuild allocates INDX blocks) — recompute
        if really and (fixed + extra_fixed):
            audit = vol.cluster_audit()
        else:
            audit = vol.cluster_audit(survey=survey)
        for failure in audit['failures']:
            print(f'! {failure}')
        print(f'  {audit["used_count"]} clusters referenced, '
              f'{audit["bitmap_count"]} marked in $Bitmap: '
              f'{audit["extra"]} leaked bit(s), {audit["missing"]} missing bit(s)')
        if audit['missing']:
            print('  WARNING: missing bits = live data on clusters marked free — '
                  'writes to this volume are unsafe until repaired')
        if audit['extra'] or audit['missing']:
            extra_issues += 1
            if not really:
                print('    (repairable: --really rewrites $Bitmap with the computed map)')
            elif audit['failures']:
                extra_failed += 1
                print('    NOT rewriting $Bitmap — the computed map is incomplete '
                      '(see failures above)')
            else:
                vol.apply_bitmap(audit)
                ondisk = vol._read_whole_attr(FILE_BITMAP, AT_DATA)
                n = len(audit['used_bytes'])
                mask = (1 << audit['nr_clusters']) - 1
                if (int.from_bytes(ondisk[:n], 'little') & mask
                        == int.from_bytes(audit['used_bytes'], 'little') & mask):
                    extra_fixed += 1
                    print('    $Bitmap rewritten and verified')
                else:
                    extra_failed += 1
                    print('    VERIFY FAILED: $Bitmap readback does not match')

        print('usn journal: verifying ...')
        usn = vol.usn_check()
        if not usn['present']:
            print('  none (journal disabled) — nothing to check')
        else:
            print(f'  id {usn["journal_id"] or 0:#x}, valid range '
                  f'[{usn["lowest"]}, {usn["next_usn"]}), {usn["records"]} records, '
                  f'{len(usn["problems"])} problem(s)')
            for note in usn['notes']:
                print(f'  note: {note}')
            for prob in usn['problems']:
                print(f'!   {prob}')
            if usn['problems']:
                extra_issues += 1
                if not really:
                    print('    (repairable: --really resets the journal; '
                          'indexers/backup tools rescan)')
                else:
                    try:
                        vol.usn_reset()
                        again = vol.usn_check()
                        if again['problems'] or again['next_usn'] != 0:
                            extra_failed += 1
                            print('    RESET VERIFY FAILED')
                        else:
                            extra_fixed += 1
                            print('    journal reset (new id; consumers will rescan)')
                    except NtfsError as exc:
                        extra_failed += 1
                        print(f'    RESET FAILED: {exc}')

        print('view indexes: $Reparse / $ObjId ...')
        vw = vol.view_index_check(survey)
        for note in vw['notes']:
            print(f'  note: {note}')
        print(f'  {vw["checked"]} entr{"y" if vw["checked"] == 1 else "ies"} checked, '
              f'{len(vw["problems"])} problem(s)')
        for prob in vw['problems'][:10]:
            print(f'!   {prob}')
        if vw['problems']:
            extra_issues += 1
            if really:
                extra_failed += 1
                print('    report-only (rebuild-from-records is a future repair)')

        # -- crashed-session residue: the dirty flag + stale $LogFile --
        # chkdsk /f ends by resetting the log and clearing the dirty bit; a
        # volume left flagged is re-checked by Windows at boot and refused
        # outright by Linux ntfs3. Safe only once every finding above was
        # repaired — anything unresolved keeps the flag (and the recheck).
        # In --really mode the flag reads set because RawVolumeRW itself sets
        # it on open, so the pre-existing state is _was_dirty.
        print('dirty flag / $LogFile: ...')
        if (vol._was_dirty if really else vol._dirty_flag()):
            extra_issues += 1
            print('!   volume is marked dirty (crashed session; $LogFile not clean)')
            unresolved = (dangling + torn + extra_issues - 1) - (fixed + extra_fixed)
            if not really:
                print('    (repairable: --really resets $LogFile and clears the '
                      'flag once every finding above is repaired)')
            elif unresolved:
                extra_failed += 1
                print(f'    left dirty: {unresolved} finding(s) unresolved — '
                      'the next mount should still trigger a full check')
            else:
                vol.reset_logfile()
                vol.clear_dirty()
                if vol._dirty_flag():
                    extra_failed += 1
                    print('    CLEAR VERIFY FAILED')
                else:
                    extra_fixed += 1
                    print('    $LogFile reset (0xff) + dirty flag cleared — '
                          'the volume mounts clean')
        else:
            print('  clean')

    issues = dangling + torn + extra_issues
    fixed += extra_fixed
    print(f'-- {walked} directories walked: {dangling} dangling '
          f'entr{"y" if dangling == 1 else "ies"}, {torn} torn '
          f'ind{"ex" if torn == 1 else "exes"}'
          + (f', {extra_issues} record/bitmap issue(s)' if extra_issues else '')
          + (f'; {fixed} fixed, {issues - fixed} remaining' if really else ''))
    if health['torn']:
        print(f'note: {health["torn"]} MFT records are torn — their files are '
              'beyond index repair (chkdsk / restore from backup)')
    covered = ('records, runlists, indexes, security descriptors, $Bitmap and '
               'the USN journal are checked')
    print(f'note: {covered}'
          + ('; the surface scan ran report-only' if surface
             else '; add --surface (or use /r) for the stage-4 read of every cluster'))
    if issues and not really:
        print('DRY RUN: re-run with --really to repair the findings listed above')
    return 1 if (issues if not really else issues - fixed) else 0


# ── targeted pre-repair backup ───────────────────────────────────────────────

def do_backup(device: str, outdir: str, dirs: list[str]) -> int:
    '''Dump the boot sectors, the full raw $MFT, $MFTMirr, and each given
       directory's raw $I30 $INDEX_ALLOCATION — everything the repair commands
       can touch, restorable by hand. Metadata only; no file data.'''

    os.makedirs(outdir, exist_ok=True)
    with open(device, 'rb') as dev, open(f'{outdir}/boot-16k.bin', 'wb') as fh:
        fh.write(dev.read(16384))
    print('boot      : 16384 bytes')

    with open_volume(device) as vol:
        rec_size = vol.mft_record_size()
        with open(f'{outdir}/mft.bin', 'wb') as fh:
            offset = 0
            while True:
                chunk = vol._mft_bulk(offset, 1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
                offset += len(chunk)
        print(f'$MFT      : {offset} bytes ({offset // rec_size} records)')

        mirror = vol._read_whole_attr(1, AT_DATA)  # $MFTMirr
        with open(f'{outdir}/mftmirr.bin', 'wb') as fh:
            fh.write(mirror)
        print(f'$MFTMirr  : {len(mirror)} bytes')

        for path in dirs:
            mft_no = vol.resolve(path)
            total = -1
            try:
                blob = vol._read_whole_attr(mft_no, AT_INDEX_ALLOCATION, INDEX_I30, 4)
                with open(f'{outdir}/dir-{mft_no}-indx.bin', 'wb') as fh:
                    fh.write(blob)
                total = len(blob)
            except NtfsError:
                pass  # resident index only
            with open(f'{outdir}/dir-{mft_no}-path.txt', 'w') as fh:
                fh.write(path + '\n')
            state = '(resident index only)' if total < 0 else f'INDX {total} bytes'
            print(f'dir-{mft_no:<8}: {state}  {path}')

    total = 0
    with os.scandir(outdir) as it:
        entries = sorted((e for e in it if e.is_file() and e.name != 'SHA256SUMS'),
                         key=lambda e: e.name)
    with open(f'{outdir}/SHA256SUMS', 'w') as sums:
        for entry in entries:
            digest = hashlib.sha256(open(entry.path, 'rb').read()).hexdigest()
            sums.write(f'{digest}  {entry.name}\n')
            total += entry.stat().st_size  # cached by scandir — no extra stat()
    print(f'backup complete: {total / 1e6:.0f} MB in {outdir}')
    return 0


# ── partition discovery: `list` (raw table scan, nothing is mounted) ─────────

def _human(n: int) -> str:
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return f'{n:.1f} {unit}' if unit != 'B' else f'{n} B'
        n /= 1024


def _parse_partitions(fd) -> list[dict]:
    '''Parse the device's partitioning from raw sector reads: a bare NTFS
       volume (no table), an MBR (incl. the EBR chain of logical partitions),
       or a GPT behind its protective MBR. Returns [{index, offset, length,
       kind, name}]; nothing is mounted and nothing is written.'''
    sec0 = _pread(fd, 512, 0)
    if len(sec0) < 512:
        return []
    if sec0[3:7] == b'NTFS':                       # bare volume, no table
        bps = struct.unpack_from('<H', sec0, 11)[0] or 512
        sectors = struct.unpack_from('<Q', sec0, 40)[0]
        return [{'index': 0, 'offset': 0, 'length': (sectors + 1) * bps,
                 'kind': 'bare', 'name': ''}]
    if sec0[510:512] != b'\x55\xaa':
        return []
    # entry: boot flag, CHS start (3), type, CHS end (3), start LBA, sectors
    entries = [(sec0[0x1BE + 16 * i + 4],
                *struct.unpack_from('<II', sec0, 0x1BE + 16 * i + 8))
               for i in range(4)]                  # (type, start_lba, sectors)
    if any(t == 0xEE for t, _s, _n in entries):    # protective MBR → GPT
        hdr = _pread(fd, 512, 512)
        if hdr[:8] != b'EFI PART':
            return []
        arr_lba = struct.unpack_from('<Q', hdr, 72)[0]
        num, esize = struct.unpack_from('<II', hdr, 80)
        # clamp what a CORRUPT header can make us read: the spec minimum is
        # 128 entries of 128 bytes; nothing sane exceeds 512 entries
        if not 0 < esize <= 4096:
            return []
        num = min(num, 512)
        blob = _pread(fd, -(-num * esize // 512) * 512, arr_lba * 512)
        out = []
        for i in range(num):
            e = blob[i * esize:(i + 1) * esize]
            if len(e) < 128 or e[:16] == b'\x00' * 16:
                continue
            start, end = struct.unpack_from('<QQ', e, 32)
            name = e[56:128].decode('utf-16-le', 'replace').rstrip('\x00')
            out.append({'index': i + 1, 'offset': start * 512,
                        'length': (end - start + 1) * 512,
                        'kind': 'gpt', 'name': name})
        return out
    out = []
    for i, (ptype, start, sectors) in enumerate(entries):
        if not ptype:
            continue
        if ptype in (0x05, 0x0F, 0x85):            # extended → walk the EBRs
            link, idx = 0, 5
            seen = set()                           # corrupt chains can cycle
            while link not in seen and len(seen) < 128:
                seen.add(link)
                ebr = _pread(fd, 512, (start + link) * 512)
                if len(ebr) < 512 or ebr[510:512] != b'\x55\xaa':
                    break
                t0 = ebr[0x1BE + 4]
                s0, n0 = struct.unpack_from('<II', ebr, 0x1BE + 8)
                if t0:
                    out.append({'index': idx,
                                'offset': (start + link + s0) * 512,
                                'length': n0 * 512, 'kind': 'mbr',
                                'name': f'type {t0:#04x}'})
                    idx += 1
                t1 = ebr[0x1BE + 16 + 4]
                s1 = struct.unpack_from('<I', ebr, 0x1BE + 16 + 8)[0]
                if not t1:
                    break
                link = s1                          # next EBR, extended-relative
            continue
        out.append({'index': i + 1, 'offset': start * 512,
                    'length': sectors * 512, 'kind': 'mbr',
                    'name': f'type {ptype:#04x}'})
    return out


def _candidate_devices() -> list[str]:
    '''Whole-disk device nodes to scan when none were given. Read-only probes;
       missing/unopenable candidates are simply skipped.'''
    if sys.platform.startswith('linux'):
        try:
            return ['/dev/' + n for n in sorted(os.listdir('/sys/block'))
                    if not n.startswith(('ram', 'zram'))]
        except OSError:
            return []
    if sys.platform == 'win32':
        return ['\\\\.\\PhysicalDrive' + str(i) for i in range(16)]
    if sys.platform == 'darwin':
        import re
        return ['/dev/' + n for n in sorted(os.listdir('/dev'))
                if re.fullmatch(r'disk\d+', n)]
    import re                                       # the BSDs
    return ['/dev/' + n for n in sorted(os.listdir('/dev'))
            if re.fullmatch(r'(ada|da|vtbd|nvd|nda)\d+', n)]


def list_volumes(devices: list[str] | None) -> int:
    '''`list`: find NTFS partitions by reading partition tables + boot sectors
       straight off the devices — nothing needs to be (or gets) mounted. With
       no arguments, scans the platform's whole-disk devices; arguments may be
       device nodes or image files.'''
    explicit = devices is not None
    found = 0
    for dev in (devices if explicit else _candidate_devices()):
        try:
            fd = os.open(dev, os.O_RDONLY | _O_BINARY)
        except FileNotFoundError:
            if explicit:
                print(f'{dev}: not found')
            continue
        except (PermissionError, OSError) as exc:
            print(f'{dev}: cannot open read-only ({exc.strerror or exc}) — '
                  'root/admin is needed for raw device reads')
            continue
        try:
            parts = _parse_partitions(fd)
        finally:
            os.close(fd)
        if not parts:
            if explicit:
                print(f'{dev}: no NTFS boot sector and no partition table')
            continue
        for p in parts:
            try:
                boot = None
                fd = os.open(dev, os.O_RDONLY | _O_BINARY)
                try:
                    boot = _pread(fd, 512, p['offset'])
                finally:
                    os.close(fd)
            except OSError:
                continue
            if boot[3:7] != b'NTFS':
                continue
            found += 1
            state = 'unreadable'
            label = ''
            try:
                # the engine's own open-time dirty warning (stderr) is
                # redundant here — the row already says DIRTY
                import contextlib, io
                with contextlib.redirect_stderr(io.StringIO()):
                    with RawVolume(dev, base=p['offset']) as v:
                        label = v.volume_label()
                        dirty = v._dirty_flag()
                state = ('DIRTY — a crashed session; /f repairs'
                         if dirty else 'clean')
            except (NtfsError, OSError) as exc:
                state = f'DAMAGED ({exc}) — a repair candidate'
            where = ('' if p['kind'] == 'bare'
                     else f'  partition {p["index"]} @ {p["offset"]:#x}')
            name = f' [{p["name"]}]' if p['name'] and p['kind'] == 'gpt' else ''
            print(f'{dev}{where}  ntfs  '
                  + (f'{label!r}  ' if label else '')
                  + f'{_human(p["length"])}{name}  {state}')
    if not found:
        print('no NTFS volumes found' + ('' if explicit else
              ' (no read access to any disk? try with root/admin)'))
    else:
        print(f'-- {found} NTFS volume(s); this listing mounted nothing and '
              'wrote nothing')
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_scan = sub.add_parser('scan', help='read-only: list a directory and health-check every entry')
    p_scan.add_argument('device')
    p_scan.add_argument('dir')

    p_rm = sub.add_parser('rm', help='remove ONE dangling index entry (dry-run unless --really)')
    p_rm.add_argument('device')
    p_rm.add_argument('dir')
    p_rm.add_argument('name')
    p_rm.add_argument('--really', action='store_true', help='actually write; default is dry-run')

    p_inspect = sub.add_parser('inspect', help='read-only triage: free record, reused record, or true orphan?')
    p_inspect.add_argument('device')
    p_inspect.add_argument('dir')
    p_inspect.add_argument('name')

    p_purge = sub.add_parser('purge', help='fully reclaim a TRUE ORPHAN: dirent + record + clusters (dry-run unless --really)')
    p_purge.add_argument('device')
    p_purge.add_argument('dir')
    p_purge.add_argument('name')
    p_purge.add_argument('--really', action='store_true', help='actually write; default is dry-run')

    p_rebuild = sub.add_parser('rebuild', help='rebuild a TORN directory index from the MFT (dry-run unless --really)')
    p_rebuild.add_argument('device')
    p_rebuild.add_argument('dir')
    p_rebuild.add_argument('--really', action='store_true', help='actually write; default is dry-run')
    p_rebuild.add_argument('--force', action='store_true', help='rebuild even if the index currently reads fine')

    p_fix = sub.add_parser('fix', aliases=['/f', '/F', '/r', '/R'],
                           help='chkdsk /f flow: verify MFT records + runlists, walk '
                                'EVERY directory index, validate $Secure, reconcile '
                                '$Bitmap, check the USN journal (dry-run unless '
                                '--really); /r or --surface adds the stage-4 read '
                                'of every cluster')
    p_fix.add_argument('device')
    p_fix.add_argument('--really', action='store_true', help='actually write; default is dry-run')
    p_fix.add_argument('--surface', action='store_true',
                       help='also read every cluster (chkdsk /r style, report-only)')
    p_fix.add_argument('--direct', action='store_true',
                       help='surface scan with O_DIRECT (do not pollute the page cache)')

    p_surface = sub.add_parser('surface', help='stage 4 only: read every cluster and '
                                               'attribute unreadable ones to their files '
                                               '(always report-only)')
    p_surface.add_argument('device')
    p_surface.add_argument('--direct', action='store_true',
                           help='read with O_DIRECT (do not pollute the page cache)')

    p_backup = sub.add_parser('backup', help='dump boot sectors, $MFT, $MFTMirr and given '
                                             "directories' raw $I30 indexes to a directory")
    p_backup.add_argument('device')
    p_backup.add_argument('outdir')
    p_backup.add_argument('dirs', nargs='*', help='directories whose $INDEX_ALLOCATION to dump')

    p_usn = sub.add_parser('usn', help='validate the USN change journal; --really resets a '
                                       'corrupt journal (--reset forces the reset)')
    p_usn.add_argument('device')
    p_usn.add_argument('--really', action='store_true', help='actually write; default is dry-run')
    p_usn.add_argument('--reset', action='store_true', help='reset even if the journal is consistent')

    p_secure = sub.add_parser('secure', help='validate $Secure: $SDS descriptors + mirrors, '
                                             '$SII/$SDH indexes, per-file references '
                                             '(--really repairs mirrors and rebuilds indexes)')
    p_secure.add_argument('device')
    p_secure.add_argument('--really', action='store_true', help='actually write; default is dry-run')

    p_list = sub.add_parser('list', help='find NTFS partitions: raw partition-table + '
                                         'boot-sector scan of the local disks (or the '
                                         'given devices/images); mounts nothing')
    p_list.add_argument('devices', nargs='*',
                        help='devices or image files to scan (default: all local disks)')

    args = parser.parse_args()
    if args.cmd == 'list':      # read-only by construction; may target mounted disks
        return list_volumes(args.devices or None)
    if args.cmd in ('/r', '/R'):
        args.surface = True
    if args.cmd in ('/f', '/F', '/r', '/R'):
        args.cmd = 'fix'
    assert_not_mounted(args.device)

    if args.cmd == 'fix':
        return full_fix(args.device, args.really, args.surface, args.direct)

    if args.cmd == 'surface':
        with open_volume(args.device, readonly=True) as volume:
            scan = run_surface(args.device, volume, args.direct)
            _print_surface(scan)
            return 1 if scan['bad'] else 0

    if args.cmd == 'backup':
        return do_backup(args.device, args.outdir, args.dirs)

    if args.cmd == 'secure':
        with open_volume(args.device, readonly=not args.really) as volume:
            chk = volume.secure_check()
            for note in chk['notes']:
                print(f'note: {note}')
            if not chk['present']:
                return 0
            print(f'descriptors: {chk["descriptors"]} in $SDS, '
                  f'{chk["files_checked"]} files reference them')
            findings = (chk['problems'] + [f'mirror mismatch at {p} ({s} side is good)'
                                           for p, _l, s in chk['mirror_fixes']]
                        + chk['index_problems'] + chk['ref_missing'])
            for prob in findings:
                print(f'! {prob}')
            if not findings:
                print('$Secure consistent')
                return 0
            if not args.really:
                print('DRY RUN: re-run with --really to repair mirrors and rebuild '
                      '$SII/$SDH (unrepairable damage and dangling references are '
                      'report-only)')
                return 1
            if chk['mirror_fixes']:
                n = volume.secure_fix_mirrors(chk['mirror_fixes'])
                print(f'{n} $SDS mirror pair(s) repaired')
            if chk['index_problems']:
                try:
                    result = volume.rebuild_secure_indexes(chk['sds_entries'])
                    print(f'$SII/$SDH rebuilt from $SDS ({result["added"]} descriptors)')
                except NtfsError as exc:
                    print(f'$SII/$SDH not rebuilt: {exc}')
            again = volume.secure_check()
            remaining = (again['problems'] + again['index_problems']
                         + [f'mirror mismatch at {p}' for p, _l, _s in again['mirror_fixes']]
                         + again['ref_missing'])
            print(f'verify: {len(remaining)} finding(s) remain')
            for prob in remaining[:10]:
                print(f'! {prob}')
            return 1 if remaining else 0

    if args.cmd == 'usn':
        with open_volume(args.device, readonly=not args.really) as volume:
            info = volume.usn_check()
            if not info['present']:
                print('no USN journal on this volume (nothing to check)')
                return 0
            print(f'journal id : {info["journal_id"] or 0:#x}')
            print(f'valid range: [{info["lowest"]}, {info["next_usn"]}), '
                  f'{info["records"]} records walked')
            for note in info['notes']:
                print(f'note: {note}')
            for prob in info['problems']:
                print(f'! {prob}')
            if not info['problems'] and not args.reset:
                print('journal consistent')
                return 0
            if not args.really:
                print('DRY RUN: re-run with --really to reset the journal '
                      '(new id; indexers/backup tools rescan)')
                return 1 if info['problems'] else 0
            new_id = volume.usn_reset()
            check = volume.usn_check()
            ok = not check['problems'] and check['next_usn'] == 0
            print(f'journal reset: new id {new_id:#x}'
                  + ('' if ok else ' — VERIFY FAILED'))
            return 0 if ok else 1

    if args.cmd == 'rebuild':
        with open_volume(args.device, readonly=True) as volume:
            probe = volume.probe_dir(args.dir)
            census = volume.children_from_mft(volume.resolve(args.dir))

        if probe['readable']:
            print(f'index     : readable, {len(probe["entries"])} entries '
                  f'({sum(e["status"] != "ok" for e in probe["entries"])} dangling)')
        else:
            print(f'index     : UNREADABLE (torn) — {probe["error"]}')
        print(f'mft census: {len(census["children"])} names claim this directory as parent '
              f'({census["stale_parent"]} stale-parent names and '
              f'{census["unreadable_records"]} torn MFT records skipped)')
        for child in census['children']:
            kind = {1: 'win32', 2: 'dos', 3: 'win32+dos'}.get(child['type'], 'posix')
            print(f'  {child["name"]!r:60} mft={child["record"]} seq={child["seq"]} [{kind}]')

        if probe['readable'] and not args.force:
            print('index reads fine — refusing to rebuild without --force')
            return 1
        if not args.really:
            print('DRY RUN: re-run with --really to wipe the $I30 index and rebuild it from these names')
            return 0

        with open_volume(args.device, readonly=False) as volume:
            result = volume.rebuild_dir(args.dir)
        print(f'rebuilt: {result["added"]} entries re-added '
              f'({result["duplicates"]} duplicates skipped, {result["planned"]} planned)')

        with open_volume(args.device, readonly=True) as volume:
            verify = volume.probe_dir(args.dir)
        if not verify['readable']:
            print(f'VERIFY FAILED: index still unreadable — {verify["error"]}')
            return 1
        bad = [e for e in verify['entries'] if e['status'] != 'ok']
        print(f'verify    : index readable, {len(verify["entries"])} entries, {len(bad)} dangling')
        for entry in bad:
            print(f'  still dangling: {entry["name"]!r} — triage with inspect')
        return 0

    if args.cmd == 'inspect':
        with open_volume(args.device, readonly=True) as volume:
            verdict = volume.classify_dirent(args.dir, args.name)
            print(f'entry     : {verdict["name"]!r} in {args.dir!r} '
                  f'-> mft={verdict["dirent_record"]} seq={verdict["dirent_seq"]}')
            record = verdict.get('record_info')
            if record and record.get('open'):
                print(f'record    : seq={record["seq"]} in_use={record["in_use"]} '
                      f'links={record["link_count"]} dir={record["is_dir"]}')
                for entry in record['names']:
                    print(f'  claims  : {entry["name"]!r} (parent mft={entry["parent_record"]})')
            elif record:
                print(f'record    : unreadable/free ({record["error"]})')
            print(f'state     : {verdict["state"]}')
            print(f'action    : {verdict["action"]}')
            return 0 if verdict['state'] == 'healthy' else 1

    if args.cmd == 'purge':
        with open_volume(args.device, readonly=not args.really) as volume:
            verdict = volume.purge_orphan(args.dir, args.name, really=args.really)
            if args.really:
                print(f'purged {args.name!r}: dirent removed, record '
                      f'{verdict["dirent_record"]} and its clusters freed')
            else:
                print(f'DRY RUN: {args.name!r} is a true orphan (record {verdict["dirent_record"]}); '
                      're-run with --really to reclaim it fully')
            return 0

    if args.cmd == 'scan':
        with open_volume(args.device, readonly=True) as volume:
            try:
                entries = volume.scan_dir(args.dir)
            except NtfsError as exc:
                print(f'index walk failed: {exc}')
                print('the directory index itself is unreadable (torn INDX block?) — '
                      'triage with `rebuild` (dry-run first)')
                return 2
            broken = 0
            for entry in entries:
                if entry['status'] == 'dir-self':
                    continue
                flag = ' ' if entry['status'] == 'ok' else '!'
                print(f'{flag} {entry["name"]!r:60} mft={entry["record"]} seq={entry["seq"]} {entry["status"]}')
                broken += entry['status'] != 'ok'
            print(f'-- {broken} dangling entr{"y" if broken == 1 else "ies"}')
            return 1 if broken else 0

    if not args.really:
        with open_volume(args.device, readonly=True) as volume:
            found = volume.remove_dirent(args.dir, args.name, really=False)
            print(f'DRY RUN: would remove {found["name"]!r} -> mft={found["record"]} seq={found["seq"]}')
            print('re-run with --really to write')
            return 0

    with open_volume(args.device, readonly=False) as volume:
        found = volume.remove_dirent(args.dir, args.name, really=True)
        print(f'removed {found["name"]!r} (was mft={found["record"]} seq={found["seq"]})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
