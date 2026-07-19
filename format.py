'''format.py — an NTFS formatter in pure Python, built on checkdisk's write engine.

Creates a blank NTFS 3.1 volume from nothing: boot sector + backup, the system
files ($MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, root, $Bitmap, $Boot,
$BadClus, $Secure with initial descriptors + $SII/$SDH, $UpCase, $Extend with
$ObjId/$Quota/$Reparse), and a populate() that creates real files/directories —
no external tooling, no root.

Two-phase design:
  1. bootstrap — hand-build the boot sector and system MFT records into the
     image (plain byte construction, sealed with checkdisk's fixup sealer);
  2. engine — open the proto-volume with checkdisk.RawVolumeRW and use the
     validated write engine for everything hard: directory entries go in via
     insert_index_entry (which converts small→large indexes and splits blocks
     as needed), and $SII/$SDH are built by rebuild_secure_indexes — the same
     code paths the repair tool exercises, so a formatted volume is
     definitionally in the shape the checker calls clean.

Geometry is fixed at the common case: 512-byte sectors, 4 KiB clusters,
1 KiB MFT records, 4 KiB index blocks.

Usage:
    python format.py IMAGE [--size MIB] [--label NAME]     format an image file
    python format.py --selftest                             format + verify /f
'''

from __future__ import annotations

import argparse, array, os, struct, subprocess, sys, time

sys.path.insert(0, __file__.replace('\\', '/').rsplit('/', 1)[0])

import checkdisk 


SECTOR = 512
CLUSTER = 4096
SPC = CLUSTER // SECTOR
REC = 1024                      # MFT record size
IBLK = 4096                     # index block size
MFT_RECORDS = 64                # minimum initial $MFT size
LOG_CLUSTERS = 512              # $LogFile: 2 MiB, 0xFF-filled ("clean")
U64MAX = 0xFFFFFFFFFFFFFFFF

# system records
R_MFT, R_MIRR, R_LOG, R_VOL, R_ATTRDEF, R_ROOT, R_BITMAP, R_BOOT = range(8)
R_BADCLUS, R_SECURE, R_UPCASE, R_EXTEND = 8, 9, 10, 11
R_QUOTA, R_OBJID, R_REPARSE = 24, 25, 26     # fixed Windows order


def _now() -> int:
    return int((time.time() + 11644473600) * 10 ** 7)   # NTFS FILETIME


# ── fixed-content blobs ──────────────────────────────────────────────────────

def _sid(*subs: int, auth: int = 5) -> bytes:
    return (struct.pack('<BB', 1, len(subs)) + auth.to_bytes(6, 'big')
            + b''.join(struct.pack('<I', s) for s in subs))


SID_EVERYONE = _sid(0, auth=1)          # S-1-1-0
SID_SYSTEM = _sid(18)                   # S-1-5-18
SID_ADMINS = _sid(32, 544)              # S-1-5-32-544


def _sd(owner: bytes, group: bytes, aces: list[tuple[bytes, int]]) -> bytes:
    '''A self-relative SECURITY_DESCRIPTOR with a DACL of allow-ACEs.'''
    body = b''.join(struct.pack('<BBHI', 0, 0, 8 + len(sid), mask) + sid
                    for sid, mask in aces)
    dacl = struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body
    dacl_off = 20
    owner_off = dacl_off + len(dacl)
    group_off = owner_off + len(owner)
    return (struct.pack('<BBHIIII', 1, 0, 0x8004,          # SELF_REL|DACL_PRESENT
                        owner_off, group_off, 0, dacl_off)
            + dacl + owner + group)


FULL = 0x001F01FF               # file all-access
_SD_WORLD = _sd(SID_ADMINS, SID_ADMINS,
                [(SID_EVERYONE, FULL), (SID_SYSTEM, FULL)])
_SD_ADMIN = _sd(SID_ADMINS, SID_ADMINS,
                [(SID_ADMINS, FULL), (SID_SYSTEM, FULL)])


def build_sds() -> tuple[bytes, dict]:
    '''The initial $SDS content (primary block only) and the sds_entries dict
       {security_id: (hash, offset, length)} the index rebuild consumes.'''
    out = bytearray()
    entries = {}
    for sid_id, sd in ((0x100, _SD_WORLD), (0x101, _SD_ADMIN)):
        off = (len(out) + 15) & ~15
        out += b'\x00' * (off - len(out))
        h = checkdisk._security_hash(sd)
        entry = struct.pack('<IIQI', h, sid_id, off, 20 + len(sd)) + sd
        out += entry
        entries[sid_id] = (h, off, 20 + len(sd))
    return bytes(out), entries


# Where the frozen Windows $UpCase disagrees with Python's Unicode tables:
# characters that gained an uppercase form in later Unicode versions map to
# THEMSELVES on real volumes. Extracted empirically by diffing against a
# real Windows 10 system volume's $UpCase.
# Bit-identity is load-bearing, not cosmetic: chkdsk quietly skips index
# verification on a volume whose $UpCase it does not expect.
_UPCASE_SELF = (
    (0x00B5, 0x00B5), (0x0131, 0x0131), (0x017F, 0x017F), (0x019B, 0x019B),
    (0x01C5, 0x01C5), (0x01C8, 0x01C8), (0x01CB, 0x01CB), (0x01F2, 0x01F2),
    (0x023F, 0x0240), (0x0252, 0x0252), (0x025C, 0x025C), (0x0261, 0x0261),
    (0x0264, 0x0266), (0x026A, 0x026A), (0x026C, 0x026C), (0x0282, 0x0282),
    (0x0287, 0x0287), (0x029D, 0x029E), (0x0345, 0x0345), (0x03C2, 0x03C2),
    (0x03D0, 0x03D1), (0x03D5, 0x03D6), (0x03F0, 0x03F1), (0x03F3, 0x03F3),
    (0x03F5, 0x03F5), (0x0525, 0x0525), (0x0527, 0x0527), (0x0529, 0x0529),
    (0x052B, 0x052B), (0x052D, 0x052D), (0x052F, 0x052F), (0x10D0, 0x10FA),
    (0x10FD, 0x10FF), (0x13F8, 0x13FD), (0x1C80, 0x1C88), (0x1C8A, 0x1C8A),
    (0x1D8E, 0x1D8E), (0x1E9B, 0x1E9B), (0x1FBE, 0x1FBE), (0x2C5F, 0x2C5F),
    (0x2CEC, 0x2CEC), (0x2CEE, 0x2CEE), (0x2CF3, 0x2CF3), (0x2D27, 0x2D27),
    (0x2D2D, 0x2D2D), (0xA661, 0xA661), (0xA699, 0xA699), (0xA69B, 0xA69B),
    (0xA791, 0xA791), (0xA793, 0xA794), (0xA797, 0xA797), (0xA799, 0xA799),
    (0xA79B, 0xA79B), (0xA79D, 0xA79D), (0xA79F, 0xA79F), (0xA7A1, 0xA7A1),
    (0xA7A3, 0xA7A3), (0xA7A5, 0xA7A5), (0xA7A7, 0xA7A7), (0xA7A9, 0xA7A9),
    (0xA7B5, 0xA7B5), (0xA7B7, 0xA7B7), (0xA7B9, 0xA7B9), (0xA7BB, 0xA7BB),
    (0xA7BD, 0xA7BD), (0xA7BF, 0xA7BF), (0xA7C1, 0xA7C1), (0xA7C3, 0xA7C3),
    (0xA7C8, 0xA7C8), (0xA7CA, 0xA7CA), (0xA7CD, 0xA7CD), (0xA7D1, 0xA7D1),
    (0xA7D7, 0xA7D7), (0xA7D9, 0xA7D9), (0xA7DB, 0xA7DB), (0xA7F6, 0xA7F6),
    (0xAB53, 0xAB53), (0xAB70, 0xABBF),
)


def build_upcase() -> bytes:
    '''The Windows $UpCase table, bit-identical: Python's 1:1 BMP uppercasing
       (multi-char expansions like ß→SS stay identity, as on Windows), the
       frozen-table identity exceptions above, and the iota-subscript vocalics
       which Windows maps to their titlecase forms.'''
    t = array.array('H', range(65536))
    for c in range(65536):
        if 0xD800 <= c <= 0xDFFF:
            continue
        u = chr(c).upper()
        if len(u) == 1:
            uo = ord(u)
            if uo < 0x10000:
                t[c] = uo
    for a, b in _UPCASE_SELF:
        for c in range(a, b + 1):
            t[c] = c
    for base in (0x1F80, 0x1F90, 0x1FA0):     # ᾀ-family → titlecase, +8
        for c in range(base, base + 8):
            t[c] = c + 8
    for c in (0x1FB3, 0x1FC3, 0x1FF3):        # ᾳ ῃ ῳ → titlecase, +9
        t[c] = c + 9
    if sys.byteorder == 'big':
        t.byteswap()
    return t.tobytes()


_ATTRDEF = [
    ('$STANDARD_INFORMATION', 0x10, 0x40, 0x30, 0x48),
    ('$ATTRIBUTE_LIST',       0x20, 0x80, 0, U64MAX),
    ('$FILE_NAME',            0x30, 0x42, 0x44, 0x242),
    ('$OBJECT_ID',            0x40, 0x40, 0, 0x100),
    ('$SECURITY_DESCRIPTOR',  0x50, 0x80, 0, U64MAX),
    ('$VOLUME_NAME',          0x60, 0x40, 2, 0x100),
    ('$VOLUME_INFORMATION',   0x70, 0x40, 0x0C, 0x0C),
    ('$DATA',                 0x80, 0x00, 0, U64MAX),
    ('$INDEX_ROOT',           0x90, 0x40, 0, U64MAX),
    ('$INDEX_ALLOCATION',     0xA0, 0x80, 0, U64MAX),
    ('$BITMAP',               0xB0, 0x80, 0, U64MAX),
    ('$REPARSE_POINT',        0xC0, 0x80, 0, 0x4000),
    ('$EA_INFORMATION',       0xD0, 0x40, 8, 8),
    ('$EA',                   0xE0, 0x00, 0, 0x10000),
    ('$LOGGED_UTILITY_STREAM', 0x100, 0x80, 0, 0x10000),
]


def build_attrdef() -> bytes:
    out = bytearray()
    for name, atype, flags, mn, mx in _ATTRDEF:
        e = bytearray(160)
        e[:len(name) * 2] = name.encode('utf-16-le')
        struct.pack_into('<IIIIQQ', e, 128, atype, 0, 0, flags, mn, mx)
        out += e
    out += bytes(160)                                    # terminator entry
    return bytes(out)


# ── value builders (attribute contents) ──────────────────────────────────────

def si_value(attr_flags: int, security_id: int = 0x100, t: int | None = None) -> bytes:
    # Default security_id = 0x100, the canonical $Secure entry (World SD) every
    # record shipped here references. chkdsk /scan validates the SecurityId ->
    # $SDS/$SII linkage and flags SecurityId = 0 on system metafiles; a fresh
    # Windows format stamps a real id, so we match rather than leave 0.
    t = _now() if t is None else t
    v = bytearray(72)                                    # v3.x layout
    struct.pack_into('<QQQQ', v, 0, t, t, t, t)          # crtime/mtime/ctime/atime
    struct.pack_into('<I', v, 32, attr_flags)
    struct.pack_into('<I', v, 52, security_id)
    return bytes(v)


def fn_value(parent_mref: int, name: str, attr_flags: int,
             alloc: int = 0, size: int = 0, namespace: int = 3,
             t: int | None = None) -> bytes:
    t = _now() if t is None else t
    n = name.encode('utf-16-le')
    v = bytearray(66 + len(n))
    struct.pack_into('<Q', v, 0, parent_mref)
    struct.pack_into('<QQQQ', v, 8, t, t, t, t)
    struct.pack_into('<QQ', v, 40, alloc, size)
    struct.pack_into('<I', v, 56, attr_flags)
    v[64], v[65] = len(name), namespace
    v[66:] = n
    return bytes(v)


def index_root_value(indexed_type: int, collation: int) -> bytes:
    '''An empty (small) index: INDEX_ROOT prefix + INDEX_HEADER + END entry.'''
    end = struct.pack('<QHHHH', 0, 16, 0, 2, 0)          # leaf END, no subnode
    hdr = struct.pack('<IIIB3x', 16, 16 + len(end), 16 + len(end), 0)
    return struct.pack('<IIIB3x', indexed_type, collation, IBLK,
                       max(IBLK // CLUSTER, 1)) + hdr + end


def view_root_value(collation: int, entries: list[tuple[bytes, bytes]]) -> bytes:
    '''A small view index whose leaf entries carry (key, data) — data packed
       directly after the key, unaligned, as Windows writes them.'''
    body = b''
    for key, data in entries:                            # pre-sorted by caller
        doff = 16 + len(key)
        elen = (doff + len(data) + 7) & ~7
        e = bytearray(elen)
        struct.pack_into('<HH', e, 0, doff, len(data))
        struct.pack_into('<HHH', e, 8, elen, len(key), 0)
        e[16:doff] = key
        e[doff:doff + len(data)] = data
        body += e
    body += struct.pack('<QHHHH', 0, 16, 0, 2, 0)        # END
    hdr = struct.pack('<IIIB3x', 16, 16 + len(body), 16 + len(body), 0)
    return struct.pack('<IIIB3x', 0, collation, IBLK,
                       max(IBLK // CLUSTER, 1)) + hdr + body


def quota_data(change_time: int, sid: bytes = b'') -> bytes:
    '''A QUOTA_CONTROL_ENTRY: v2, default limits (no threshold/limit), zero
       usage — what Windows expects to find for owner ids 1 and 0x100.'''
    return struct.pack('<IIQqqqq', 2, 1, 0, change_time, -1, -1, 0) + sid


# ── record construction ──────────────────────────────────────────────────────

def new_record(rec_no: int, is_dir: bool = False, links: int = 1,
               view: bool = False) -> bytearray:
    r = bytearray(REC)
    r[:4] = b'FILE'
    struct.pack_into('<HH', r, 4, 0x30, 1 + REC // 512)  # USA at 0x30
    struct.pack_into('<H', r, 0x10, max(rec_no, 1))      # seq = record number
    struct.pack_into('<H', r, 0x12, links)
    struct.pack_into('<H', r, 0x14, 0x38)                # attrs at 0x38
    # view-index records carry 0x0C on real volumes; chkdsk verifies it
    struct.pack_into('<H', r, 0x16, (3 if is_dir else 1) | (0xC if view else 0))
    struct.pack_into('<I', r, 0x18, 0x38 + 8)            # in_use: terminator
    struct.pack_into('<I', r, 0x1C, REC)
    struct.pack_into('<I', r, 0x2C, rec_no)
    struct.pack_into('<I', r, 0x38, 0xFFFFFFFF)
    return r


def _add(rec: bytearray, atype: int, name: str = '', **kw) -> int:
    '''Insert an attribute via checkdisk's builder (pure record surgery).'''
    return checkdisk.RawVolumeRW._add_attr(None, rec, atype,
                                     name.encode('utf-16-le'), **kw)


def add_resident(rec, atype, value, name='', indexed=False) -> None:
    a = _add(rec, atype, name, resident=True, value=value)
    if indexed:
        rec[a + 0x16] = 1                                # indexed flag ($FILE_NAME)


def add_nonres(rec, atype, runs, data_size, name='',
               alloc: int | None = None, init: int | None = None) -> None:
    a = _add(rec, atype, name, resident=False, runs=runs, data_size=data_size)
    # on-disk conventions chkdsk checks: allocated_size is cluster-rounded,
    # and some special files ($Bad) keep initialized_size at 0
    if alloc is None:
        alloc = -(-data_size // CLUSTER) * CLUSTER
    if init is None:
        init = data_size
    struct.pack_into('<QQQ', rec, a + 40, alloc, data_size, init)


def mref(rec_no: int) -> int:
    return rec_no | (max(rec_no, 1) << 48)


F_METAFILE = 0x06                # hidden + system
F_DIR = 0x10000006
F_VIEW = 0x20000026              # + archive, as Windows marks view files


# ── the formatter ────────────────────────────────────────────────────────────

def format_volume(path: str, size_mib: int = 64, label: str = '',
                  log_mib: int = 2) -> None:
    nc = size_mib * 1024 * 1024 // CLUSTER               # clusters
    if nc < 2048:
        raise SystemExit('minimum size is 8 MiB')
    # initial $MFT scaled to the volume (~6%): the engine's record allocator
    # deliberately does not grow the MFT, so the formatter pre-allocates room
    n_rec = max(MFT_RECORDS, nc // 4 // 8 * 8)
    img = bytearray(nc * CLUSTER + SECTOR)               # + backup boot sector

    # -- sequential cluster allocator (bitmap built alongside) --
    bitmap = bytearray((nc + 7) // 8)
    cursor = 0

    def alloc(n: int, at: int | None = None) -> int:
        nonlocal cursor
        lcn = cursor if at is None else at
        checkdisk._set_run(bitmap, lcn, n)
        if at is None:
            cursor = lcn + n
        return lcn

    alloc(2)                                             # clusters 0-1: $Boot
    mft_lcn = alloc(n_rec * REC // CLUSTER)              # $MFT data
    log_clusters = max(LOG_CLUSTERS, log_mib * 1024 * 1024 // CLUSTER)
    log_lcn = alloc(log_clusters)                        # $LogFile
    attrdef_blob = build_attrdef()
    attrdef_lcn = alloc(-(-len(attrdef_blob) // CLUSTER))
    bmp_clusters = -(-len(bitmap) // CLUSTER)
    bmp_lcn = alloc(bmp_clusters)                        # $Bitmap data
    upcase_blob = build_upcase()
    upcase_lcn = alloc(len(upcase_blob) // CLUSTER)
    sds_blob, sds_entries = build_sds()
    sds_clusters = 0x40000 // CLUSTER + 1                # both mirror blocks, real
    sds_lcn = alloc(sds_clusters)                        # $SDS (no sparse holes)
    mftbmp_bytes = (n_rec // 8 + 7) & ~7
    mftbmp_clusters = -(-mftbmp_bytes // CLUSTER)
    mftbmp_lcn = alloc(mftbmp_clusters)                  # $MFT's $BITMAP (non-res)
    mirr_lcn = alloc(1, at=nc // 2)                      # $MFTMirr, mid-volume

    # -- boot sector + backup --
    boot = bytearray(SECTOR)
    boot[0:3] = b'\xeb\x52\x90'
    boot[3:11] = b'NTFS    '
    struct.pack_into('<H', boot, 11, SECTOR)
    boot[13] = SPC
    boot[21] = 0xF8                                      # media descriptor
    struct.pack_into('<H', boot, 24, 63)                 # sectors/track
    struct.pack_into('<H', boot, 26, 255)                # heads
    struct.pack_into('<I', boot, 36, 0x00800080)         # BIOS drive
    struct.pack_into('<Q', boot, 40, nc * SPC)           # sectors (excl. backup)
    struct.pack_into('<Q', boot, 48, mft_lcn)
    struct.pack_into('<Q', boot, 56, mirr_lcn)
    struct.pack_into('<b', boot, 64, -10)                # 2^10 = 1 KiB records
    struct.pack_into('<b', boot, 68, IBLK // CLUSTER)    # index block, clusters
    struct.pack_into('<Q', boot, 72, int.from_bytes(os.urandom(8), 'little'))
    boot[510:512] = b'\x55\xaa'
    img[0:SECTOR] = boot
    img[nc * CLUSTER:nc * CLUSTER + SECTOR] = boot       # backup boot sector

    # -- system records --
    recs: dict[int, bytearray] = {}

    r = recs[R_MFT] = new_record(R_MFT)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$MFT', F_METAFILE,
                                   n_rec * REC, n_rec * REC),
                 indexed=True)
    add_nonres(r, 0x80, [(mft_lcn, n_rec * REC // CLUSTER)], n_rec * REC)
    mft_bm = bytearray((n_rec // 8 + 7) & ~7)            # 1 bit per record
    for no in (*range(16), R_OBJID, R_QUOTA, R_REPARSE):
        mft_bm[no >> 3] |= 1 << (no & 7)
    # non-resident, as on real volumes — driver record allocators walk the
    # bitmap attribute's runlist and refuses a resident one (EINVAL on create)
    add_nonres(r, 0xB0, [(mftbmp_lcn, mftbmp_clusters)], len(mft_bm))

    r = recs[R_MIRR] = new_record(R_MIRR)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$MFTMirr', F_METAFILE,
                                   CLUSTER, 4 * REC), indexed=True)
    add_nonres(r, 0x80, [(mirr_lcn, 1)], 4 * REC)

    r = recs[R_LOG] = new_record(R_LOG)
    add_resident(r, 0x10, si_value(F_METAFILE))
    log_bytes = log_clusters * CLUSTER
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$LogFile', F_METAFILE,
                                   log_bytes, log_bytes), indexed=True)
    add_nonres(r, 0x80, [(log_lcn, log_clusters)], log_bytes)

    r = recs[R_VOL] = new_record(R_VOL)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$Volume', F_METAFILE),
                 indexed=True)
    add_resident(r, 0x60, label.encode('utf-16-le'))     # $VOLUME_NAME
    add_resident(r, 0x70, struct.pack('<QBBH', 0, 3, 1, 0))  # NTFS 3.1, clean
    add_resident(r, 0x80, b'')

    r = recs[R_ATTRDEF] = new_record(R_ATTRDEF)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$AttrDef', F_METAFILE,
                                   -(-len(attrdef_blob) // CLUSTER) * CLUSTER,
                                   len(attrdef_blob)), indexed=True)
    add_nonres(r, 0x80, [(attrdef_lcn, -(-len(attrdef_blob) // CLUSTER))],
               len(attrdef_blob))

    r = recs[R_ROOT] = new_record(R_ROOT, is_dir=True)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '.', F_DIR), indexed=True)
    add_resident(r, 0x90, index_root_value(0x30, 0x01), name='$I30')

    r = recs[R_BITMAP] = new_record(R_BITMAP)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$Bitmap', F_METAFILE,
                                   bmp_clusters * CLUSTER, len(bitmap)),
                 indexed=True)
    add_nonres(r, 0x80, [(bmp_lcn, bmp_clusters)], len(bitmap))

    r = recs[R_BOOT] = new_record(R_BOOT)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$Boot', F_METAFILE,
                                   2 * CLUSTER, 8192), indexed=True)
    add_nonres(r, 0x80, [(0, 2)], 8192)

    r = recs[R_BADCLUS] = new_record(R_BADCLUS)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$BadClus', F_METAFILE),
                 indexed=True)
    add_resident(r, 0x80, b'')
    add_nonres(r, 0x80, [(-1, nc)], nc * CLUSTER, name='$Bad',
               alloc=nc * CLUSTER, init=0)               # all-sparse, init 0

    r = recs[R_SECURE] = new_record(R_SECURE)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$Secure', F_METAFILE),
                 indexed=True)
    # $SDS: entries in even 256 KiB block 0, mirrored into odd block 1;
    # fully allocated, as Windows formats it — no sparse holes
    sds_size = 0x40000 + len(sds_blob)
    add_nonres(r, 0x80, [(sds_lcn, sds_clusters)], sds_size, name='$SDS')
    # same-type attributes must be name-sorted ($SDH < $SII) — attribute
    # lookups stop early on out-of-order names
    add_resident(r, 0x90, index_root_value(0, 0x12), name='$SDH')
    add_resident(r, 0x90, index_root_value(0, 0x10), name='$SII')

    r = recs[R_UPCASE] = new_record(R_UPCASE)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$UpCase', F_METAFILE,
                                   len(upcase_blob), len(upcase_blob)),
                 indexed=True)
    add_nonres(r, 0x80, [(upcase_lcn, len(upcase_blob) // CLUSTER)],
               len(upcase_blob))
    # $UpCase:$Info — a 32-byte named resident $DATA a fresh Windows format
    # ships: u32 length(0x20) + u32 reserved + u64 CRC64(table) + 16 reserved.
    # Our $UpCase is the md5-pinned Windows table (see build_upcase / the drift
    # guard), so its CRC64 is the constant Windows stamps; recompute both if the
    # table ever drifts. Absent, ntfs.sys raises Event 55 on a /scan mount.
    add_resident(r, 0x80, struct.pack('<IIQ16x', 0x20, 0, 0xDADC7E776B1B690C),
                 name='$Info')

    r = recs[R_EXTEND] = new_record(R_EXTEND, is_dir=True)
    add_resident(r, 0x10, si_value(F_METAFILE))
    add_resident(r, 0x30, fn_value(mref(R_ROOT), '$Extend', F_DIR),
                 indexed=True)
    add_resident(r, 0x90, index_root_value(0x30, 0x01), name='$I30')

    for no in (12, 13, 14, 15):                          # reserved records
        r = recs[no] = new_record(no, links=0)
        add_resident(r, 0x10, si_value(F_METAFILE))
        add_resident(r, 0x80, b'')

    # $Extend children: view-index files, in the exact Windows shape chkdsk
    # verifies — $Quota at 24 with the default quota entries (owner id 1 =
    # default, 0x100 = Administrators), $ObjId at 25, $Reparse at 26
    t = _now()
    for no, name, roots in (
            (R_QUOTA, '$Quota',
             (('$O', 0x11, [(SID_ADMINS, struct.pack('<I', 0x100))]),
              ('$Q', 0x10, [(struct.pack('<I', 1), quota_data(t)),
                            (struct.pack('<I', 0x100),
                             quota_data(t, SID_ADMINS))]))),
            (R_OBJID, '$ObjId', (('$O', 0x13, []),)),
            (R_REPARSE, '$Reparse', (('$R', 0x13, []),))):
        r = recs[no] = new_record(no, view=True)
        add_resident(r, 0x10, si_value(F_VIEW))
        add_resident(r, 0x30, fn_value(mref(R_EXTEND), name, F_VIEW),
                     indexed=True)
        for iname, coll, entries in roots:
            add_resident(r, 0x90, view_root_value(coll, entries), name=iname)

    # -- data streams into the image --
    def put(lcn: int, blob: bytes) -> None:
        img[lcn * CLUSTER:lcn * CLUSTER + len(blob)] = blob

    put(attrdef_lcn, attrdef_blob)
    put(upcase_lcn, upcase_blob)
    put(sds_lcn, sds_blob)
    put(sds_lcn + 0x40000 // CLUSTER, sds_blob)          # verbatim mirror
    put(mftbmp_lcn, bytes(mft_bm))
    img[log_lcn * CLUSTER:(log_lcn + log_clusters) * CLUSTER] = \
        b'\xff' * log_bytes
    put(bmp_lcn, bytes(bitmap))

    # -- seal + place the MFT, mirror records 0-3 --
    mft_area = bytearray(n_rec * REC)
    for no, rec in recs.items():
        sealed = bytearray(rec)
        checkdisk._seal_fixups(sealed)
        mft_area[no * REC:(no + 1) * REC] = sealed
    img[mft_lcn * CLUSTER:mft_lcn * CLUSTER + len(mft_area)] = mft_area
    img[mirr_lcn * CLUSTER:mirr_lcn * CLUSTER + 4 * REC] = mft_area[:4 * REC]

    with open(path, 'wb') as fh:
        fh.write(img)

    # -- phase 2: the engine finishes the job --
    with checkdisk.RawVolumeRW(path) as v:
        # the root is the one directory that indexes ITSELF: a '.' entry in
        # its own $I30 (drivers look it up there after any change under
        # root, and fail with EIO if it is missing)
        for no in (R_ROOT, R_MFT, R_MIRR, R_LOG, R_VOL, R_ATTRDEF, R_BITMAP,
                   R_BOOT, R_BADCLUS, R_SECURE, R_UPCASE, R_EXTEND):
            fn = _first_fn(v, no)
            v.insert_index_entry(R_ROOT, mref(no), fn)
        for no in (R_OBJID, R_QUOTA, R_REPARSE):
            fn = _first_fn(v, no)
            v.insert_index_entry(R_EXTEND, mref(no), fn)
        v.rebuild_secure_indexes(sds_entries)
        v.clear_dirty()


def _first_fn(v, rec_no: int) -> bytes:
    rec = v._load_record(rec_no)
    return next(checkdisk._file_name_attrs(bytes(rec)))


# ── populate: create real files with the engine ──────────────────────────────

def populate(path: str, files: dict[str, bytes],
             dirs: tuple[str, ...] = ()) -> None:
    '''Create directories and files (path -> content) on a formatted volume,
       natively: allocate records + clusters, build SI/FN/$DATA, and insert
       the names through the engine's B+ index insert.'''
    with checkdisk.RawVolumeRW(path) as v:
        made: dict[str, int] = {'': R_ROOT}

        def ensure_dir(rel: str) -> int:
            if rel in made:
                return made[rel]
            parent = ensure_dir(os.path.dirname(rel))
            no = _mkfile(v, parent, os.path.basename(rel), None)
            made[rel] = no
            return no

        for d in dirs:
            ensure_dir(d.strip('/'))
        for rel, content in files.items():
            rel = rel.strip('/')
            parent = ensure_dir(os.path.dirname(rel))
            _mkfile(v, parent, os.path.basename(rel), content)


def _mkfile(v, parent_no: int, name: str, content: bytes | None) -> int:
    '''content None = directory. Returns the new record number.'''
    is_dir = content is None
    no = v.alloc_record()
    old = v.read_record(no)
    seq = 1
    if old and old[:4] == b'FILE':
        seq = (struct.unpack_from('<H', old, 0x10)[0] + 1) & 0xFFFF or 1
    rec = new_record(no, is_dir=is_dir)
    struct.pack_into('<H', rec, 0x10, seq)
    p_rec = v._load_record(parent_no)
    p_seq = struct.unpack_from('<H', p_rec, 0x10)[0]
    # one timestamp for SI and FN: chkdsk cross-checks the dirent's duplicated
    # times against the record's $STANDARD_INFORMATION
    t = _now()
    add_resident(rec, 0x10, si_value(0x10 if is_dir else 0x20,
                                     security_id=0x100, t=t))
    # namespace POSIX (0): a lone WIN32 (1) name implies a DOS twin exists
    # and driver deletes go looking for it (ENOENT); POSIX names stand alone
    # and are what Linux drivers themselves create
    resident = content is not None and len(content) <= 700
    if is_dir:
        alloc = 0
    elif resident:
        alloc = (len(content) + 7) & ~7        # resident: 8-aligned value size
    else:
        alloc = (len(content) + CLUSTER - 1) // CLUSTER * CLUSTER
    fn = fn_value(parent_no | (p_seq << 48), name,
                  0x10000000 if is_dir else 0x20,
                  alloc, 0 if is_dir else len(content), namespace=0, t=t)
    add_resident(rec, 0x30, fn, indexed=True)
    if is_dir:
        add_resident(rec, 0x90, index_root_value(0x30, 0x01), name='$I30')
    elif len(content) <= 700:                            # resident data
        add_resident(rec, 0x80, content)
    else:
        n = -(-len(content) // CLUSTER)
        runs = v.alloc_clusters(n)
        add_nonres(rec, 0x80, runs, len(content))
        pos = 0
        for lcn, cnt in runs:
            chunk = content[pos:pos + cnt * CLUSTER]
            checkdisk._pwrite(v._fd, chunk, lcn * CLUSTER)
            pos += len(chunk)
    v.write_record(no, rec)
    v.insert_index_entry(parent_no, no | (seq << 48), fn)
    return no


# ── selftest ─────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile
    fd, path = tempfile.mkstemp(suffix='.ntfs.img', prefix='fmt-test-')
    os.close(fd)
    try:
        format_volume(path, 64, label='FMTTEST')
        print('formatted 64 MiB')
        populate(path, {'docs/hello.txt': b'hello from format.py\n',
                        'docs/big.bin': os.urandom(3 * CLUSTER + 17),
                        'a/b/c/deep.txt': b'nested\n'},
                 dirs=('empty',))
        print('populated')
        here = os.path.dirname(os.path.abspath(__file__))
        p = subprocess.run([sys.executable, os.path.join(here, 'checkdisk.py'),
                            '/f', path], capture_output=True, text=True)
        tail = [l for l in p.stdout.splitlines() if l.startswith(('--', '!'))]
        print('\n'.join('  ' + l for l in tail))
        print(f'checkdisk /f exit={p.returncode}')
        if p.returncode:
            print(p.stdout)
            return 1
        with checkdisk.RawVolume(path) as v:
            names = sorted(e['name'] for e in v.scan_dir('/docs'))
            assert names == ['big.bin', 'hello.txt'], names
            assert v.scan_dir('/a/b/c')[0]['name'] == 'deep.txt'
        print('selftest OK')
        return 0
    finally:
        os.unlink(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('image', nargs='?', help='image file to create')
    ap.add_argument('--size', type=int, default=64, metavar='MIB')
    ap.add_argument('--label', default='')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.image:
        ap.print_help()
        return 2
    format_volume(a.image, a.size, a.label)
    print(f'formatted {a.image}: {a.size} MiB NTFS 3.1')
    return 0


if __name__ == '__main__':
    sys.exit(main())
