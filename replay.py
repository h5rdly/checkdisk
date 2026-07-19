'''replay.py — native NTFS $LogFile replay (prototype): on-disk structures + engine.

Two parts in one module:

  1. The $LogFile on-disk format — the restart pages (RSTR), log record pages
     (RCRD), per-record headers, and the log operation codes. These are facts of
     the NTFS on-disk format (offsets, field names, sizes), the same layout
     Windows and the Linux NTFS driver read. All multi-byte fields are
     little-endian; restart and record pages carry the usual multi-sector
     "fixup" (update sequence array) — apply checkdisk._apply_fixups before
     trusting a page's contents.

  2. The LFS recovery engine — pick the newer restart area, read the NTFS
     client checkpoint and its four table dumps, run the analysis pass to
     rebuild the dirty-page/transaction/open-attribute tables, redo committed
     operations onto pages whose own LSN is older than the record's, undo the
     operations of transactions that never committed, and mark the log clean.
     The write path reuses checkdisk's engine (record IO with fixups + $MFTMirr
     sync); non-MFT pages are addressed through each log record's own page-LCN
     array — authoritative even when the on-disk runlist never saw the mapping.

This is RESEARCH, not the shipped repair path: checkdisk resets the $LogFile
(RawVolumeRW.reset_logfile) rather than replaying it — a reset log is clean to
the next mount and the structural checks already reconcile the on-disk state, so
a checker needs no replay. Kept because it works and others can learn from it.

Scope: LFS v1.1 and v2.0 logs (v2.0 is what current Windows writes). Tail-copy
reconciliation for v1.x single-page-IO logs is not implemented — a torn last
page simply ends the walk at the last complete record, which loses at most the
final in-flight operations (they would be undone as uncommitted anyway).

Usage:
    python replay.py IMAGE            # analyze: report what replay would do
    python replay.py IMAGE --really   # replay + mark the log clean
'''

from __future__ import annotations

import os, struct, sys

from typing import NamedTuple

sys.path.insert(0, __file__.replace('\\', '/').rsplit('/', 1)[0])

import checkdisk


# ══ $LogFile on-disk structures ══
# ── signatures ───────────────────────────────────────────────────────────────

RSTR_MAGIC = b'RSTR'   # a restart page
RCRD_MAGIC = b'RCRD'   # a log record page
CHKD_MAGIC = b'CHKD'   # a page chkdsk marked (treated like RSTR)


# ── log operation codes (redo_op / undo_op in LOG_REC_HDR) ───────────────────
# The NTFS log records metadata mutations as (redo, undo) operation pairs.

class Op:
    Noop = 0x00
    CompensationLogRecord = 0x01
    InitializeFileRecordSegment = 0x02
    DeallocateFileRecordSegment = 0x03
    WriteEndOfFileRecordSegment = 0x04
    CreateAttribute = 0x05
    DeleteAttribute = 0x06
    UpdateResidentValue = 0x07
    UpdateNonresidentValue = 0x08
    UpdateMappingPairs = 0x09
    DeleteDirtyClusters = 0x0A
    SetNewAttributeSizes = 0x0B
    AddIndexEntryRoot = 0x0C
    DeleteIndexEntryRoot = 0x0D
    AddIndexEntryAllocation = 0x0E
    DeleteIndexEntryAllocation = 0x0F
    WriteEndOfIndexBuffer = 0x10
    SetIndexEntryVcnRoot = 0x11
    SetIndexEntryVcnAllocation = 0x12
    UpdateFileNameRoot = 0x13
    UpdateFileNameAllocation = 0x14
    SetBitsInNonresidentBitMap = 0x15
    ClearBitsInNonresidentBitMap = 0x16
    HotFix = 0x17
    EndTopLevelAction = 0x18
    PrepareTransaction = 0x19
    CommitTransaction = 0x1A
    ForgetTransaction = 0x1B
    OpenNonresidentAttribute = 0x1C
    OpenAttributeTableDump = 0x1D
    AttributeNamesDump = 0x1E
    DirtyPageTableDump = 0x1F
    TransactionTableDump = 0x20
    UpdateRecordDataRoot = 0x21
    UpdateRecordDataAllocation = 0x22
    UpdateRelativeDataInIndex = 0x23     # newer view-index ops; ntfs3 doesn't
    UpdateRelativeDataInIndex2 = 0x24    # apply these — treated as unsupported
    ZeroEndOfFileRecord = 0x25


OP_NAME = {v: k for k, v in vars(Op).items()
           if isinstance(v, int) and not k.startswith('_')}

# The record record_type values in an LFS record header.
LfsClientRecord = 1
LfsClientRestart = 2

# LOG_REC_HDR flag: the redo/undo data spans more than one log page.
LOG_RECORD_MULTI_PAGE = 0x0001


# ── RESTART_HDR — a restart page (RSTR), one per log, mirrored ───────────────
# Standard NTFS record header (magic + fixup array) then the restart fields.

class RestartHdr(NamedTuple):
    magic: bytes          # 0x00: 'RSTR' (or 'CHKD')
    usa_ofs: int          # 0x04: update-sequence-array offset
    usa_count: int        # 0x06: update-sequence-array entry count
    chkdsk_lsn: int       # 0x08: LSN at last chkdsk (0 if none)
    sys_page_size: int    # 0x10: page size of the initializing system
    page_size: int        # 0x14: log page size for this $LogFile
    ra_off: int           # 0x18: offset to the RESTART_AREA within this page
    minor_ver: int        # 0x1A
    major_ver: int        # 0x1C

    @classmethod
    def parse(cls, b: bytes, off: int = 0) -> 'RestartHdr':
        magic = bytes(b[off:off + 4])
        usa_ofs, usa_count = struct.unpack_from('<HH', b, off + 4)
        chkdsk_lsn = struct.unpack_from('<Q', b, off + 8)[0]
        sys_ps, ps = struct.unpack_from('<II', b, off + 16)
        ra_off, minor, major = struct.unpack_from('<HHH', b, off + 24)
        return cls(magic, usa_ofs, usa_count, chkdsk_lsn, sys_ps, ps,
                   ra_off, minor, major)


# ── RESTART_AREA — the log's current state, at RestartHdr.ra_off ─────────────

class RestartArea(NamedTuple):
    current_lsn: int          # 0x00: logical end of the log
    log_clients: int          # 0x08: max clients
    client_idx_free: int      # 0x0A: head of the free client list
    client_idx_use: int       # 0x0C: head of the in-use client list
    flags: int                # 0x0E
    seq_num_bits: int         # 0x10: bits of the sequence number in an LSN
    ra_len: int               # 0x14: length of this restart area
    client_off: int           # 0x16: offset to the client-record array
    l_size: int               # 0x18: usable log-file size in bytes
    last_lsn_data_len: int    # 0x20
    rec_hdr_len: int          # 0x24: log page data offset
    data_off: int             # 0x26: log page data length
    open_log_count: int       # 0x28

    @classmethod
    def parse(cls, b: bytes, off: int) -> 'RestartArea':
        current_lsn = struct.unpack_from('<Q', b, off)[0]
        log_clients, idx_free, idx_use, flags = struct.unpack_from('<HHHH', b, off + 8)
        seq_num_bits = struct.unpack_from('<I', b, off + 16)[0]
        ra_len, client_off = struct.unpack_from('<HH', b, off + 20)
        l_size = struct.unpack_from('<Q', b, off + 24)[0]
        last_lsn_data_len = struct.unpack_from('<I', b, off + 32)[0]
        rec_hdr_len, data_off = struct.unpack_from('<HH', b, off + 36)
        open_log_count = struct.unpack_from('<I', b, off + 40)[0]
        return cls(current_lsn, log_clients, idx_free, idx_use, flags,
                   seq_num_bits, ra_len, client_off, l_size,
                   last_lsn_data_len, rec_hdr_len, data_off, open_log_count)


# ── CLIENT_REC — one client's log window (NTFS is the sole client) ───────────
# Array begins at RESTART_AREA + client_off (0x40 with the default ra layout).

class ClientRec(NamedTuple):
    oldest_lsn: int       # 0x00: oldest LSN this client still needs
    restart_lsn: int      # 0x08: LSN of this client's last restart record
    prev_client: int      # 0x10
    next_client: int      # 0x12
    seq_num: int          # 0x14
    name_bytes: int       # 0x1C: client name length in bytes
    name: str             # 0x20: client name (UTF-16LE), e.g. "NTFS"

    SIZE = 0x60           # 0x20 header + 32 UTF-16 name units

    @classmethod
    def parse(cls, b: bytes, off: int) -> 'ClientRec':
        oldest, restart = struct.unpack_from('<QQ', b, off)
        prev_c, next_c, seq = struct.unpack_from('<HHH', b, off + 16)
        name_bytes = struct.unpack_from('<I', b, off + 28)[0]
        name = bytes(b[off + 32:off + 32 + name_bytes]).decode('utf-16-le', 'replace')
        return cls(oldest, restart, prev_c, next_c, seq, name_bytes, name)


# ── RECORD_PAGE_HDR — a log record page (RCRD) ───────────────────────────────
# Standard NTFS record header, then per-page log bookkeeping. The first log
# record header on the page begins at RestartArea.rec_hdr_len from page start.

class RecordPageHdr(NamedTuple):
    magic: bytes          # 0x00: 'RCRD'
    usa_ofs: int          # 0x04
    usa_count: int        # 0x06
    copy: int             # 0x08: last-end-lsn / file-offset copy (header union)
    rflags: int           # 0x10: LOG_PAGE_* flags (record-end present, etc.)
    page_count: int       # 0x14
    page_pos: int         # 0x16

    @classmethod
    def parse(cls, b: bytes, off: int = 0) -> 'RecordPageHdr':
        magic = bytes(b[off:off + 4])
        usa_ofs, usa_count = struct.unpack_from('<HH', b, off + 4)
        copy = struct.unpack_from('<Q', b, off + 8)[0]
        rflags = struct.unpack_from('<I', b, off + 16)[0]
        page_count, page_pos = struct.unpack_from('<HH', b, off + 20)
        return cls(magic, usa_ofs, usa_count, copy, rflags, page_count, page_pos)


# ── LFS_RECORD_HDR — a single log record's header (inside an RCRD page) ───────

class LfsRecordHdr(NamedTuple):
    this_lsn: int                 # 0x00
    client_prev_lsn: int          # 0x08: prev LSN of this client (chain back)
    client_undo_next_lsn: int     # 0x10: next LSN to undo
    client_data_len: int          # 0x18: length of the record payload
    client_seq: int               # 0x1C: CLIENT_ID.seq_number
    client_index: int             # 0x1E: CLIENT_ID.client_index
    record_type: int              # 0x20: LfsClientRecord / LfsClientRestart
    transact_id: int              # 0x24
    flags: int                    # 0x28: LOG_RECORD_MULTI_PAGE

    HDR_LEN = 0x30                # payload (a LogRecHdr) follows

    @classmethod
    def parse(cls, b: bytes, off: int) -> 'LfsRecordHdr':
        this_lsn, prev_lsn, undo_next = struct.unpack_from('<QQQ', b, off)
        data_len = struct.unpack_from('<I', b, off + 24)[0]
        seq, index = struct.unpack_from('<HH', b, off + 28)
        rtype, tid = struct.unpack_from('<II', b, off + 32)
        flags = struct.unpack_from('<H', b, off + 40)[0]
        return cls(this_lsn, prev_lsn, undo_next, data_len, seq, index,
                   rtype, tid, flags)


# ── LOG_REC_HDR — the operation itself (the LFS record's payload) ─────────────

class LogRecHdr(NamedTuple):
    redo_op: int          # 0x00: Op.* to apply on redo
    undo_op: int          # 0x02: Op.* to apply on undo
    redo_off: int         # 0x04: offset to the redo data
    redo_len: int         # 0x06: redo data length
    undo_off: int         # 0x08: offset to the undo data
    undo_len: int         # 0x0A: undo data length
    target_attr: int      # 0x0C: open-attribute-table index of the target
    lcns_follow: int      # 0x0E: count of page_lcns entries
    record_off: int       # 0x10: offset within the target record/index
    attr_off: int         # 0x12: offset within the target attribute
    cluster_off: int      # 0x14: cluster offset for non-resident targets
    target_vcn: int       # 0x18: target VCN
    page_lcns_off: int    # 0x20: where the LCN array begins (relative to hdr)

    @classmethod
    def parse(cls, b: bytes, off: int) -> 'LogRecHdr':
        (redo_op, undo_op, redo_off, redo_len, undo_off, undo_len,
         target_attr, lcns_follow, record_off, attr_off,
         cluster_off, _reserved) = struct.unpack_from('<12H', b, off)
        target_vcn = struct.unpack_from('<Q', b, off + 24)[0]
        return cls(redo_op, undo_op, redo_off, redo_len, undo_off, undo_len,
                   target_attr, lcns_follow, record_off, attr_off,
                   cluster_off, target_vcn, off + 32)

    def redo(self, b: bytes, hdr_off: int) -> bytes:
        '''The redo payload bytes for this record (b is the record buffer).'''
        return bytes(b[hdr_off + self.redo_off:hdr_off + self.redo_off + self.redo_len])

    def undo(self, b: bytes, hdr_off: int) -> bytes:
        return bytes(b[hdr_off + self.undo_off:hdr_off + self.undo_off + self.undo_len])


# ══ replay engine ══
SECTOR = 512

# ops whose redo/undo updates a page (everything else is bookkeeping)
_PAGE_OPS = {
    Op.InitializeFileRecordSegment, Op.DeallocateFileRecordSegment,
    Op.WriteEndOfFileRecordSegment, Op.CreateAttribute, Op.DeleteAttribute,
    Op.UpdateResidentValue, Op.UpdateNonresidentValue, Op.UpdateMappingPairs,
    Op.SetNewAttributeSizes, Op.AddIndexEntryRoot, Op.DeleteIndexEntryRoot,
    Op.AddIndexEntryAllocation, Op.DeleteIndexEntryAllocation,
    Op.WriteEndOfIndexBuffer, Op.SetIndexEntryVcnRoot,
    Op.SetIndexEntryVcnAllocation, Op.UpdateFileNameRoot,
    Op.UpdateFileNameAllocation, Op.SetBitsInNonresidentBitMap,
    Op.ClearBitsInNonresidentBitMap, Op.UpdateRecordDataRoot,
    Op.UpdateRecordDataAllocation, Op.ZeroEndOfFileRecord,
}
# ops applied to a FILE record (the rest of _PAGE_OPS target an attribute page)
_MFT_OPS = {
    Op.InitializeFileRecordSegment, Op.DeallocateFileRecordSegment,
    Op.WriteEndOfFileRecordSegment, Op.CreateAttribute, Op.DeleteAttribute,
    Op.UpdateResidentValue, Op.UpdateMappingPairs, Op.SetNewAttributeSizes,
    Op.AddIndexEntryRoot, Op.DeleteIndexEntryRoot, Op.SetIndexEntryVcnRoot,
    Op.UpdateFileNameRoot, Op.UpdateRecordDataRoot, Op.ZeroEndOfFileRecord,
}
_SKIP_OPS = {  # no page action ever
    Op.Noop, Op.CompensationLogRecord, Op.DeleteDirtyClusters, Op.HotFix,
    Op.EndTopLevelAction, Op.PrepareTransaction, Op.CommitTransaction,
    Op.ForgetTransaction, Op.OpenNonresidentAttribute,
    Op.OpenAttributeTableDump, Op.AttributeNamesDump, Op.DirtyPageTableDump,
    Op.TransactionTableDump,
    Op.UpdateRelativeDataInIndex, Op.UpdateRelativeDataInIndex2,
}

TXN_ACTIVE, TXN_PREPARED, TXN_COMMITTED = 1, 2, 3
ALLOCATED = 0xFFFFFFFF          # RESTART_TABLE entry 'next' when live


class ReplayError(Exception):
    pass


class _Tbl:
    '''A RESTART_TABLE materialized as {byte_offset: entry_bytes} — entries
       are addressed by their byte offset from the table start on disk.'''

    def __init__(self, blob: bytes | None):
        self.entry_size = 0
        self.entries: dict[int, bytearray] = {}
        if not blob or len(blob) < 0x18:
            return
        size, used, total = struct.unpack_from('<HHH', blob, 0)
        self.entry_size = size
        for i in range(total):
            off = 0x18 + i * size
            if off + size > len(blob):
                break
            e = blob[off:off + size]
            if struct.unpack_from('<I', e, 0)[0] == ALLOCATED:
                self.entries[off] = bytearray(e)

    def get(self, off: int) -> bytearray | None:
        return self.entries.get(off)

    def put(self, off: int, entry: bytes) -> bytearray:
        e = bytearray(entry)
        struct.pack_into('<I', e, 0, ALLOCATED)
        self.entries[off] = e
        return e

    def drop(self, off: int) -> None:
        self.entries.pop(off, None)


class LogReplay:
    def __init__(self, vol: ndf.RawVolumeRW):
        self.v = vol
        self.csz = vol._cluster_size
        size, self.log_runs = vol._stream_runs(2, ndf.AT_DATA, None)
        self.raw = bytearray(vol._runs_read(self.log_runs, 0, size))
        self.report = {'records': 0, 'redo_applied': 0, 'redo_skipped': 0,
                       'undo_applied': 0, 'txn_committed': 0, 'txn_undone': 0,
                       'warnings': []}
        self._parse_restart()
        self._fixup_pages()

    # ── restart selection ────────────────────────────────────────────────────

    def _parse_restart(self):
        cands = []
        for pg in (0, 1):
            page = bytearray(self.raw[pg * 4096:(pg + 1) * 4096])
            if page[:4] not in (RSTR_MAGIC, CHKD_MAGIC):
                continue
            if not ndf._apply_fixups(page):
                continue
            rh = RestartHdr.parse(page)
            ra = RestartArea.parse(page, rh.ra_off)
            cands.append((rh, ra, page))
        if not cands:
            raise ReplayError('no valid restart page')
        cands.sort(key=lambda t: t[1].current_lsn, reverse=True)
        # newest first; the older one is the fallback when the newest
        # checkpoint's pages never reached the disk before the crash
        self._restarts = cands
        self.rh, self.ra, rpage = cands[0]
        if (self.rh.major_ver, self.rh.minor_ver) not in ((1, 0), (1, 1), (2, 0)):
            raise ReplayError(f'unsupported log version '
                              f'{self.rh.major_ver}.{self.rh.minor_ver}')
        self.page_size = self.rh.page_size
        self.page_mask = self.page_size - 1
        self.l_size = self.ra.l_size
        self.seq_bits = self.ra.seq_num_bits
        self.data_bits = 64 - self.seq_bits
        self.data_off = self.ra.data_off        # first record offset in a page
        self.first_page = (0x22 * self.page_size if self.rh.major_ver >= 2
                           else 4 * self.page_size)
        if self.ra.client_idx_use == 0xFFFF:
            raise ReplayError('log is clean (no client in use)')
        self.client = ClientRec.parse(rpage, self.rh.ra_off + self.ra.client_off)
        if not self.client.restart_lsn:
            raise ReplayError('no client checkpoint (nothing to replay)')

    def _use_restart(self, idx: int) -> bool:
        '''Switch to restart candidate idx (0 = newest). False if absent.'''
        if idx >= len(self._restarts):
            return False
        self.rh, self.ra, rpage = self._restarts[idx]
        if self.ra.client_idx_use == 0xFFFF:
            return False
        self.client = ClientRec.parse(rpage, self.rh.ra_off + self.ra.client_off)
        return bool(self.client.restart_lsn)

    def _fixup_pages(self):
        '''Apply fixups to every record page and build the logical→physical
           page map. v2 logs never rewrite a page in place: each physical page
           carries the LOGICAL file offset it represents (file_off, 0x3C), and
           several physical pages may claim the same logical page — the one
           whose last_end_lsn is newest wins. v1 pages are identity-mapped
           (tail-copy reconciliation not implemented).'''
        self.page_map: dict[int, int] = {}
        best_end: dict[int, int] = {}
        for off in range(2 * self.page_size, self.l_size, self.page_size):
            page = self.raw[off:off + self.page_size]
            if page[:4] != RCRD_MAGIC:
                continue
            page = bytearray(page)
            if not ndf._apply_fixups(page):
                continue
            self.raw[off:off + self.page_size] = page
            if self.rh.major_ver >= 2:
                logical = struct.unpack_from('<I', page, 0x3C)[0]
            else:
                logical = off
            end_lsn = struct.unpack_from('<Q', page, 0x20)[0]   # last_end_lsn
            if logical not in self.page_map or end_lsn >= best_end[logical]:
                self.page_map[logical] = off
                best_end[logical] = end_lsn

    def _phys(self, logical_page: int) -> int | None:
        return self.page_map.get(logical_page)

    # ── LSN / stream math ────────────────────────────────────────────────────

    def lsn_vbo(self, lsn: int) -> int:
        return ((lsn << self.seq_bits) & ((1 << 64) - 1)) >> (self.seq_bits - 3)

    def _stream_read(self, vbo: int, n: int) -> tuple[bytes, int]:
        '''Read n log-stream bytes starting at LOGICAL offset vbo, skipping
           page headers; returns (data, vbo_after). Raises on a bad page.'''
        out = bytearray()
        while n > 0:
            page = vbo & ~self.page_mask
            off = vbo & self.page_mask
            phys = self._phys(page)
            if page < self.first_page or phys is None:
                raise ReplayError(f'walk entered unmapped page {page:#x}')
            if off < self.data_off:
                off = self.data_off
                vbo = page + off
            take = min(n, self.page_size - off)
            out += self.raw[phys + off:phys + off + take]
            n -= take
            vbo = page + self.page_size
            if vbo >= self.l_size:
                vbo = self.first_page
        return bytes(out), vbo if n else (page + off + take if take else vbo)

    def _advance(self, vbo: int, n: int) -> int:
        '''Position after skipping n stream bytes from vbo.'''
        while True:
            page = vbo & ~self.page_mask
            off = vbo & self.page_mask
            if off < self.data_off:
                off = self.data_off
            room = self.page_size - off
            if n < room:
                return page + off + n
            n -= room
            page += self.page_size
            if page >= self.l_size:
                page = self.first_page
            vbo = page + self.data_off

    def read_record(self, lsn: int):
        '''(LfsRecordHdr, payload bytes) for the record at LSN, or None.'''
        # NB: an earlier "harden the walk with RECORD_PAGE_HDR.next_record_offset
        # (u16 @ 0x18)" guard — cross-checked against ntfs-core's version-agnostic
        # parse_log_records — was REVERTED: on real v2 pages it truncated the walk
        # 197 -> 15 records. v2 shifts the page header (file_off @ 0x3C,
        # last_end_lsn @ 0x20), so 0x18 is not the first-free-byte here. The
        # position-reconstruction walk that stops on a this_lsn mismatch is
        # correct; do not re-add a 0x18 bound without a v2-specific offset.
        vbo = self.lsn_vbo(lsn)
        try:
            blob, _ = self._stream_read(vbo, LfsRecordHdr.HDR_LEN)
            frh = LfsRecordHdr.parse(blob, 0)
            if frh.this_lsn != lsn:
                return None
            if not 0 < frh.client_data_len < self.l_size:
                return None
            body = self._advance(vbo, LfsRecordHdr.HDR_LEN)
            payload, _ = self._stream_read(body, frh.client_data_len)
            return frh, payload
        except ReplayError:
            return None

    def records_from(self, lsn: int):
        '''Yield (lsn, LfsRecordHdr, payload) forward until the true end of
           the log. The restart page's current_lsn is only a periodic
           snapshot — the tail runs until a position's stored this_lsn no
           longer matches the expected LSN (older-sequence data).'''
        walked = 0
        while True:
            got = self.read_record(lsn)
            if got is None:
                return
            frh, payload = got
            yield lsn, frh, payload
            walked += LfsRecordHdr.HDR_LEN + frh.client_data_len
            if walked > 2 * self.l_size:          # safety: never loop forever
                return
            end = self._advance(self.lsn_vbo(lsn),
                                LfsRecordHdr.HDR_LEN + frh.client_data_len)
            end = (end + 7) & ~7
            off = end & self.page_mask
            if self.page_size - off < LfsRecordHdr.HDR_LEN:
                page = (end & ~self.page_mask) + self.page_size
                if page >= self.l_size:
                    page = self.first_page
                end = page + self.data_off
            # candidate LSN carrying the right sequence for this position
            nxt = (end >> 3) | (frh.this_lsn & ~((1 << self.data_bits) - 1))
            if nxt <= lsn:
                nxt += 1 << self.data_bits        # wrapped: sequence advances
            lsn = nxt

    # ── checkpoint ───────────────────────────────────────────────────────────

    def _table_dump(self, lsn: int, length: int) -> bytes | None:
        if not lsn or not length:
            return None
        got = self.read_record(lsn)
        if got is None:
            return None
        _frh, payload = got
        lrh = LogRecHdr.parse(payload, 0)
        return payload[lrh.redo_off:lrh.redo_off + lrh.redo_len]

    def load_checkpoint(self):
        '''Load the newest checkpoint whose record AND table dumps are all
           readable; a crash can leave the newest restart pointing at pages
           that never reached the disk — the previous restart still works.'''
        last_err = None
        for idx in range(len(self._restarts)):
            if idx and not self._use_restart(idx):
                break
            try:
                self._load_checkpoint_tables()
                if idx:
                    self.report['warnings'].append(
                        'newest checkpoint unreadable — used the previous one')
                return
            except ReplayError as e:
                last_err = e
        raise last_err or ReplayError('client checkpoint record unreadable')

    def _load_checkpoint_tables(self):
        got = self.read_record(self.client.restart_lsn)
        if got is None:
            raise ReplayError('client checkpoint record unreadable')
        frh, payload = got
        if frh.record_type != LfsClientRestart:
            raise ReplayError('checkpoint record has wrong type')
        (major, _minor, cp_start, oat_lsn, names_lsn, dp_lsn, tt_lsn,
         oat_len, names_len, dp_len, tt_len) = struct.unpack_from(
            '<IIQQQQQIIII', payload, 0)
        self.rst_major = major
        self.attr_entry_size = 0x2C if major == 0 else 0x28
        self.checkpoint_start = cp_start or self.client.restart_lsn
        dumps = []
        for lsn, length in ((tt_lsn, tt_len), (dp_lsn, dp_len),
                            (oat_lsn, oat_len), (names_lsn, names_len)):
            blob = self._table_dump(lsn, length)
            if length and blob is None:
                raise ReplayError('checkpoint table dump unreadable')
            dumps.append(blob)
        self.trtbl = _Tbl(dumps[0])
        self.dptbl = _Tbl(dumps[1])
        self.oatbl = _Tbl(dumps[2])
        self.attr_names = dumps[3]

    # open-attribute entry accessors (v0 = 32-bit layout, v1 = 64-bit)
    def _oa_ref_type(self, e: bytes) -> tuple[int, int]:
        if self.rst_major == 0:
            ref = struct.unpack_from('<Q', e, 0x08)[0]
            atype = struct.unpack_from('<I', e, 0x1C)[0]
        else:
            atype = struct.unpack_from('<I', e, 0x08)[0]
            ref = struct.unpack_from('<Q', e, 0x10)[0]
        return ref, atype

    def _oa_bytes_per_index(self, e: bytes) -> int:
        return struct.unpack_from('<I', e, 0x28 if self.rst_major == 0 else 0x04)[0]

    # dirty-page entry accessors
    def _dp_parse(self, e: bytes):
        if self.rst_major == 0:
            target = struct.unpack_from('<I', e, 4)[0]
            vcn = struct.unpack_from('<Q', e, 0x14)[0]
            oldest = struct.unpack_from('<Q', e, 0x1C)[0]
        else:
            target = struct.unpack_from('<I', e, 4)[0]
            vcn, oldest = struct.unpack_from('<QQ', e, 0x10)
        return target, vcn, oldest

    # ── analysis pass ────────────────────────────────────────────────────────

    def analyze(self):
        self.load_checkpoint()
        clst_per_page = max(self.page_size // self.csz, 1)
        rlsn = 0
        for lsn, frh, payload in self.records_from(self.checkpoint_start):
            self.report['records'] += 1
            if not rlsn:
                rlsn = lsn
            if frh.record_type != LfsClientRecord:
                continue
            lrh = LogRecHdr.parse(payload, 0)
            tid = frh.transact_id
            tr = self.trtbl.get(tid)
            if tr is None:
                tr = self.trtbl.put(tid, bytes(0x28))
                tr[4] = TXN_ACTIVE
                struct.pack_into('<Q', tr, 0x08, lsn)     # first_lsn
            struct.pack_into('<Q', tr, 0x10, lsn)         # prev_lsn
            struct.pack_into('<Q', tr, 0x18, lsn)         # undo_next_lsn
            if lrh.undo_op == Op.CompensationLogRecord:
                struct.pack_into('<Q', tr, 0x18, frh.client_undo_next_lsn)
            op = lrh.redo_op
            if op == Op.PrepareTransaction:
                tr[4] = TXN_PREPARED
            elif op == Op.CommitTransaction:
                tr[4] = TXN_COMMITTED
            elif op == Op.ForgetTransaction:
                self.trtbl.drop(tid)
            elif op == Op.OpenNonresidentAttribute:
                self.oatbl.put(lrh.target_attr,
                               payload[lrh.redo_off:
                                       lrh.redo_off + self.attr_entry_size]
                               .ljust(self.attr_entry_size, b'\0'))
            elif op in _PAGE_OPS:
                page_vcn = lrh.target_vcn & ~(clst_per_page - 1)
                key = None
                for off, e in self.dptbl.entries.items():
                    t, vcn, _old = self._dp_parse(e)
                    if t == lrh.target_attr and vcn <= lrh.target_vcn < vcn + clst_per_page:
                        key = off
                        break
                if key is None:
                    e = bytearray(0x20 + 8 * clst_per_page)
                    struct.pack_into('<I', e, 4, lrh.target_attr)
                    struct.pack_into('<I', e, 8, clst_per_page * self.csz)
                    struct.pack_into('<I', e, 0x0C, clst_per_page)
                    struct.pack_into('<Q', e, 0x10, page_vcn)
                    struct.pack_into('<Q', e, 0x18, lsn)
                    key = 0x10000 + len(self.dptbl.entries) * 8  # synthetic slot
                    self.dptbl.put(key, bytes(e))
                dp = self.dptbl.get(key)
                _t, dvcn, _old = self._dp_parse(dp)
                for i in range(lrh.lcns_follow):
                    lcn = struct.unpack_from('<Q', payload, 32 + 8 * i)[0]
                    slot = lrh.target_vcn + i - dvcn
                    if 0 <= slot < clst_per_page and len(dp) >= 0x20 + 8 * (slot + 1):
                        struct.pack_into('<Q', dp, 0x20 + 8 * slot, lcn)
        # redo LSN = oldest thing anyone still needs
        self.redo_lsn = rlsn or self.checkpoint_start
        for e in self.dptbl.entries.values():
            _t, _v, old = self._dp_parse(e)
            if old and old < self.redo_lsn:
                self.redo_lsn = old
        for e in self.trtbl.entries.values():
            first = struct.unpack_from('<Q', e, 8)[0]
            if first and first < self.redo_lsn:
                self.redo_lsn = first
        self.report['txn_committed'] = sum(
            1 for e in self.trtbl.entries.values() if e[4] == TXN_COMMITTED)
        self.report['txn_open'] = sum(
            1 for e in self.trtbl.entries.values() if e[4] != TXN_COMMITTED)
        self.report['dirty_pages'] = len(self.dptbl.entries)
        return self.report

    # ── target page IO ───────────────────────────────────────────────────────

    def _clusters_read(self, lcns: list[int]) -> bytearray:
        out = bytearray()
        for lcn in lcns:
            out += ndf._pread(self.v._fd, self.csz, self.v._base + lcn * self.csz)
        return out

    def _clusters_write(self, lcns: list[int], buf: bytes) -> None:
        for i, lcn in enumerate(lcns):
            chunk = bytes(buf[i * self.csz:(i + 1) * self.csz])
            ndf._pwrite(self.v._fd, chunk, self.v._base + lcn * self.csz)

    # ── op application (shared by redo and undo) ─────────────────────────────

    def _apply(self, lsn: int, lrh, payload: bytes, op: int,
               data: bytes, gate: bool) -> bool:
        '''Apply one operation; returns True if a page was modified.'''
        vbo = lrh.target_vcn * self.csz + lrh.cluster_off * SECTOR
        if op in _MFT_OPS:
            return self._apply_mft(lsn, lrh, op, data, vbo, gate)
        return self._apply_page(lsn, lrh, payload, op, data, gate)

    def _apply_mft(self, lsn, lrh, op, data, vbo, gate) -> bool:
        rec_no = vbo // self.v._rec_size
        # Logical form is mandatory here: log records describe the UNSEALED
        # record image, and write_record seals on the way out. _load_record
        # applies the fixups; the raw read_record hands back the SEALED bytes,
        # and modify-then-reseal on those captures the OLD USN into the USA as
        # if it were data — two garbage bytes at every sector tail (0x1FE /
        # 0x3FE), visible only when a real field straddles one (found via
        # $RmMetadata\$Repair:$Verify allocated_size = 0x19 << 48 | true size).
        rec = self.v._load_record(rec_no)
        if rec is None:
            if op != Op.InitializeFileRecordSegment:
                self.report['warnings'].append(
                    f'{OP_NAME.get(op, op)}: record {rec_no} unreadable')
                return False
            rec = bytearray(self.v._rec_size)
        rec = bytearray(rec)
        page_lsn = struct.unpack_from('<Q', rec, 8)[0] if rec[:4] == b'FILE' else 0
        if gate and page_lsn >= lsn:
            return False
        roff, aoff, dlen = lrh.record_off, lrh.attr_off, len(data)
        rs = self.v._rec_size

        def used():
            return struct.unpack_from('<I', rec, 0x18)[0]

        def set_used(n):
            struct.pack_into('<I', rec, 0x18, n)

        a = roff                                       # attribute position
        if op == Op.InitializeFileRecordSegment:
            if roff + dlen > rs:
                return False
            rec[roff:roff + dlen] = data
        elif op == Op.DeallocateFileRecordSegment:
            flags = struct.unpack_from('<H', rec, 22)[0]
            struct.pack_into('<H', rec, 22, flags & ~1)
            seq = struct.unpack_from('<H', rec, 16)[0]
            struct.pack_into('<H', rec, 16, (seq + 1) & 0xFFFF)
        elif op == Op.WriteEndOfFileRecordSegment:
            if roff + dlen > rs:
                return False
            rec[a:a + dlen] = data
            set_used((roff + dlen + 7) & ~7)
        elif op == Op.CreateAttribute:
            asize = struct.unpack_from('<I', data, 4)[0] if dlen >= 8 else 0
            if not asize or asize % 8 or used() + asize > rs:
                return False
            u = used()
            rec[a + asize:u + asize] = rec[a:u]
            rec[a:a + asize] = data[:asize]
            set_used(u + asize)
            nid = struct.unpack_from('<H', rec, 0x28)[0]
            aid = struct.unpack_from('<H', data, 0x0E)[0]
            if nid <= aid:
                struct.pack_into('<H', rec, 0x28, aid + 1)
            if struct.unpack_from('<I', data, 0)[0] == ndf.AT_FILE_NAME:
                links = struct.unpack_from('<H', rec, 18)[0]
                struct.pack_into('<H', rec, 18, links + 1)
        elif op == Op.DeleteAttribute:
            asize = struct.unpack_from('<I', rec, a + 4)[0]
            u = used()
            if struct.unpack_from('<I', rec, a)[0] == ndf.AT_FILE_NAME:
                links = struct.unpack_from('<H', rec, 18)[0]
                struct.pack_into('<H', rec, 18, max(0, links - 1))
            rec[a:u - asize] = rec[a + asize:u]
            rec[u - asize:u] = bytes(asize)
            set_used(u - asize)
        elif op == Op.UpdateResidentValue:
            asize = struct.unpack_from('<I', rec, a + 4)[0]
            if lrh.redo_len == lrh.undo_len:           # in-place overwrite
                if aoff + dlen > asize:
                    return False
                rec[a + aoff:a + aoff + dlen] = data
            else:                                       # resize
                nsize = (aoff + dlen + 7) & ~7
                u = used()
                if nsize > asize and nsize - asize > rs - u:
                    return False
                data_off = struct.unpack_from('<H', rec, a + 0x14)[0]
                if aoff < data_off or aoff + dlen < data_off:
                    return False
                tail = bytes(rec[a + asize:u])
                if nsize < asize:
                    rec[a + aoff:a + aoff + dlen] = data
                rec[a + nsize:a + nsize + len(tail)] = tail
                for i in range(a + nsize + len(tail), u):
                    rec[i] = 0
                set_used(u + nsize - asize)
                struct.pack_into('<I', rec, a + 4, nsize)
                struct.pack_into('<I', rec, a + 0x10, aoff + dlen - data_off)
                if nsize >= asize:
                    rec[a + aoff:a + aoff + dlen] = data
        elif op == Op.UpdateMappingPairs:
            asize = struct.unpack_from('<I', rec, a + 4)[0]
            run_off = struct.unpack_from('<H', rec, a + 0x20)[0]
            u = used()
            if aoff < run_off or aoff > asize:
                return False
            nsize = (aoff + dlen + 7) & ~7
            if nsize > asize and nsize - asize > rs - u:
                return False
            tail = bytes(rec[a + asize:u])
            rec[a + nsize:a + nsize + len(tail)] = tail
            for i in range(a + nsize + len(tail), u):
                rec[i] = 0
            set_used(u + nsize - asize)
            struct.pack_into('<I', rec, a + 4, nsize)
            rec[a + aoff:a + aoff + dlen] = data
            # recompute evcn from the (svcn + runlist) now in place
            svcn = struct.unpack_from('<q', rec, a + 0x10)[0]
            total, pos = 0, a + run_off
            while pos < a + nsize and rec[pos]:
                h = rec[pos]
                ls, os_ = h & 0xF, h >> 4
                total += int.from_bytes(rec[pos + 1:pos + 1 + ls], 'little',
                                        signed=True)
                pos += 1 + ls + os_
            struct.pack_into('<q', rec, a + 0x18, svcn + total - 1)
        elif op == Op.SetNewAttributeSizes:
            alloc, valid, dsz = struct.unpack_from('<QQQ', data, 0)
            struct.pack_into('<Q', rec, a + 0x28, alloc)
            struct.pack_into('<Q', rec, a + 0x30, dsz)
            struct.pack_into('<Q', rec, a + 0x38, valid)
            if len(data) >= 32:
                struct.pack_into('<Q', rec, a + 0x40, struct.unpack_from('<Q', data, 24)[0])
        elif op == Op.ZeroEndOfFileRecord:
            if roff + dlen > rs:
                return False
            for i in range(roff, roff + dlen):
                rec[i] = 0
        elif op in (Op.AddIndexEntryRoot, Op.DeleteIndexEntryRoot,
                    Op.SetIndexEntryVcnRoot, Op.UpdateFileNameRoot,
                    Op.UpdateRecordDataRoot):
            if not self._apply_root_index(rec, a, aoff, op, data):
                return False
        else:
            return False
        struct.pack_into('<Q', rec, 8, lsn)             # stamp page LSN
        self.v.write_record(rec_no, rec)
        return True

    def _apply_root_index(self, rec, a, aoff, op, data) -> bool:
        '''Index ops against the resident $INDEX_ROOT attribute at rec[a].'''
        vofs = struct.unpack_from('<H', rec, a + 0x14)[0]
        ih = a + vofs + 16                              # INDEX_HEADER
        used = struct.unpack_from('<I', rec, ih + 4)[0]
        e1 = a + aoff                                   # target entry position
        if op == Op.AddIndexEntryRoot:
            esize = struct.unpack_from('<H', data, 8)[0]
            asize = struct.unpack_from('<I', rec, a + 4)[0]
            ru = struct.unpack_from('<I', rec, 0x18)[0]
            if not esize or ru + esize > self.v._rec_size:
                return False
            tail = bytes(rec[a + asize:ru])             # grow the attribute
            rec[a + asize + esize:a + asize + esize + len(tail)] = tail
            struct.pack_into('<I', rec, a + 4, asize + esize)
            struct.pack_into('<I', rec, 0x18, ru + esize)
            vlen = struct.unpack_from('<I', rec, a + 0x10)[0]
            struct.pack_into('<I', rec, a + 0x10, vlen + esize)
            end = ih + used
            rec[e1 + esize:end + esize] = rec[e1:end]
            rec[e1:e1 + esize] = data[:esize]
            struct.pack_into('<I', rec, ih + 4, used + esize)
            total = struct.unpack_from('<I', rec, ih + 8)[0]
            struct.pack_into('<I', rec, ih + 8, total + esize)
        elif op == Op.DeleteIndexEntryRoot:
            esize = struct.unpack_from('<H', rec, e1 + 8)[0]
            if not esize or e1 + esize > ih + used:
                return False
            end = ih + used
            rec[e1:end - esize] = rec[e1 + esize:end]
            asize = struct.unpack_from('<I', rec, a + 4)[0]
            ru = struct.unpack_from('<I', rec, 0x18)[0]
            tail = bytes(rec[a + asize:ru])
            rec[a + asize - esize:a + asize - esize + len(tail)] = tail
            for i in range(a + asize - esize + len(tail), ru):
                rec[i] = 0
            struct.pack_into('<I', rec, a + 4, asize - esize)
            struct.pack_into('<I', rec, 0x18, ru - esize)
            vlen = struct.unpack_from('<I', rec, a + 0x10)[0]
            struct.pack_into('<I', rec, a + 0x10, vlen - esize)
            struct.pack_into('<I', rec, ih + 4, used - esize)
            total = struct.unpack_from('<I', rec, ih + 8)[0]
            struct.pack_into('<I', rec, ih + 8, total - esize)
        elif op == Op.SetIndexEntryVcnRoot:
            esize = struct.unpack_from('<H', rec, e1 + 8)[0]
            rec[e1 + esize - 8:e1 + esize] = data[:8]
        elif op == Op.UpdateFileNameRoot:
            rec[e1 + 16 + 8:e1 + 16 + 8 + len(data)] = data   # FN dup-info
        elif op == Op.UpdateRecordDataRoot:
            doff = struct.unpack_from('<H', rec, e1)[0]
            rec[e1 + doff:e1 + doff + len(data)] = data
        return True

    def _apply_page(self, lsn, lrh, payload, op, data, gate) -> bool:
        '''Ops against a non-resident page addressed by the record's LCNs.'''
        if not lrh.lcns_follow:
            return False
        lcns = [struct.unpack_from('<Q', payload, 32 + 8 * i)[0]
                for i in range(lrh.lcns_follow)]
        if not all(lcns):
            return False
        buf = self._clusters_read(lcns)
        base = lrh.cluster_off * SECTOR
        roff, aoff, dlen = lrh.record_off, lrh.attr_off, len(data)
        is_indx = op in (Op.AddIndexEntryAllocation, Op.DeleteIndexEntryAllocation,
                         Op.WriteEndOfIndexBuffer, Op.SetIndexEntryVcnAllocation,
                         Op.UpdateFileNameAllocation, Op.UpdateRecordDataAllocation)
        if is_indx:
            ib = base + roff
            blk = bytearray(buf[ib:])
            if blk[:4] != b'INDX':
                self.report['warnings'].append(
                    f'{OP_NAME.get(op, op)}: INDX target absent')
                return False
            # A prior redo may have written this page in LOGICAL (unsealed) form
            # — NTFS logs INDX pages with the multi-sector fixup NOT applied, so
            # an UpdateNonresidentValue that laid down a fresh INDX block leaves
            # the sector tails holding real data (tails != USN). Un-seal a real
            # on-disk (sealed) block; accept an already-logical one as-is. Either
            # way we _seal_fixups on write below, so the final block is valid.
            probe = bytearray(blk)
            if ndf._apply_fixups(probe):
                blk = probe                       # was sealed on disk → now logical
            page_lsn = struct.unpack_from('<Q', blk, 8)[0]
            if gate and page_lsn >= lsn:
                return False
            ih = 0x18
            used = struct.unpack_from('<I', blk, ih + 4)[0]
            e1 = aoff
            if op == Op.AddIndexEntryAllocation:
                esize = struct.unpack_from('<H', data, 8)[0]
                total = struct.unpack_from('<I', blk, ih + 8)[0]
                if not esize or used + esize > total:
                    return False
                end = ih + used
                blk[e1 + esize:end + esize] = blk[e1:end]
                blk[e1:e1 + esize] = data[:esize]
                struct.pack_into('<I', blk, ih + 4, used + esize)
            elif op == Op.DeleteIndexEntryAllocation:
                esize = struct.unpack_from('<H', blk, e1 + 8)[0]
                end = ih + used
                if not esize or e1 + esize > end:
                    return False
                blk[e1:end - esize] = blk[e1 + esize:end]
                struct.pack_into('<I', blk, ih + 4, used - esize)
            elif op == Op.WriteEndOfIndexBuffer:
                blk[e1:e1 + dlen] = data
                struct.pack_into('<I', blk, ih + 4, e1 + dlen - ih)
            elif op == Op.SetIndexEntryVcnAllocation:
                esize = struct.unpack_from('<H', blk, e1 + 8)[0]
                blk[e1 + esize - 8:e1 + esize] = data[:8]
            elif op == Op.UpdateFileNameAllocation:
                blk[e1 + 16 + 8:e1 + 16 + 8 + dlen] = data
            elif op == Op.UpdateRecordDataAllocation:
                doff = struct.unpack_from('<H', blk, e1)[0]
                blk[e1 + doff:e1 + doff + dlen] = data
            struct.pack_into('<Q', blk, 8, lsn)
            ndf._seal_fixups(blk)
            buf[ib:ib + len(blk)] = blk
        elif op in (Op.SetBitsInNonresidentBitMap, Op.ClearBitsInNonresidentBitMap):
            bit_off, bits = struct.unpack_from('<II', data, 0)
            p = base + roff
            for b in range(bit_off, bit_off + bits):
                if p + (b >> 3) >= len(buf):
                    return False
                if op == Op.SetBitsInNonresidentBitMap:
                    buf[p + (b >> 3)] |= 1 << (b & 7)
                else:
                    buf[p + (b >> 3)] &= ~(1 << (b & 7))
        elif op == Op.UpdateNonresidentValue:
            p = base + roff
            if p + dlen > len(buf):
                return False
            buf[p:p + dlen] = data
        else:
            return False
        self._clusters_write(lcns, buf)
        return True

    # ── redo + undo ──────────────────────────────────────────────────────────

    def redo(self):
        clst_per_page = max(self.page_size // self.csz, 1)
        for lsn, frh, payload in self.records_from(self.redo_lsn):
            if frh.record_type != LfsClientRecord:
                continue
            lrh = LogRecHdr.parse(payload, 0)
            op = lrh.redo_op
            if op in _SKIP_OPS or op not in _PAGE_OPS or not lrh.lcns_follow:
                continue
            hit = None
            for e in self.dptbl.entries.values():
                t, vcn, old = self._dp_parse(e)
                if (t == lrh.target_attr and
                        vcn <= lrh.target_vcn < vcn + clst_per_page):
                    hit = old
                    break
            if hit is None or lsn < hit:
                self.report['redo_skipped'] += 1
                continue
            data = payload[lrh.redo_off:lrh.redo_off + lrh.redo_len]
            if self._apply(lsn, lrh, payload, op, data, gate=True):
                self.report['redo_applied'] += 1
            else:
                self.report['redo_skipped'] += 1

    def undo(self):
        for tid, tr in list(self.trtbl.entries.items()):
            if tr[4] == TXN_COMMITTED:
                continue
            self.report['txn_undone'] += 1
            lsn = struct.unpack_from('<Q', tr, 0x18)[0]   # undo_next_lsn
            while lsn:
                got = self.read_record(lsn)
                if got is None:
                    break
                frh, payload = got
                lrh = LogRecHdr.parse(payload, 0)
                op = lrh.undo_op
                if op not in _SKIP_OPS and op in _PAGE_OPS:
                    data = payload[lrh.undo_off:lrh.undo_off + lrh.undo_len]
                    if self._apply(lsn, lrh, payload, op, data, gate=False):
                        self.report['undo_applied'] += 1
                if lrh.undo_op == Op.CompensationLogRecord:
                    lsn = frh.client_undo_next_lsn
                else:
                    lsn = frh.client_prev_lsn
                if lsn and lsn < self.client.oldest_lsn:
                    break

    def finalize(self):
        '''Mark the log clean (the 0xFF reset chkdsk accepts) + clear dirty.'''
        self.v.reset_logfile()
        self.v.clear_dirty()


def replay(path: str, really: bool) -> dict:
    # A dry run only reads (analysis works on an in-memory copy of the log), so
    # open read-only — otherwise RawVolumeRW's open/close $MFTMirr sync would
    # write a handful of bytes and a "dry run" would not be one. The write
    # passes (redo/undo/finalize) need the RW volume.
    vol_cls = ndf.RawVolumeRW if really else ndf.RawVolume
    with vol_cls(path) as v:
        lr = LogReplay(v)
        lr.analyze()
        if really:
            lr.redo()
            lr.undo()
            lr.finalize()
        return lr.report


def main(argv):
    if not argv or argv[0].startswith('-'):
        print(__doc__)
        return 2
    path = argv[0]
    really = '--really' in argv[1:]
    try:
        rep = replay(path, really)
    except ReplayError as e:
        print(f'no replay: {e}')
        return 1
    for k, v in rep.items():
        if k != 'warnings':
            print(f'{k:14} {v}')
    for w in rep['warnings'][:20]:
        print('  !', w)
    if not really:
        print('(dry run — use --really to apply)')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
