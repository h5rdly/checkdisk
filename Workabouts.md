## The volume at a glance

An NTFS volume is bootstrapped from a single sector and then becomes entirely
self-describing — **everything is a file**, including all metadata.

The **boot sector** (`RawVolume.__init__`) carries:

| offset | field | note |
|-------:|-------|------|
| 3      | `"NTFS"` magic | |
| 11     | bytes/sector (u16) | almost always 512 |
| 13     | sectors/cluster (u8) | values > 0x80 encode `2^(256-x)` |
| 40     | total sectors (u64) | |
| 48     | LCN of $MFT (u64) | where record 0 lives |
| 64     | MFT record size (s8) | negative → `2^-x` bytes (typically −10 = 1024); positive → clusters |

The first 24 MFT records are reserved for system files. The ones this tool
touches:

| # | file | role |
|--:|------|------|
| 0 | `$MFT` | the Master File Table itself — one record per file |
| 1 | `$MFTMirr` | mirror of the first 4 records (drivers verify it) |
| 2 | `$LogFile` | metadata journal (see §6) |
| 3 | `$Volume` | volume flags — including the **dirty bit** |
| 5 | `.` (root) | root directory |
| 6 | `$Bitmap` | one bit per cluster: allocated or free (§7) |
| 9 | `$Secure` | all security descriptors, deduplicated (§5) |
| 10 | `$UpCase` | 64K-entry uppercasing table — defines case-insensitivity (§4) |
| 11 | `$Extend` | directory holding `$UsnJrnl`, `$Reparse`, `$ObjId`, `$Quota` |

Addresses are **LCN** (logical cluster number, volume-absolute) or **VCN**
(virtual cluster number, position within one file's data). Runlists map VCN→LCN.

## MFT records and attributes

### The FILE record

Each file is a fixed-size **FILE record** (`read_record`, `_load_record`):

| offset | field |
|-------:|-------|
| 0  | `"FILE"` magic |
| 4  | update-sequence array offset / count (fixups, below) |
| 16 | **sequence number** — bumped every time the record is freed |
| 18 | hard-link count |
| 20 | first-attribute offset |
| 22 | flags: bit 0 = in use, bit 1 = directory |
| 32 | base-record reference (non-zero ⇒ this is an *extension* record) |

A **file reference (mref)** is 64 bits: low 48 = record number, high 16 = the
sequence number *at the time the reference was made* (`MREF_MASK`). This is
NTFS's stale-pointer defence: when a record is reused, its sequence changes,
and every old reference to it becomes detectably stale. Half the repairs in
this tool reduce to "does the sequence still match?" (`_mref_live`).

### Multi-sector fixups — how NTFS detects torn writes

Any structure larger than a sector (FILE records, INDX blocks) is protected by
the **update sequence array**: before writing, the last 2 bytes of every sector
are stashed in the header's USA and replaced by a counter (USN); the counter is
bumped each write. On read, all sector tails must equal the USN — if the disk
died mid-write, some sectors are old and some new, the tails disagree, and the
record is **torn** (`_apply_fixups` / inverse `_seal_fixups`). Torn = the
strongest possible corruption signal: the structure's content cannot be
trusted at all.

The seal/unseal pair is also a bug magnet for anything that *writes* these
structures, and the failure has a recognizable fingerprint. Re-seal a buffer
that was never unsealed and the stale USN gets captured into the USA as if it
were data: exactly two garbage bytes at each sector-tail offset (0x1FE, 0x3FE,
…), typically equal to a recent USN, with every other byte intact. Corruption
confined to those offsets means a mis-sealed writer, not random damage — worth
checking before blaming the disk.

### Attributes

A record's content is a chain of **attributes** (`_attrs` walks it): each has a
type, length, optional UTF-16LE name, and is **resident** (value inline in the
record) or **non-resident** (value on clusters, located by a runlist). The
chain ends with type `0xFFFFFFFF`. Types used here: `$STANDARD_INFORMATION`
(0x10, holds the security_id at value offset 52), `$ATTRIBUTE_LIST` (0x20),
`$FILE_NAME` (0x30), `$OBJECT_ID` (0x40), `$DATA` (0x80), `$INDEX_ROOT` (0x90),
`$INDEX_ALLOCATION` (0xA0), `$BITMAP` (0xB0), `$REPARSE_POINT` (0xC0).

`$FILE_NAME` is the linchpin of repair: it stores the parent directory's mref
(offset 0), name length (64), namespace (65: POSIX/WIN32/DOS), and the name
(66). **The same fact exists twice** — in the file's record *and* in the
parent's index — and that redundancy is what makes directory repair possible.

### Runlists (mapping pairs)

Non-resident data is described by a compact varint encoding
(`_check_mapping_pairs` decodes + validates, `_encode_mapping_pairs` builds):
each pair is a header byte (low nibble = length-field size, high nibble =
offset-field size), a run length, and an LCN **delta from the previous run**
(signed). **Both fields are signed**, the length included: a 128-cluster run
must encode its length as two bytes (`80 00`) — a lone `80` sign-extends to
−128 and every NTFS implementation then rejects the whole runlist. Offset
size 0 = sparse run (a hole). A zero header byte terminates.
The attribute header redundantly states `lowest_vcn`/`highest_vcn` — the
decoded runs must cover exactly that range, another self-check this tool
leans on.

### Extension records and $ATTRIBUTE_LIST

When one record can't hold all attributes, they spill into **extension
records**; a resident-or-not `$ATTRIBUTE_LIST` in the base enumerates where
every attribute lives (`_record_attrs_uncached` follows it transparently;
`_spill_index_alloc` performs the spill natively when a directory outgrows its
base record).

## Indexes — the B+ trees

A directory is not a list; it's a **B+ tree keyed by name**. Three attributes
cooperate (all named `$I30` for directories):

- `$INDEX_ROOT` (resident): header (collation rule, index block size) + the
  root node. A *small* index is just this.
- `$INDEX_ALLOCATION` (non-resident): the **INDX blocks** — 4 KiB fixup-
  protected nodes (`"INDX"` magic, header VCN at offset 16, INDEX_HEADER at 24).
- `$BITMAP`: one bit per INDX block — allocated blocks whose bit is clear are
  free and may contain stale garbage legally.

A node is a run of **INDEX_ENTRY** structures: `{value, entry_len(8),
key_len(10), flags(12)}` with the key at offset 16. Flags: bit 0 = has a
subnode (its VCN sits in the entry's **last 8 bytes**), bit 1 = END entry (no
key; terminates the node; its subnode pointer, if any, covers everything
greater than the last key). Directory entries store the child's mref as the
value at offset 0; the key is the **entire `$FILE_NAME` attribute value**.

Ordering is `COLLATION_FILE_NAME` (0x01): compare names **uppercased through
the volume's own `$UpCase` table**, not through any programming language's
notion of case (`_upcase_seq`, `names_equal`). A prefix sorts first.

That table is more load-bearing than it looks: **Windows chkdsk silently
skips its entire index verification stage on a volume whose `$UpCase` is not
the exact frozen table it expects** — no warning, exit 0. The frozen table
predates modern Unicode: characters that gained uppercase mappings later map
to *themselves* on real volumes, and the iota-subscript vocalics map to their
titlecase forms.


## The journals

- **`$LogFile`** is a metadata write-ahead log. This tool — like chkdsk —
  **resets it rather than replaying it** (`reset_logfile` fills it with
  `0xFF`): the structural checks reconcile the on-disk state directly, which
  makes replay redundant, and a reset log is unambiguously clean.
- The **dirty bit** lives in `$Volume`'s `$VOLUME_INFORMATION` (flags bit 0).
  The write engine *sets it on open and clears it on clean close*
  (`RawVolumeRW.__init__`/`close`) so that a crash mid-repair leaves the
  volume flagged for a full check — the same discipline the driver uses.
- **`$UsnJrnl`** (`\$Extend\$UsnJrnl`) is the *user-visible* change journal:
  `$Max` (32 bytes: max size, allocation delta, journal id, LowestValidUsn)
  and `$J`, an append-only sparse stream whose **byte offset is the USN**.
  Old content is punched out with sparse holes, so the file's allocated tail
  is the live window. Each V2 record self-states its USN at offset 24 — it
  must equal the record's own position (`_walk_usn_records`).

### What `$LogFile` replay actually does (research)

The `$LogFile` is an LFS (Log File Service) circular log of two page kinds: the
first two 4 KiB pages are **restart pages** (`RSTR`) holding a checkpoint pointer
plus per-client state; the rest are **record pages** (`RCRD`) carrying the log
records. A driver's crash recovery is three passes from the last checkpoint:

- **restart selection** — take the restart page with the higher `current_lsn`;
  the other is a stale backup (fall back to it if the newest checkpoint's own
  pages never reached the disk).
- **analysis** — rebuild the transaction / dirty-page / open-attribute tables
  from the checkpoint's table dumps, walking records forward to find `redo_lsn`,
  the oldest LSN any still-dirty page needs.
- **redo** — from `redo_lsn`, re-apply each committed op whose target page is
  older than the record (`page_lsn < record_lsn`, the LSN gate; a page already
  past the change is skipped).
- **undo** — roll back ops of transactions that never committed, walking each
  transaction's undo-next chain backward.

The load-bearing subtlety, learned building a replayer validated chkdsk-clean on
a real Windows crash: **NTFS logs multi-sector-protected pages (FILE records,
INDX blocks) in *logical* form — the update-sequence fixup is NOT applied.** In a
logged page image the sector tails hold the real data, not the USN; sealing is a
flush-time concern. So a redo that lays down a fresh INDX block writes a logical
page, and a *later* redo against it must accept that logical form (its fixup
check 'fails' because tails ≠ USN — expected, not a torn page) and re-seal only
on write-back. A replayer that demands a sealed on-disk block at every step
silently drops those ops.

The same rule governs the **read side**, and getting it wrong there is much
quieter. Target FILE records must be loaded in logical form too (fixups
applied), because log ops describe the unsealed image and the write path
re-seals on flush. Modify a still-sealed buffer and the re-seal captures the
*old* USN into the USA as if it were data: every field that straddles a
sector-tail offset (0x1FE / 0x3FE of a 1 KiB record) silently gains two garbage
bytes, and everything else stays perfect. On a real crash volume this surfaced
as `$Extend\$RmMetadata\$Repair:$Verify` claiming `allocated_size =
0x19 << 48 | true size` — the leaked USN sitting in the high bytes — plus
phantom dangling entries and bitmap drift in other records whose structures
happened to cross a tail. The bug carried a second lesson: **Windows 10's
chkdsk passed the damaged volume; Windows Server 2022's flagged it — and this
tool's own checker had flagged it all along.** "chkdsk-clean" is a floor, not a
proof, and the floor's height depends on which chkdsk; when a strict checker
and a lenient oracle disagree, suspect the oracle's leniency before the
checker's pedantry.

Two more traps: the **v2 log relocates the record-page
header** — its logical file offset is at 0x3C and last-end LSN at 0x20, so the
0x18 "first free byte" field some parsers read is v1-shaped and truncates a v2
walk; and a **dry run applies nothing** (redo/undo only run when you commit), so
"zero ops applied" can just mean you didn't ask.

Why this tool still **resets** rather than replays: the structural checks
reconcile the on-disk state directly, so replay yields no repair the passes
don't already achieve, and an all-`0xFF` log is unambiguously clean to the next
mount. A genuine redo/undo engine (`replay.py`) that *does* produce a
chkdsk-clean volume is kept as research, not the repair path.