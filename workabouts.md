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

