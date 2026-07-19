'''Native Windows chkdsk oracle — the QEMU cross-check without the VM.

The portable suite (tests.py, ci_tests.py) verifies checkdisk.py with its own
readers. This module adds the one external authority that matters — Microsoft's
own chkdsk — but runs it *natively* on a real Windows CI runner instead of a
QEMU guest, so it needs no 40 GB installed image and no /dev/kvm. Each test
fabricates a bare NTFS volume with format.py, wraps it in a fixed VHD (an MBR
disk with one partition, plus the 512-byte VHD footer), attaches it read-only
through virtdisk.dll (see win_vhd — ctypes, no PowerShell), and runs chkdsk
against the resulting drive letter.

The claim tested is the same triad the QEMU oracle checks: a clean volume and a
checkdisk-repaired volume both come back clean (exit 0), while an unrepaired
corrupt volume is flagged (non-zero). Read-only mount keeps Windows' online
self-healing from touching the bytes, so chkdsk sees exactly what checkdisk left.

Skipped on every non-Windows platform (skipUnless win32); on the Windows leg it
is the only place a genuine chkdsk verdict enters the suite.

    python win_github_ci.py -v      # Windows only; elsewhere: all skipped
'''

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
import unittest

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)                    # tests/ (sibling fabricators)
sys.path.insert(0, os.path.dirname(_here))   # repo root (checkdisk / format)

if sys.platform == 'win32':                  # importing the fixtures pulls in
    import tests as T                        # format.py; only needed on Windows
    CHECKDISK = os.path.join(os.path.dirname(_here), 'checkdisk.py')

SECTOR = 512
PART_LBA = 2048                              # 1 MiB-aligned partition start


# ── frame a bare NTFS volume into a fixed VHD Windows will mount ──────────────

def _frame_bytes(vol: bytes) -> bytes:
    '''Bare volume → MBR disk with one NTFS partition at LBA 2048. Mirrors the
       QEMU oracle's frame_disk (a superfloppy is often not lettered), built in
       memory rather than as a sparse file so the bytes are VHD-ready.'''
    vol = bytearray(vol)
    if len(vol) % SECTOR:
        vol += b'\0' * (SECTOR - len(vol) % SECTOR)
    vol_sectors = len(vol) // SECTOR
    struct.pack_into('<I', vol, 0x1C, PART_LBA)                   # BPB hidden_sectors
    struct.pack_into('<I', vol, len(vol) - SECTOR + 0x1C, PART_LBA)  # NTFS backup boot

    mbr = bytearray(SECTOR)
    off = 0x1BE                                                   # first partition entry
    mbr[off] = 0x80                                              # bootable
    mbr[off + 1:off + 4] = bytes((0xFE, 0xFF, 0xFF))            # start CHS (LBA marker)
    mbr[off + 4] = 0x07                                          # type 0x07 NTFS/IFS
    mbr[off + 5:off + 8] = bytes((0xFE, 0xFF, 0xFF))           # end CHS (LBA marker)
    struct.pack_into('<I', mbr, off + 8, PART_LBA)              # start LBA
    struct.pack_into('<I', mbr, off + 12, vol_sectors)         # sector count
    mbr[510], mbr[511] = 0x55, 0xAA
    return bytes(mbr) + b'\0' * (PART_LBA * SECTOR - SECTOR) + bytes(vol)


def _vhd_footer(size: int) -> bytes:
    '''512-byte fixed-VHD (conectix) footer for a disk of `size` bytes. Fields
       are big-endian per the VHD spec; disk type 2 = fixed, data offset all-ones.'''
    total = size // SECTOR
    # CHS derivation straight from the VHD spec appendix.
    if total > 65535 * 16 * 255:
        total = 65535 * 16 * 255
    if total >= 65535 * 16 * 63:
        spt, heads, cth = 255, 16, total // 255
    else:
        spt = 17
        cth = total // spt
        heads = max((cth + 1023) // 1024, 4)
        if cth >= heads * 1024 or heads > 16:
            spt, heads = 31, 16
            cth = total // spt
        if cth >= heads * 1024:
            spt, heads = 63, 16
            cth = total // spt
    cyl = cth // heads

    f = bytearray(512)
    f[0:8] = b'conectix'
    struct.pack_into('>I', f, 8, 0x00000002)                    # features: reserved bit
    struct.pack_into('>I', f, 12, 0x00010000)                   # format version 1.0
    struct.pack_into('>Q', f, 16, 0xFFFFFFFFFFFFFFFF)           # data offset (fixed)
    struct.pack_into('>I', f, 24, 0)                            # timestamp (epoch 2000)
    f[28:32] = b'ckdk'                                           # creator app
    struct.pack_into('>I', f, 32, 0x000A0000)                   # creator version
    f[36:40] = b'Wi2k'                                           # creator host OS
    struct.pack_into('>Q', f, 40, size)                         # original size
    struct.pack_into('>Q', f, 48, size)                         # current size
    struct.pack_into('>H', f, 56, cyl & 0xFFFF)                 # geometry: cylinders
    f[58] = heads & 0xFF
    f[59] = spt & 0xFF
    struct.pack_into('>I', f, 60, 2)                            # disk type: fixed
    # unique id (16 bytes) left zero; saved-state byte at 84 left zero.
    struct.pack_into('>I', f, 64, (~sum(f)) & 0xFFFFFFFF)       # checksum (field was 0)
    return bytes(f)


def _chkdsk(volume_path: str) -> tuple[int, str]:
    '''Frame VOLUME_PATH as a VHD, attach + online it via virtdisk.dll (see
       win_vhd), and return (chkdsk_exit_code, chkdsk_output). We only ever run
       read-only chkdsk, so the volume bytes are exactly what checkdisk left.'''
    import win_vhd                                     # ctypes; Windows-only
    with open(volume_path, 'rb') as fh:
        data = _frame_bytes(fh.read())
    fd, vhd = tempfile.mkstemp(suffix='.vhd', prefix='ckdk-')
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.write(_vhd_footer(len(data)))
        with win_vhd.mounted(vhd) as letter:
            proc = subprocess.run(['chkdsk', letter + ':'], capture_output=True,
                                  text=True, encoding='utf-8', errors='replace')
        return proc.returncode, (proc.stdout or '') + (proc.stderr or '')
    finally:
        if os.path.exists(vhd):
            os.unlink(vhd)


_BASE = {f'docs/f{i:03d}.txt': b'hello\n' for i in range(40)}


@unittest.skipUnless(sys.platform == 'win32',
                     'native chkdsk oracle runs only on the Windows CI runner')
class WindowsChkdskOracle(unittest.TestCase):
    '''Real Windows chkdsk over a read-only VHD mount — the QEMU triad, native.'''

    def test_clean_volume_passes_chkdsk(self) -> None:
        img = T.NtfsImage()
        self.addCleanup(img.dispose)
        img.populate(dict(_BASE))
        code, out = self._verdict(img.path)
        self.assertEqual(code, 0, f'clean volume should pass chkdsk\n{out}')

    def test_checkdisk_repaired_volume_passes_chkdsk(self) -> None:
        img = T.NtfsImage()
        self.addCleanup(img.dispose)
        img.populate(dict(_BASE, **{'docs/orphan.bin': b'x' * 4096}))
        T.corrupt_orphan(img.path, 'orphan.bin')
        subprocess.run([sys.executable, CHECKDISK, '/f', img.path, '--really'],
                       check=True, capture_output=True)
        code, out = self._verdict(img.path)
        self.assertEqual(code, 0, f'checkdisk-repaired volume should pass chkdsk\n{out}')

    def test_unrepaired_corruption_is_flagged(self) -> None:
        img = T.NtfsImage()
        self.addCleanup(img.dispose)
        img.populate(dict(_BASE, **{'docs/orphan.bin': b'x' * 4096}))
        T.corrupt_orphan(img.path, 'orphan.bin')          # left unrepaired
        code, out = self._verdict(img.path)
        self.assertNotEqual(code, 0,
                            f'chkdsk should flag the unrepaired volume\n{out}')

    def _verdict(self, path: str) -> tuple[int, str]:
        code, out = _chkdsk(path)
        # chkdsk's exit 3 is overloaded: "could not check the volume" AND
        # "errors found but /f not given" both return 3 — only the output tells
        # them apart. In read-only mode a flagged volume legitimately exits 3
        # ("Errors found. CHKDSK cannot continue in read-only mode."), so gate
        # on the could-not-run marker instead of the code.
        self.assertNotIn('Cannot open volume', out,
                         f'chkdsk could not run:\n{out}')
        return code, out


if __name__ == '__main__':
    unittest.main(verbosity=2)
