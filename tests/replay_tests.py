#!/usr/bin/env python3
'''Tests for the native $LogFile replay engine (replay.py).

Replay is research, not the shipped repair path: checkdisk *resets* the log
rather than replaying it (a reset log is unambiguously clean to the next mount,
and the structural checks already reconcile the on-disk state — see workabouts.md
"What $LogFile replay actually does"). But the engine genuinely works, and these
tests pin what it recovers so the research stays reproducible.

The fixture, fixtures/dirty-big-win.img.gz, is a real Windows 10 volume captured
mid-crash: under QEMU the guest churned files onto it and was hard-killed,
leaving a Microsoft-written v2 $LogFile with pending records. It is 256 MiB of
mostly-zero NTFS, so it gzips to ~390 KB. Replaying it re-applies 148 committed
redo records.

Cross-platform: the replay is deterministic, so the report is pinned exactly.
The 148 applied / 0 skipped count is the regression anchor for the "NTFS logs
INDX pages logically" fix (it moved the count from 146/2). On the Windows CI
runner an extra case brings in the external authority — real chkdsk agrees the
replayed volume is clean (reusing win_github_ci's VHD + chkdsk harness).

    python replay_tests.py -v
'''

from __future__ import annotations

import gzip
import hashlib
import os
import shutil
import sys
import tempfile
import unittest

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)                    # tests/
sys.path.insert(0, os.path.dirname(_here))   # repo root (checkdisk / replay)
import checkdisk as ndf   # noqa: E402
import replay             # noqa: E402

FIXTURE = os.path.join(_here, 'fixtures', 'dirty-big-win.img.gz')


def _load_dirty() -> str:
    '''Decompress the crashed-volume fixture to a fresh temp image (caller unlinks).'''
    fd, path = tempfile.mkstemp(suffix='.img', prefix='replay-')
    with os.fdopen(fd, 'wb') as out, gzip.open(FIXTURE, 'rb') as gz:
        shutil.copyfileobj(gz, out, length=1 << 20)
    return path


def _md5(path: str) -> str:
    with open(path, 'rb') as fh:
        return hashlib.md5(fh.read()).hexdigest()


class ReplayEngineTests(unittest.TestCase):
    '''Drive the replay engine against the genuine Windows crash and pin the recovery.'''

    def setUp(self) -> None:
        self.img = _load_dirty()
        self.addCleanup(lambda: os.path.exists(self.img) and os.unlink(self.img))

    def test_analysis_parses_the_windows_v2_log(self) -> None:
        # Reads the newer restart page, the NTFS client checkpoint and its four
        # table dumps, and walks every record of a real v2 log (header at 0x3C).
        rep = replay.replay(self.img, really=False)
        self.assertEqual(rep['records'], 197)
        self.assertEqual(rep['dirty_pages'], 12)
        self.assertEqual(rep['txn_committed'], 0)
        self.assertEqual(rep['redo_applied'], 0)      # a dry run applies nothing
        self.assertEqual(rep['warnings'], [])

    def test_dry_run_writes_nothing(self) -> None:
        before = _md5(self.img)
        replay.replay(self.img, really=False)
        self.assertEqual(_md5(self.img), before,
                         'a dry run must not touch a single byte')

    def test_redo_applies_every_committed_op(self) -> None:
        rep = replay.replay(self.img, really=True)
        # 148 applied / 0 skipped / no warnings is the "NTFS logs INDX pages in
        # logical form" fix (was 146/2 when the replayer wrongly demanded a
        # sealed on-disk block). A change to these numbers is a real change in
        # what replay recovers — update them deliberately, not to make CI green.
        self.assertEqual(rep['redo_applied'], 148)
        self.assertEqual(rep['redo_skipped'], 0)
        self.assertEqual(rep['warnings'], [])

    def test_replayed_volume_still_parses(self) -> None:
        replay.replay(self.img, really=True)
        with ndf.RawVolume(self.img) as v:
            roots = [e['name'] for e in v.scan_dir('/') if e['status'] != 'dir-self']
        self.assertGreater(len(roots), 0, 'root directory unreadable after replay')

    def test_finalize_resets_the_log(self) -> None:
        replay.replay(self.img, really=True)
        # finalize() reset the $LogFile to 0xFF, so a second analysis finds no
        # restart page at all — the volume presents as clean to the next mount.
        with self.assertRaises(replay.ReplayError):
            replay.replay(self.img, really=False)


@unittest.skipUnless(sys.platform == 'win32',
                     'native chkdsk oracle runs only on the Windows CI runner')
class ReplayChkdskOracle(unittest.TestCase):
    '''The external authority: after our replay, Microsoft's chkdsk is content.'''

    def test_replayed_volume_passes_chkdsk(self) -> None:
        import win_github_ci                       # VHD + read-only chkdsk harness
        img = _load_dirty()
        self.addCleanup(lambda: os.path.exists(img) and os.unlink(img))
        replay.replay(img, really=True)
        code, out = win_github_ci._chkdsk(img)
        self.assertNotEqual(code, 3, f'chkdsk could not run:\n{out}')
        self.assertEqual(code, 0,
                         f'chkdsk should find the replayed volume clean\n{out}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
