'''Crash-consistency harness: hard-poweroff simulation, N seeded crashes.

The unit suite injects the *logical outcomes* of crashes (orphans, dangling
entries, torn indexes) at rest. This harness produces the *byte-level artifact*
of an actual hard reboot: it records every positioned write the engine issues
during a metadata-heavy workload (checkdisk._pwrite is the single choke point
for the write engine and format.populate alike), then rebuilds the volume from
a clean baseline plus an arbitrary PREFIX of that write journal — cutting power
mid-workload — with the in-flight write torn at sector granularity (a seeded
subset of its sectors land, the rest keep old bytes: partial DMA). Because the
cut point sweeps with the seed, crashes land inside B+ splits, small→large
transitions, $MFT record allocation, $Bitmap updates and $MFTMirr sync
naturally, without hand-picking targets.

Each crashed volume must then satisfy checkdisk's actual promises:
  1. `/f` (dry) never crashes — a clean report, whatever the damage;
  2. `/f --really` converges: repair exits 0, a re-run finds 0 remaining;
  3. files whose writes fully completed BEFORE the cut survive byte-exact
     (a torn index is repairable; flushed file content is sacred);
  4. on the Windows leg, native chkdsk agrees the repaired volume is clean.

Honest model limitation: this tears the single in-flight write; a real disk's
write-back cache can also reorder and drop *earlier* unflushed writes. A
dropped-suffix model over the journal is a natural extension.

Deterministic via CHECKDISK_CI_SEED; iteration count via CHECKDISK_CRASH_ITERS
(default 10).

    python crash_tests.py -v
'''

from __future__ import annotations

import hashlib, os, random, subprocess, sys, tempfile
import unittest

_here = __file__.replace('\\', '/').rsplit('/', 1)[0]
sys.path.insert(0, _here)                    # tests/
sys.path.insert(0, os.path.dirname(_here))   # repo root (checkdisk / format)

import checkdisk          # noqa: E402
import format             # noqa: E402


SEED = int(os.environ.get('CHECKDISK_CI_SEED', '20260719'))
ITERS = int(os.environ.get('CHECKDISK_CRASH_ITERS', '10'))
SECTOR = 512
CLI = [sys.executable, os.path.join(os.path.dirname(_here), 'checkdisk.py')]


def _cli(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([*CLI, *argv], capture_output=True, text=True)


def _md5(blob) -> str:
    return hashlib.md5(bytes(blob)).hexdigest()


class CrashConsistencyTest(unittest.TestCase):
    '''One recorded workload, ITERS different power-cut points.'''

    maxDiff = None

    def test_hard_crash_recovery(self) -> None:
        rng = random.Random(SEED)
        fd, img = tempfile.mkstemp(suffix='.img', prefix='crash-')
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(img) and os.unlink(img))

        # -- baseline: a healthy volume that existed before the "session" --
        format.format_volume(img, size_mib=64, label='CRASH')
        canaries = {f'd{d}/base{i:02d}.bin': rng.randbytes(rng.choice((30, 700, 5000)))
                    for d in range(4) for i in range(8)}
        format.populate(img, dict(canaries), dirs=('d0/sub',))
        with open(img, 'rb') as fh:
            baseline = fh.read()
        want = {rel: _md5(content) for rel, content in canaries.items()}

        # -- record the workload's write journal --
        journal: list[tuple[int, bytes]] = []
        real_pwrite = checkdisk._pwrite

        def logging_pwrite(fd, data, offset):
            journal.append((offset, bytes(data)))
            return real_pwrite(fd, data, offset)

        # batches: new dirs, nested dirs, and inserts into the PRE-EXISTING d0
        # (its on-disk index splits mid-batch — the interesting tear target)
        batches = []
        for b in range(8):
            d = 'd0' if b in (3, 6) else (f'w{b}/deep' if b == 5 else f'w{b}')
            batches.append({f'{d}/f{b}{i:02d}.bin':
                            rng.randbytes(rng.choice((30, 700, 5000, 12000)))
                            for i in range(25)})
        marks = []                       # (journal watermark, {rel: md5})
        checkdisk._pwrite = logging_pwrite
        try:
            for files in batches:
                format.populate(img, dict(files))
                marks.append((len(journal),
                              {rel: _md5(c) for rel, c in files.items()}))
        finally:
            checkdisk._pwrite = real_pwrite
        assert len(journal) > 100, f'workload too quiet: {len(journal)} writes'

        # -- N power cuts, each a subTest --
        for it in range(ITERS):
            with self.subTest(crash=it):
                crng = random.Random(SEED + 1000 + it)
                cut = crng.randrange(1, len(journal))
                self._one_crash(img, baseline, journal, cut, crng, want, marks)

    def _one_crash(self, img, baseline, journal, cut, crng, want, marks) -> None:
        # rebuild: baseline + full writes before the cut + the torn one
        vol = bytearray(baseline)
        for off, data in journal[:cut]:
            vol[off:off + len(data)] = data
        off, data = journal[cut]
        for s in range(0, len(data), SECTOR):        # partial DMA: sector mix
            if crng.getrandbits(1):
                vol[off + s:off + s + len(data[s:s + SECTOR])] = data[s:s + SECTOR]
        with open(img, 'wb') as fh:
            fh.write(vol)

        # 1. the dry run must produce a report, never a crash
        dry = _cli('/f', img)
        assert dry.returncode in (0, 1), (
            f'cut@{cut}: dry run rc={dry.returncode}\n{dry.stdout}{dry.stderr}')
        assert 'Traceback' not in dry.stderr, f'cut@{cut}:\n{dry.stderr}'

        # 2. repair must converge to a clean volume
        if dry.returncode:
            rep = _cli('/f', img, '--really')
            assert rep.returncode == 0 and ', 0 remaining' in rep.stdout, (
                f'cut@{cut}: repair did not converge\n{rep.stdout}{rep.stderr}')
            again = _cli('/f', img)
            assert again.returncode == 0, (
                f'cut@{cut}: not clean after repair\n{again.stdout}')

        # 3. everything fully flushed before the cut survives byte-exact
        expected = dict(want)
        for watermark, digests in marks:
            if watermark <= cut:
                expected.update(digests)
        with checkdisk.RawVolume(img) as v:
            listing: dict[str, dict] = {}
            for rel, digest in expected.items():
                d, name = rel.rsplit('/', 1)
                if d not in listing:
                    listing[d] = {e['name']: e['record']
                                  for e in v.scan_dir('/' + d)
                                  if e['status'] == 'ok'}
                assert name in listing[d], f'cut@{cut}: {rel} lost'
                got = _md5(v._attr_value(listing[d][name], checkdisk.AT_DATA, None))
                assert got == digest, f'cut@{cut}: {rel} corrupted'

        # 4. the external authority agrees (Windows leg only)
        if sys.platform == 'win32':
            import win_github_ci
            code, out = win_github_ci._chkdsk(img)
            assert 'Cannot open volume' not in out, f'cut@{cut}:\n{out}'
            assert code == 0, f'cut@{cut}: chkdsk disagrees\n{out}'


if __name__ == '__main__':
    unittest.main(verbosity=2)
