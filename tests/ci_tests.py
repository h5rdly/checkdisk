#!/usr/bin/env python3
'''Heavy CI pipeline test — the "Common partition rehearsal", reproducible.

One larger volume, thousands of files, EVERY corruption class injected at
once, then the full `/f --really` pipeline and a canary-checksum verification
through the tool's own readers. Multi-corruption at scale is the point: the classes
of bug that single-corruption unit tests cannot see (walk-order effects,
cache interactions between a stale dirent and its record's current owner,
repairs of one structure invalidating assumptions of the next stage) only
show up when many damaged structures coexist — exactly how real crashed
volumes present.

Deterministic via CHECKDISK_CI_SEED (default 20260716).

    python3 ci_tests.py -v
'''

from __future__ import annotations

import hashlib
import os
import random
import struct
import subprocess
import sys
import unittest

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)                    # tests/ (sibling tests)
sys.path.insert(0, os.path.dirname(_here))   # repo root (checkdisk)
import checkdisk as ndf  # noqa: E402
import tests as T  # noqa: E402  (image fixture + corruption fabricators)

SEED = int(os.environ.get('CHECKDISK_CI_SEED', '20260716'))
IMAGE_BYTES = 256 * 1024 * 1024
N_DIRS = 60
N_CANARIES = 900
N_PER_CLASS = 6


class HeavyPipelineTest(unittest.TestCase):
    maxDiff = None

    def _cli(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'checkdisk.py'),
             *argv], capture_output=True, text=True)

    def test_full_pipeline_under_mass_corruption(self) -> None:
        rng = random.Random(SEED)
        img = T.NtfsImage(size=IMAGE_BYTES)
        self.addCleanup(img.dispose)

        # -- build: canaries spread over many dirs, victims for every class --
        files: dict[str, bytes] = {}
        canaries: dict[str, str] = {}  # rel path -> md5
        for i in range(N_CANARIES):
            rel = f'dir{rng.randrange(N_DIRS):02d}/canary_{i:04d}.bin'
            content = rng.randbytes(rng.choice((30, 700, 5000)))
            files[rel] = content
            canaries[rel] = hashlib.md5(content).hexdigest()

        victims = {'orphan': [], 'gone': [], 'reused': [], 'crosslink': []}
        for i in range(N_PER_CLASS):
            d = f'dir{rng.randrange(N_DIRS):02d}'
            for cls, name in (('orphan', f'orphan{i:02d}.bin'),
                              ('gone', f'goneee{i:02d}.bin'),
                              ('reused', f'reused{i:02d}.dat'),
                              ('crosslink', f'crosslk{i:02d}.dat')):
                rel = f'{d}/{name}'
                files[rel] = rng.randbytes(4096)
                victims[cls].append((rel.rsplit('/', 1)[0], name))
        files['dirTT/toorn.bin'] = b'y' * 8192  # torn-truncate victim
        for i in range(300):  # big dir with multi-block $I30 to tear
            files[f'teardir/tearfile_{i:03d}.dat'] = f'tear-{i}\n'.encode()
        teardir_expected = sorted(f'tearfile_{i:03d}.dat' for i in range(300))

        img.populate(files, dirs=('teardir/subdir',))

        # -- inject: every corruption class at once --
        for parent, name in victims['orphan']:
            T.corrupt_orphan(img.path, name)
        for parent, name in victims['gone']:
            T.corrupt_record_free(img.path, name)
        for i, (parent, name) in enumerate(victims['reused']):
            T.corrupt_record_reused(img.path, name, f'squatt{i:02d}.dat')
        for i, (parent, name) in enumerate(victims['crosslink']):
            T.corrupt_cross_link(img.path, name, f'squatlk{i:02d}.dat')
        T.tear_index_block(img.path, 'tearfile_')
        T.corrupt_torn_truncate(img.path, 'toorn.bin')

        # leaked $Bitmap bits (extra-only: marking used clusters free would let
        # the repair allocator overwrite live data — that direction is covered
        # by the quiescent unit test instead)
        with ndf.RawVolume(img.path) as vol:
            nc = vol.nr_clusters()
        T.patch_stream(img.path, ndf.FILE_BITMAP, ndf.AT_DATA, '',
                       nc // 8 - 32, b'\xff' * 4)

        # $Secure: corrupt one descriptor's primary copy (the $SDS mirror the
        # native engine repairs) AND a $SII root entry's security_id (the native
        # engine rebuilds $SII/$SDH from $SDS).
        with ndf.RawVolume(img.path) as vol:
            chk = vol.secure_check()
            _sid, (_h, sds_off, _l) = sorted(chk['sds_entries'].items())[0]
            sii_root = vol._read_whole_attr(ndf.FILE_SECURE, ndf.AT_INDEX_ROOT,
                                            '$SII'.encode('utf-16-le'), 4)
        entry = 16 + struct.unpack_from('<I', sii_root, 16)[0]
        data_ofs = struct.unpack_from('<H', sii_root, entry)[0]
        T.patch_stream(img.path, ndf.FILE_SECURE, ndf.AT_DATA, '$SDS',
                       sds_off + 24, b'\xEE')
        T.patch_stream(img.path, ndf.FILE_SECURE, ndf.AT_INDEX_ROOT, '$SII',
                       entry + data_ofs + 4, struct.pack('<I', 0xDEAD))

        # -- dry run: everything is found, nothing is written --
        before = img.md5()
        proc = self._cli('/f', img.path)
        out = proc.stdout
        self.assertEqual(proc.returncode, 1, out + proc.stderr)
        self.assertEqual(img.md5(), before, 'dry run must not write a byte')
        expected_dangling = 4 * N_PER_CLASS
        self.assertIn(f'{expected_dangling} dangling entries, 1 torn index', out)
        self.assertIn('phantom run', out)
        self.assertIn('leaked bit(s)', out)
        for state in ('orphan', 'record-free', 'record-reused', 'cross-linked'):
            self.assertEqual(
                out.count(f': {state} ->'), N_PER_CLASS,
                f'{state}: expected {N_PER_CLASS} findings\n{out}')
        self.assertIn('index problem', out)

        # -- repair: one pass fixes everything fixable --
        proc = self._cli('/f', img.path, '--really')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(', 0 remaining', proc.stdout)

        # -- verify: clean re-run, then the real driver reads every canary --
        proc = self._cli('/f', img.path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

        with ndf.RawVolume(img.path) as v:
            listing = {}          # dir rel -> {name: record}
            for rel, want in canaries.items():
                d, name = rel.rsplit('/', 1)
                if d not in listing:
                    listing[d] = {e['name']: e['record']
                                  for e in v.scan_dir('/' + d)
                                  if e['status'] == 'ok'}
                self.assertIn(name, listing[d], f'canary missing: {rel}')
                got = hashlib.md5(bytes(
                    v._attr_value(listing[d][name], ndf.AT_DATA, None))).hexdigest()
                self.assertEqual(got, want, f'canary corrupted: {rel}')
            self.assertEqual(
                sorted(e['name'] for e in v.scan_dir('/teardir')
                       if e['status'] != 'dir-self' and e['name'] != 'subdir'),
                teardir_expected)
            e = next(x for x in v.scan_dir('/dirTT') if x['name'] == 'toorn.bin')
            self.assertEqual(v._attr_value(e['record'], ndf.AT_DATA, None), b'')
            for cls in ('orphan', 'gone'):
                for parent, name in victims[cls]:
                    names = {x['name'] for x in v.scan_dir('/' + parent)}
                    self.assertNotIn(name, names,
                                     f'{cls} victim {name} should be gone from {parent}')



class MetadataFuzzTest(unittest.TestCase):
    '''Seeded metadata fuzzing: flip random bytes inside the metadata regions
       (MFT records + INDX blocks), then require that every read path either
       completes or raises NtfsError/OSError — never an uncaught exception or
       hang. Rounds via CHECKDISK_FUZZ_ROUNDS.'''

    ROUNDS = int(os.environ.get('CHECKDISK_FUZZ_ROUNDS', '25'))

    def test_fuzz_read_paths(self) -> None:
        rng = random.Random(SEED + 1)
        img = T.NtfsImage()
        self.addCleanup(img.dispose)
        img.populate({f'd{i % 7}/f{i:03d}.bin': rng.randbytes(rng.choice((30, 800, 5000)))
                      for i in range(120)}, dirs=('d0/sub',))
        pristine = T._read(img.path)

        # metadata targets: every FILE record and INDX block in the image
        targets = [off for off in range(0, len(pristine), 1024)
                   if pristine[off:off + 4] in (b'FILE', b'INDX')]
        self.assertGreater(len(targets), 100)

        for round_no in range(self.ROUNDS):
            blob = bytearray(pristine)
            for _ in range(rng.randrange(1, 9)):
                base = rng.choice(targets)
                blob[base + rng.randrange(1024)] ^= 1 << rng.randrange(8)
            with open(img.path, 'wb') as fh:
                fh.write(blob)

            try:
                vol = ndf.RawVolume(img.path)
            except (ndf.NtfsError, OSError):
                continue                     # refusing to mount is acceptable
            try:
                for op, fn in (
                        ('survey', lambda: self._digest(
                            vol.mft_survey(want_used=True))),
                        ('audit', lambda: vol.cluster_audit()['extra']),
                        ('secure', lambda: len(vol.secure_check()['problems'])),
                        ('usn', lambda: vol.usn_check()['present']),
                        ('scan', lambda: sorted(
                            (e['name'], e['status'])
                            for e in vol.scan_dir('/d1')
                            if e['status'] != 'dir-self'))):
                    try:
                        fn()
                    except (ndf.NtfsError, OSError):
                        pass                 # clean refusal is fine
            finally:
                vol.close()

    @staticmethod
    def _digest(survey):
        return (survey['total'], survey['in_use'], survey['torn'],
                len(survey['runlist_problems']), bytes(survey['used']))



if __name__ == '__main__':
    unittest.main(verbosity=2)
