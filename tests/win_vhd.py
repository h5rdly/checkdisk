#!/usr/bin/env python3
r'''Attach a VHD read-only and hand back a drive letter — pure ctypes/virtdisk.dll.

The Windows chkdsk oracle needs each fabricated volume presented to Windows as a
lettered drive. PowerShell can do it (Mount-DiskImage), but Get-Disk enumerates
the CIM store asynchronously and races a freshly attached image
(CmdletizationQuery_NotFound). virtdisk.dll avoids that: OpenVirtualDisk +
AttachVirtualDisk attach the image, GetVirtualDiskPhysicalPath returns
\\.\PhysicalDriveN straight from the handle (no CIM), then we find that disk's
volume by matching disk extents and give it a letter — reusing an automount
letter if one appeared, otherwise assigning a free one ourselves.

Windows-only, but every Win32 DLL is loaded lazily inside the functions, so the
module still imports on other platforms (its callers are skipped there anyway).
'''

from __future__ import annotations

import contextlib
import ctypes
import string
import time
from ctypes import wintypes


# ── structures (virtdisk.h / winioctl.h) ─────────────────────────────────────

class _VIRTUAL_STORAGE_TYPE(ctypes.Structure):
    _fields_ = [('DeviceId', wintypes.ULONG), ('VendorId', ctypes.c_ubyte * 16)]


class _ATTACH_PARAMS(ctypes.Structure):        # ATTACH_VIRTUAL_DISK_PARAMETERS v1
    _fields_ = [('Version', wintypes.DWORD), ('Reserved', wintypes.ULONG)]


class _DISK_EXTENT(ctypes.Structure):
    _fields_ = [('DiskNumber', wintypes.DWORD),
                ('StartingOffset', wintypes.LARGE_INTEGER),
                ('ExtentLength', wintypes.LARGE_INTEGER)]


class _VOLUME_DISK_EXTENTS(ctypes.Structure):
    _fields_ = [('NumberOfDiskExtents', wintypes.DWORD),
                ('Extents', _DISK_EXTENT * 8)]


# device type VHD + vendor GUID {EC984AEC-A0F9-47e9-901F-71415A66345B}, the
# Microsoft provider, in the mixed-endian byte order a GUID serializes to.
_STORAGE_TYPE_VHD = 2
_MS_VENDOR = bytes.fromhex('ec4a98ecf9a0e947901f71415a66345b')

_ACCESS_READ = 0x000D0000            # VIRTUAL_DISK_ACCESS_READ = RO|DETACH|GET_INFO
_OPEN_FLAG_NONE = 0
_ATTACH_FLAG_READ_ONLY = 0x00000001
_ATTACH_VERSION_1 = 1
_DETACH_FLAG_NONE = 0
_IOCTL_GET_DISK_EXTENTS = 0x00560000     # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
_INVALID_HANDLE = ctypes.c_void_p(-1).value


# ── lazily-bound DLLs (WinDLL only exists on Windows) ────────────────────────

def _virtdisk():
    d = ctypes.WinDLL('virtdisk.dll')
    d.OpenVirtualDisk.argtypes = [
        ctypes.POINTER(_VIRTUAL_STORAGE_TYPE), wintypes.LPCWSTR, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]
    d.OpenVirtualDisk.restype = wintypes.DWORD
    d.AttachVirtualDisk.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.ULONG,
        ctypes.POINTER(_ATTACH_PARAMS), ctypes.c_void_p]
    d.AttachVirtualDisk.restype = wintypes.DWORD
    d.GetVirtualDiskPhysicalPath.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG), wintypes.LPWSTR]
    d.GetVirtualDiskPhysicalPath.restype = wintypes.DWORD
    d.DetachVirtualDisk.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.ULONG]
    d.DetachVirtualDisk.restype = wintypes.DWORD
    return d


def _kernel32():
    k = ctypes.WinDLL('kernel32.dll', use_last_error=True)
    k.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p]
    k.DeviceIoControl.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.FindFirstVolumeW.argtypes = [wintypes.LPWSTR, wintypes.DWORD]
    k.FindFirstVolumeW.restype = wintypes.HANDLE
    k.FindNextVolumeW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
    k.FindNextVolumeW.restype = wintypes.BOOL
    k.FindVolumeClose.argtypes = [wintypes.HANDLE]
    k.FindVolumeClose.restype = wintypes.BOOL
    k.GetVolumePathNamesForVolumeNameW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    k.GetVolumePathNamesForVolumeNameW.restype = wintypes.BOOL
    k.SetVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    k.SetVolumeMountPointW.restype = wintypes.BOOL
    k.DeleteVolumeMountPointW.argtypes = [wintypes.LPCWSTR]
    k.DeleteVolumeMountPointW.restype = wintypes.BOOL
    k.GetLogicalDrives.restype = wintypes.DWORD
    return k


# ── attach / detach ──────────────────────────────────────────────────────────

def _attach(virtdisk, k, vhd_path: str) -> wintypes.HANDLE:
    st = _VIRTUAL_STORAGE_TYPE()
    st.DeviceId = _STORAGE_TYPE_VHD
    st.VendorId = (ctypes.c_ubyte * 16)(*_MS_VENDOR)
    handle = wintypes.HANDLE()
    rc = virtdisk.OpenVirtualDisk(ctypes.byref(st), vhd_path, _ACCESS_READ,
                                  _OPEN_FLAG_NONE, None, ctypes.byref(handle))
    if rc:
        raise ctypes.WinError(rc, f'OpenVirtualDisk({vhd_path})')
    params = _ATTACH_PARAMS()
    params.Version = _ATTACH_VERSION_1
    rc = virtdisk.AttachVirtualDisk(handle, None, _ATTACH_FLAG_READ_ONLY, 0,
                                    ctypes.byref(params), None)
    if rc:
        k.CloseHandle(handle)
        raise ctypes.WinError(rc, 'AttachVirtualDisk')
    return handle


def _disk_number(virtdisk, handle) -> int:
    size = wintypes.ULONG(260 * 2)
    buf = ctypes.create_unicode_buffer(260)
    rc = virtdisk.GetVirtualDiskPhysicalPath(handle, ctypes.byref(size), buf)
    if rc:
        raise ctypes.WinError(rc, 'GetVirtualDiskPhysicalPath')
    path = buf.value                                  # \\.\PhysicalDriveN
    return int(path.rsplit('PhysicalDrive', 1)[-1])


# ── volume → drive letter ────────────────────────────────────────────────────

def _volume_disk_number(k, vol_path: str):
    h = k.CreateFileW(vol_path.rstrip('\\'), 0, 0x3, None, 3, 0, None)  # share RW
    if h == _INVALID_HANDLE:
        return None
    try:
        vde = _VOLUME_DISK_EXTENTS()
        ret = wintypes.DWORD()
        ok = k.DeviceIoControl(h, _IOCTL_GET_DISK_EXTENTS, None, 0,
                               ctypes.byref(vde), ctypes.sizeof(vde),
                               ctypes.byref(ret), None)
        if ok and vde.NumberOfDiskExtents >= 1:
            return vde.Extents[0].DiskNumber
        return None
    finally:
        k.CloseHandle(h)


def _volume_on_disk(k, disk_number: int):
    buf = ctypes.create_unicode_buffer(260)
    fh = k.FindFirstVolumeW(buf, 260)
    if fh == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error(), 'FindFirstVolume')
    try:
        while True:
            if _volume_disk_number(k, buf.value) == disk_number:
                return buf.value                      # \\?\Volume{GUID}\
            if not k.FindNextVolumeW(fh, buf, 260):
                return None
    finally:
        k.FindVolumeClose(fh)


def _existing_letter(k, vol_path: str):
    buf = ctypes.create_unicode_buffer(260)
    ret = wintypes.DWORD()
    ok = k.GetVolumePathNamesForVolumeNameW(vol_path, buf, 260, ctypes.byref(ret))
    p = buf.value if ok else ''
    return p[0] if len(p) >= 2 and p[1] == ':' else None


def _free_letter(k) -> str:
    used = k.GetLogicalDrives()
    for i in range(3, 26):                             # D..Z (skip A, B, C)
        if not (used & (1 << i)):
            return string.ascii_uppercase[i]
    raise OSError('no free drive letter available')


@contextlib.contextmanager
def mounted_readonly(vhd_path: str):
    '''Attach VHD_PATH read-only and yield its NTFS partition's drive letter
       (e.g. "E"). On exit: release any letter we assigned, detach, close.'''
    virtdisk, k = _virtdisk(), _kernel32()
    handle = _attach(virtdisk, k, vhd_path)
    mount_point = None
    try:
        disk = _disk_number(virtdisk, handle)
        vol = None
        for _ in range(40):               # the volume can surface a moment later
            vol = _volume_on_disk(k, disk)
            if vol is not None:
                break
            time.sleep(0.25)
        if vol is None:
            raise OSError(f'no volume surfaced on PhysicalDrive{disk}')
        letter = _existing_letter(k, vol)
        if letter is None:                # automount didn't letter it — do it ourselves
            letter = _free_letter(k)
            mount_point = letter + ':\\'
            if not k.SetVolumeMountPointW(mount_point, vol):
                raise ctypes.WinError(ctypes.get_last_error(), 'SetVolumeMountPoint')
        yield letter
    finally:
        if mount_point:
            k.DeleteVolumeMountPointW(mount_point)
        virtdisk.DetachVirtualDisk(handle, _DETACH_FLAG_NONE, 0)
        k.CloseHandle(handle)
