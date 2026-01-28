#!/usr/bin/env python3
"""Native macOS helpers (no external binaries).

This module intentionally avoids spawning system utilities. It uses ctypes to
call macOS frameworks/libraries directly where practical.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from typing import Iterable, List, Optional, Tuple


_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def xattr_set(path: str, name: str, value: bytes, flags: int = 0) -> int:
    """Set an extended attribute via libc setxattr."""

    _libc.setxattr.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    _libc.setxattr.restype = ctypes.c_int

    bpath = path.encode("utf-8")
    bname = name.encode("utf-8")
    buf = ctypes.create_string_buffer(value)
    return int(_libc.setxattr(bpath, bname, buf, len(value), 0, int(flags)))


def xattr_get(path: str, name: str) -> Optional[bytes]:
    """Get an extended attribute via libc getxattr."""

    _libc.getxattr.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    _libc.getxattr.restype = ctypes.c_ssize_t

    bpath = path.encode("utf-8")
    bname = name.encode("utf-8")

    size = int(_libc.getxattr(bpath, bname, None, 0, 0, 0))
    if size < 0:
        return None
    if size == 0:
        return b""

    buf = ctypes.create_string_buffer(size)
    got = int(_libc.getxattr(bpath, bname, buf, size, 0, 0))
    if got < 0:
        return None
    return buf.raw[:got]


def xattr_remove(path: str, name: str) -> int:
    """Remove an extended attribute via libc removexattr."""

    _libc.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _libc.removexattr.restype = ctypes.c_int

    bpath = path.encode("utf-8")
    bname = name.encode("utf-8")
    return int(_libc.removexattr(bpath, bname, 0))


class _CoreFoundation:
    def __init__(self) -> None:
        path = ctypes.util.find_library("CoreFoundation")
        if not path:
            raise RuntimeError("CoreFoundation not found")
        self.cf = ctypes.CDLL(path)

        self.CFRelease = self.cf.CFRelease
        self.CFRelease.argtypes = [ctypes.c_void_p]
        self.CFRelease.restype = None

        self.CFStringGetCString = self.cf.CFStringGetCString
        self.CFStringGetCString.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_long,
            ctypes.c_uint32,
        ]
        self.CFStringGetCString.restype = ctypes.c_bool


def _cfstring_to_str(cfstring: int) -> Optional[str]:
    if not cfstring:
        return None

    cf = _CoreFoundation()
    # kCFStringEncodingUTF8
    kCFStringEncodingUTF8 = 0x08000100
    buf = ctypes.create_string_buffer(1024)
    ok = cf.CFStringGetCString(cfstring, buf, ctypes.sizeof(buf), kCFStringEncodingUTF8)
    try:
        return buf.value.decode("utf-8") if ok else None
    finally:
        cf.CFRelease(cfstring)


def get_console_user() -> Tuple[Optional[str], Optional[int], Optional[int]]:
    """Return (username, uid, gid) for the active console user.

    Uses SystemConfiguration's SCDynamicStoreCopyConsoleUser.
    """

    sc_path = "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration"
    sc = ctypes.CDLL(sc_path)

    sc.SCDynamicStoreCopyConsoleUser.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    sc.SCDynamicStoreCopyConsoleUser.restype = ctypes.c_void_p

    uid = ctypes.c_uint32(0)
    gid = ctypes.c_uint32(0)
    cf_user = sc.SCDynamicStoreCopyConsoleUser(None, ctypes.byref(uid), ctypes.byref(gid))
    username = _cfstring_to_str(cf_user) if cf_user else None
    return username, int(uid.value) if cf_user else None, int(gid.value) if cf_user else None


class _LibProc:
    def __init__(self) -> None:
        # libproc is usually available via find_library('proc')
        path = ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib"
        self.lp = ctypes.CDLL(path)

        self.proc_listallpids = self.lp.proc_listallpids
        self.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.proc_listallpids.restype = ctypes.c_int

        self.proc_name = self.lp.proc_name
        self.proc_name.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.proc_name.restype = ctypes.c_int


def list_processes() -> List[Tuple[int, str]]:
    """Return a list of (pid, process_name) for running processes."""

    lp = _LibProc()
    count = lp.proc_listallpids(None, 0)
    if count <= 0:
        return []

    # proc_listallpids returns number of PIDs when buffer is NULL
    pids = (ctypes.c_int * count)()
    written = lp.proc_listallpids(pids, ctypes.sizeof(pids))
    if written <= 0:
        return []

    results: List[Tuple[int, str]] = []
    name_buf = ctypes.create_string_buffer(1024)

    for i in range(min(written, count)):
        pid = int(pids[i])
        if pid <= 0:
            continue
        name_buf.raw = b"\x00" * ctypes.sizeof(name_buf)
        n = lp.proc_name(pid, name_buf, ctypes.sizeof(name_buf))
        if n > 0:
            try:
                results.append((pid, name_buf.value.decode("utf-8", errors="replace")))
            except Exception:
                continue

    return results


def find_processes_by_name(names: Iterable[str]) -> List[Tuple[int, str]]:
    wanted = {n.lower() for n in names}
    return [(pid, name) for pid, name in list_processes() if name.lower() in wanted]
