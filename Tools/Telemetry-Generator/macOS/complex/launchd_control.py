#!/usr/bin/env python3
"""Launchd control helpers (no launchctl).

This module provides a single implementation for launchd job registration and
removal using ServiceManagement SMJobSubmit/SMJobRemove.

It also provides a best-effort service start via launchd's XPC START routine
(equivalent to `launchctl start <label>`), without spawning launchctl.
"""

from __future__ import annotations

import ctypes
import plistlib
from typing import Any, Dict, Optional


_cf = ctypes.CDLL(
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
)


def _load_servicemanagement() -> ctypes.CDLL:
    path = "/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement"
    return ctypes.CDLL(path)


def _cfrelease(obj: int) -> None:
    if not obj:
        return
    _cf.CFRelease.argtypes = [ctypes.c_void_p]
    _cf.CFRelease.restype = None
    _cf.CFRelease(ctypes.c_void_p(obj))


def _cfdata_from_bytes(data: bytes) -> int:
    _cf.CFDataCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
    _cf.CFDataCreate.restype = ctypes.c_void_p
    buf = ctypes.create_string_buffer(data)
    return int(_cf.CFDataCreate(None, buf, len(data)))


def _cfplist_from_dict(d: Dict[str, Any]) -> int:
    payload = plistlib.dumps(d, fmt=plistlib.FMT_BINARY)
    cfdata = _cfdata_from_bytes(payload)
    try:
        _cf.CFPropertyListCreateWithData.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        _cf.CFPropertyListCreateWithData.restype = ctypes.c_void_p
        err = ctypes.c_void_p()
        pl = _cf.CFPropertyListCreateWithData(None, ctypes.c_void_p(cfdata), 0, None, ctypes.byref(err))
        if not pl:
            raise RuntimeError("CFPropertyListCreateWithData failed")
        return int(pl)
    finally:
        _cfrelease(cfdata)


def _cfstring(s: str) -> int:
    _cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    _cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    # kCFStringEncodingUTF8
    return int(_cf.CFStringCreateWithCString(None, s.encode("utf-8"), 0x08000100))


def _cferror_to_str(cferr: int) -> str:
    if not cferr:
        return ""
    _cf.CFErrorCopyDescription.argtypes = [ctypes.c_void_p]
    _cf.CFErrorCopyDescription.restype = ctypes.c_void_p
    _cf.CFStringGetCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_long,
        ctypes.c_uint32,
    ]
    _cf.CFStringGetCString.restype = ctypes.c_bool

    # kCFStringEncodingUTF8
    kCFStringEncodingUTF8 = 0x08000100
    desc = int(_cf.CFErrorCopyDescription(ctypes.c_void_p(cferr)))
    try:
        buf = ctypes.create_string_buffer(2048)
        ok = _cf.CFStringGetCString(ctypes.c_void_p(desc), buf, ctypes.sizeof(buf), kCFStringEncodingUTF8)
        return buf.value.decode("utf-8", errors="replace") if ok else ""
    finally:
        _cfrelease(desc)
        _cfrelease(cferr)


def sm_job_submit_system(job: Dict[str, Any]) -> bool:
    sm = _load_servicemanagement()
    domain = int(ctypes.c_void_p.in_dll(sm, "kSMDomainSystemLaunchd").value)
    cf_job = _cfplist_from_dict(job)
    try:
        sm.SMJobSubmit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sm.SMJobSubmit.restype = ctypes.c_bool

        err = ctypes.c_void_p()
        ok = bool(sm.SMJobSubmit(ctypes.c_void_p(domain), ctypes.c_void_p(cf_job), None, ctypes.byref(err)))
        if not ok:
            msg = _cferror_to_str(int(err.value) if err.value else 0)
            raise RuntimeError(msg or "SMJobSubmit failed")
        return True
    finally:
        _cfrelease(cf_job)


def sm_job_remove_system(label: str, *, wait: bool = True) -> bool:
    sm = _load_servicemanagement()
    domain = int(ctypes.c_void_p.in_dll(sm, "kSMDomainSystemLaunchd").value)
    cf_label = _cfstring(label)
    try:
        sm.SMJobRemove.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_bool,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sm.SMJobRemove.restype = ctypes.c_bool

        err = ctypes.c_void_p()
        ok = bool(
            sm.SMJobRemove(
                ctypes.c_void_p(domain),
                ctypes.c_void_p(cf_label),
                None,
                bool(wait),
                ctypes.byref(err),
            )
        )
        if not ok:
            msg = _cferror_to_str(int(err.value) if err.value else 0)
            raise RuntimeError(msg or "SMJobRemove failed")
        return True
    finally:
        _cfrelease(cf_label)


def start_service_system(label: str) -> Optional[int]:
    """Best-effort start of a service by label (system domain).

    Returns:
    - None: could not attempt
    - 0: started/no error
    - non-zero: launchd error code
    """

    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    xpc_object_t = ctypes.c_void_p

    lib.xpc_dictionary_create.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    lib.xpc_dictionary_create.restype = xpc_object_t
    lib.xpc_dictionary_set_uint64.argtypes = [xpc_object_t, ctypes.c_char_p, ctypes.c_uint64]
    lib.xpc_dictionary_set_uint64.restype = None
    lib.xpc_dictionary_set_string.argtypes = [xpc_object_t, ctypes.c_char_p, ctypes.c_char_p]
    lib.xpc_dictionary_set_string.restype = None
    lib.xpc_dictionary_set_bool.argtypes = [xpc_object_t, ctypes.c_char_p, ctypes.c_bool]
    lib.xpc_dictionary_set_bool.restype = None
    lib.xpc_dictionary_get_int64.argtypes = [xpc_object_t, ctypes.c_char_p]
    lib.xpc_dictionary_get_int64.restype = ctypes.c_longlong
    lib.xpc_release.argtypes = [xpc_object_t]
    lib.xpc_release.restype = None
    lib.xpc_pipe_routine.argtypes = [xpc_object_t, xpc_object_t, ctypes.POINTER(xpc_object_t)]
    lib.xpc_pipe_routine.restype = ctypes.c_int

    class _OsAllocOnce(ctypes.Structure):
        _fields_ = [("once", ctypes.c_long), ("ptr", ctypes.c_void_p)]

    class _XpcGlobal(ctypes.Structure):
        _fields_ = [
            ("a", ctypes.c_uint64),
            ("xpc_flags", ctypes.c_uint64),
            ("task_bootstrap_port", ctypes.c_uint32),
            ("pad", ctypes.c_uint32),
            ("xpc_bootstrap_pipe", xpc_object_t),
        ]

    try:
        table = (_OsAllocOnce * 100).in_dll(lib, "_os_alloc_once_table")
        gd_ptr = table[1].ptr
        if not gd_ptr:
            return None
        gd = ctypes.cast(gd_ptr, ctypes.POINTER(_XpcGlobal)).contents
        pipe = gd.xpc_bootstrap_pipe
        if not pipe:
            return None

        d = lib.xpc_dictionary_create(None, None, 0)
        try:
            lib.xpc_dictionary_set_uint64(d, b"subsystem", 3)
            lib.xpc_dictionary_set_uint64(d, b"type", 1)
            lib.xpc_dictionary_set_uint64(d, b"handle", 0)
            lib.xpc_dictionary_set_uint64(d, b"routine", 0x32D)  # START
            lib.xpc_dictionary_set_string(d, b"name", label.encode("utf-8"))
            lib.xpc_dictionary_set_bool(d, b"legacy", True)

            out = xpc_object_t()
            rc = int(lib.xpc_pipe_routine(pipe, d, ctypes.byref(out)))
            if rc != 0:
                return rc

            try:
                if out:
                    err = int(lib.xpc_dictionary_get_int64(out, b"error"))
                    return err
                return 0
            finally:
                if out:
                    lib.xpc_release(out)
        finally:
            lib.xpc_release(d)
    except Exception:
        return None
