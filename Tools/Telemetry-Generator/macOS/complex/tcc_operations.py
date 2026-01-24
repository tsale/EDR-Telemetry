#!/usr/bin/env python3
"""macOS TCC (Privacy) Activity (syscall-only).

This module avoids external binaries (`osascript`, `screencapture`, etc.).
It generates telemetry via direct file/database access:
- Read-only queries of TCC.db
- An explicit "access check" style query (service/client lookup)
"""

from __future__ import annotations

import ctypes
import os
import sqlite3


TCC_SERVICES = {
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceAppleEvents": "Automation",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
}


def _db_paths() -> dict:
    return {
        "user": os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db"),
        "system": "/Library/Application Support/com.apple.TCC/TCC.db",
    }


def _query_recent(db_path: str, label: str) -> bool:
    print(f"\n    === {label} TCC Database (recent entries) ===")
    if not os.path.exists(db_path):
        print(f"    [*] Not found: {db_path}")
        return True

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute(
            "SELECT service, client, auth_value, last_modified FROM access "
            "ORDER BY last_modified DESC LIMIT 10"
        )
        rows = cur.fetchall()
        conn.close()

        if not rows:
            print("    [*] No rows returned")
            return True

        print(f"    [+] {len(rows)} row(s)")
        for service, client, auth_value, _lm in rows:
            svc = TCC_SERVICES.get(service, service)
            print(f"        - {svc}: {str(client)[:48]} (auth={auth_value})")
        return True
    except sqlite3.OperationalError as e:
        print(f"    [!] Could not open DB (SIP/FDA likely): {e}")
        return True
    except Exception as e:
        print(f"    [-] DB query failed: {e}")
        return False


def tcc_access_check(db_path: str, service: str, client_like: str) -> bool:
    """Simulate a TCC access check by querying TCC.db for service/client."""

    print("\n    === TCC Access Check (DB lookup) ===")
    print(f"    [*] DB: {db_path}")
    print(f"    [*] service={service}, client_like={client_like}")

    if not os.path.exists(db_path):
        print("    [*] DB not found")
        return True

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute(
            "SELECT client, auth_value, auth_reason FROM access "
            "WHERE service = ? AND client LIKE ? LIMIT 5",
            (service, client_like),
        )
        rows = cur.fetchall()
        conn.close()

        if not rows:
            print("    [*] No matching entries")
            return True

        print(f"    [+] Found {len(rows)} matching entr(ies)")
        for client, auth_value, auth_reason in rows:
            print(f"        - {str(client)[:48]} auth={auth_value} reason={auth_reason}")
        return True
    except sqlite3.OperationalError as e:
        print(f"    [!] Access check query failed (SIP/FDA likely): {e}")
        return True
    except Exception as e:
        print(f"    [-] Access check query failed: {e}")
        return False


def screen_recording_access_check() -> bool:
    """Perform a real TCC-gated access check via CoreGraphics.

    This calls CGPreflightScreenCaptureAccess/CGRequestScreenCaptureAccess.
    """

    print("\n    === TCC Access Check (Screen Recording) ===")
    cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")

    cg.CGPreflightScreenCaptureAccess.argtypes = []
    cg.CGPreflightScreenCaptureAccess.restype = ctypes.c_bool
    cg.CGRequestScreenCaptureAccess.argtypes = []
    cg.CGRequestScreenCaptureAccess.restype = ctypes.c_bool

    try:
        pre = bool(cg.CGPreflightScreenCaptureAccess())
        print(f"    [+] CGPreflightScreenCaptureAccess -> {pre}")
    except Exception as e:
        print(f"    [!] Preflight call failed: {e}")
        return True

    # Request will trigger a prompt if not already granted.
    try:
        req = bool(cg.CGRequestScreenCaptureAccess())
        print(f"    [+] CGRequestScreenCaptureAccess -> {req}")
    except Exception as e:
        print(f"    [!] Request call failed: {e}")
        return True

    return True


def accessibility_access_check() -> bool:
    """Perform a real accessibility TCC check via AX API."""

    print("\n    === TCC Access Check (Accessibility) ===")

    cf = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    ax = ctypes.CDLL(
        "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices"
    )

    ax.AXIsProcessTrustedWithOptions.argtypes = [ctypes.c_void_p]
    ax.AXIsProcessTrustedWithOptions.restype = ctypes.c_bool

    # Build { kAXTrustedCheckOptionPrompt: True }
    try:
        key = int(ctypes.c_void_p.in_dll(ax, "kAXTrustedCheckOptionPrompt").value)
    except Exception:
        # Fallback: create a CFString with the expected value
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        key = int(cf.CFStringCreateWithCString(None, b"AXTrustedCheckOptionPrompt", 0x08000100))

    try:
        cf.CFBooleanGetValue.argtypes = [ctypes.c_void_p]
        cf.CFBooleanGetValue.restype = ctypes.c_bool
        # kCFBooleanTrue is exported
        val = int(ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue").value)

        cf.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        cf.CFDictionaryCreate.restype = ctypes.c_void_p

        keys = (ctypes.c_void_p * 1)(ctypes.c_void_p(key))
        vals = (ctypes.c_void_p * 1)(ctypes.c_void_p(val))

        # kCFTypeDictionaryKeyCallBacks / kCFTypeDictionaryValueCallBacks
        kcb = ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryKeyCallBacks")
        vcb = ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryValueCallBacks")
        opts = int(
            cf.CFDictionaryCreate(
                None,
                keys,
                vals,
                1,
                ctypes.byref(kcb),
                ctypes.byref(vcb),
            )
        )

        try:
            trusted = bool(ax.AXIsProcessTrustedWithOptions(ctypes.c_void_p(opts)))
            print(f"    [+] AXIsProcessTrustedWithOptions -> {trusted}")
        finally:
            cf.CFRelease(ctypes.c_void_p(opts))

    finally:
        # Only release key if we created it. If it came from in_dll it's managed.
        pass

    return True


def tcc_operations() -> bool:
    print("[*] Running TCC (Privacy) demonstrations (syscall-only)...")
    paths = _db_paths()

    ok1 = _query_recent(paths["user"], "User")
    ok2 = _query_recent(paths["system"], "System")

    # DB lookup (useful) + real API access checks.
    ok3 = tcc_access_check(paths["user"], "kTCCServiceAppleEvents", "%python%")
    ok4 = screen_recording_access_check()
    ok5 = accessibility_access_check()
    return ok1 and ok2 and ok3 and ok4 and ok5


if __name__ == "__main__":
    raise SystemExit(0 if tcc_operations() else 1)
