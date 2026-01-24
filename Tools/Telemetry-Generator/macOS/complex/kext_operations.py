#!/usr/bin/env python3
"""macOS Kernel/System Extension Activity (syscall-only).

This module avoids calling external binaries such as `kextstat` or
`systemextensionsctl`. Instead it uses IOKit KextManager APIs (same family of
APIs those tools use) plus supporting filesystem/database access.
"""

from __future__ import annotations

import ctypes
import os
import plistlib
import sqlite3


def _list_dir(path: str, *, suffix: str | None = None) -> int | None:
    if not os.path.exists(path):
        return None
    try:
        entries = os.listdir(path)
        if suffix is not None:
            entries = [e for e in entries if e.endswith(suffix)]
        return len(entries)
    except PermissionError:
        return None


def _print_dir_summary(path: str, *, suffix: str | None = None, label: str) -> None:
    count = _list_dir(path, suffix=suffix)
    if count is None:
        if os.path.exists(path):
            print(f"    [!] {label}: {path} (permission denied)")
        else:
            print(f"    [*] {label}: {path} (not found)")
        return

    print(f"    [+] {label}: {path} ({count} item(s))")


def check_kext_consent_database() -> bool:
    print("\n    === Kernel Extension Consent Database ===")
    db = "/var/db/SystemPolicyConfiguration/KextPolicy"
    if not os.path.exists(db):
        print("    [*] KextPolicy DB not found")
        return True

    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT team_id, bundle_id FROM kext_policy LIMIT 5")
        rows = cur.fetchall()
        conn.close()
        print(f"    [+] Read KextPolicy DB ({len(rows)} row(s) shown)")
        for team_id, bundle_id in rows:
            print(f"        - {bundle_id} (Team: {team_id})")
        return True
    except sqlite3.OperationalError as e:
        print(f"    [!] Could not open KextPolicy DB: {e}")
        return True
    except Exception as e:
        print(f"    [-] Error reading KextPolicy DB: {e}")
        return False


def list_loaded_kexts() -> bool:
    """List loaded kexts via KextManagerCopyLoadedKextInfo."""

    print("\n    === Loaded Kernel Extensions (KextManager) ===")
    iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )

    # CFDictionaryRef KextManagerCopyLoadedKextInfo(CFArrayRef kextIdentifiers, CFArrayRef infoKeys);
    iokit.KextManagerCopyLoadedKextInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    iokit.KextManagerCopyLoadedKextInfo.restype = ctypes.c_void_p

    # Convert the returned CFDictionary to bytes via CFPropertyListCreateData.
    cf.CFPropertyListCreateData.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    cf.CFPropertyListCreateData.restype = ctypes.c_void_p
    cf.CFDataGetLength.argtypes = [ctypes.c_void_p]
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
    cf.CFDataGetBytePtr.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = [ctypes.c_void_p]
    cf.CFRelease.restype = None

    d = iokit.KextManagerCopyLoadedKextInfo(None, None)
    if not d:
        print("    [!] KextManagerCopyLoadedKextInfo returned NULL")
        return True

    try:
        err = ctypes.c_void_p()
        # kCFPropertyListBinaryFormat_v1_0 = 200
        data_ref = cf.CFPropertyListCreateData(None, ctypes.c_void_p(d), 200, 0, ctypes.byref(err))
        if not data_ref:
            print("    [!] Failed to serialize loaded kext info")
            return True

        try:
            length = int(cf.CFDataGetLength(ctypes.c_void_p(data_ref)))
            ptr = cf.CFDataGetBytePtr(ctypes.c_void_p(data_ref))
            blob = ctypes.string_at(ptr, length)
            pl = plistlib.loads(blob)
            print(f"    [+] Loaded kexts: {len(pl)}")
            # Show a few non-Apple identifiers if present
            non_apple = [k for k in pl.keys() if not str(k).startswith('com.apple')]
            for k in non_apple[:5]:
                print(f"        - {k}")
        finally:
            cf.CFRelease(ctypes.c_void_p(data_ref))
    finally:
        cf.CFRelease(ctypes.c_void_p(d))

    return True


def simulate_kext_load_attempt() -> bool:
    """Attempt to load an (invalid) kext via KextManagerLoadKextWithURL.

    This is the API-level equivalent of `kextload` and should generate relevant
    telemetry even when it fails (expected on modern macOS).
    """

    print("\n    === Kext Load Attempt (KextManagerLoadKextWithURL) ===")

    iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )

    kext_path = "/tmp/EDRTelemetryTest.kext"
    contents = os.path.join(kext_path, "Contents")
    macos_dir = os.path.join(contents, "MacOS")

    try:
        os.makedirs(macos_dir, exist_ok=True)
        info = {
            "CFBundleIdentifier": "com.edr.telemetry.test.kext",
            "CFBundleName": "EDRTelemetryTestKext",
            "CFBundlePackageType": "KEXT",
            "CFBundleVersion": "1.0",
            "OSBundleLibraries": {"com.apple.kpi.bsd": "8.0.0"},
        }
        with open(os.path.join(contents, "Info.plist"), "wb") as f:
            plistlib.dump(info, f)
        with open(os.path.join(macos_dir, "EDRTelemetryTestKext"), "wb") as f:
            f.write(b"\x00")

        # CFURLCreateWithFileSystemPath
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        cf.CFURLCreateWithFileSystemPath.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_bool,
        ]
        cf.CFURLCreateWithFileSystemPath.restype = ctypes.c_void_p
        cf.CFRelease.argtypes = [ctypes.c_void_p]
        cf.CFRelease.restype = None

        # kCFStringEncodingUTF8
        cpath = int(cf.CFStringCreateWithCString(None, kext_path.encode("utf-8"), 0x08000100))
        try:
            # kCFURLPOSIXPathStyle
            url = int(cf.CFURLCreateWithFileSystemPath(None, ctypes.c_void_p(cpath), 0, True))
        finally:
            cf.CFRelease(ctypes.c_void_p(cpath))

        try:
            iokit.KextManagerLoadKextWithURL.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            iokit.KextManagerLoadKextWithURL.restype = ctypes.c_int
            rc = int(iokit.KextManagerLoadKextWithURL(ctypes.c_void_p(url), None))
            print(f"    [*] KextManagerLoadKextWithURL return={rc} (0 indicates success)")
        finally:
            cf.CFRelease(ctypes.c_void_p(url))

        return True
    except Exception as e:
        print(f"    [!] Kext load attempt failed: {e}")
        return True
    finally:
        try:
            import shutil

            if os.path.exists(kext_path):
                shutil.rmtree(kext_path)
        except Exception:
            pass


def kext_operations() -> bool:
    print("[*] Running Kernel/System Extension demonstrations (syscall-only)...")

    print("\n    === Extension Directories ===")
    _print_dir_summary("/Library/Extensions", suffix=".kext", label="/Library/Extensions")
    _print_dir_summary("/System/Library/Extensions", suffix=".kext", label="/System/Library/Extensions")
    _print_dir_summary("/Library/StagedExtensions", suffix=".kext", label="/Library/StagedExtensions")

    _print_dir_summary("/Library/SystemExtensions", label="/Library/SystemExtensions")
    _print_dir_summary("/System/Library/SystemExtensions", label="/System/Library/SystemExtensions")

    ok1 = list_loaded_kexts()
    ok2 = simulate_kext_load_attempt()
    ok3 = check_kext_consent_database()
    return ok1 and ok2 and ok3


if __name__ == "__main__":
    raise SystemExit(0 if kext_operations() else 1)
