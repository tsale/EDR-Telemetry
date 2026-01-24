#!/usr/bin/env python3
"""macOS Login Item Persistence (syscall-only).

Goal: add/remove a Login Item without invoking `osascript` or other binaries.

We use LaunchServices' (deprecated but still present) LSSharedFileList APIs to
add/remove a Session Login Item. This is close to what higher level tools used
to do under the hood.
"""

from __future__ import annotations

import os
import ctypes
import plistlib
import time


def _create_test_app_bundle() -> str:
    app_path = "/tmp/EDRTelemetryTest.app"
    contents_path = os.path.join(app_path, "Contents")
    macos_path = os.path.join(contents_path, "MacOS")
    os.makedirs(macos_path, exist_ok=True)

    info_plist = {
        "CFBundleExecutable": "EDRTelemetryTest",
        "CFBundleIdentifier": "com.edr.telemetry.test",
        "CFBundleName": "EDRTelemetryTest",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
        "LSMinimumSystemVersion": "10.10",
        "NSHighResolutionCapable": True,
    }

    with open(os.path.join(contents_path, "Info.plist"), "wb") as f:
        plistlib.dump(info_plist, f)

    # Create a dummy executable (not executed).
    exe = os.path.join(macos_path, "EDRTelemetryTest")
    with open(exe, "w", encoding="utf-8") as f:
        f.write("#!/usr/bin/env python3\nprint('edr login item test')\n")
    os.chmod(exe, 0o755)

    return app_path


def _remove_tree(path: str) -> None:
    import shutil

    try:
        if os.path.exists(path):
            shutil.rmtree(path)
    except Exception:
        pass


def loginitem_persistence() -> bool:
    print("[*] Running Login Item Persistence demonstrations (syscall-only)...")

    cf = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    ls = ctypes.CDLL(
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/LaunchServices"
    )

    def cfrelease(obj: int) -> None:
        if not obj:
            return
        cf.CFRelease(ctypes.c_void_p(obj))

    def cfstr(s: str) -> int:
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        # kCFStringEncodingUTF8
        return int(cf.CFStringCreateWithCString(None, s.encode("utf-8"), 0x08000100))

    def cfurl(path: str, is_dir: bool) -> int:
        cf.CFURLCreateWithFileSystemPath.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_bool,
        ]
        cf.CFURLCreateWithFileSystemPath.restype = ctypes.c_void_p
        # kCFURLPOSIXPathStyle
        kCFURLPOSIXPathStyle = 0
        cpath = cfstr(path)
        try:
            return int(cf.CFURLCreateWithFileSystemPath(None, ctypes.c_void_p(cpath), kCFURLPOSIXPathStyle, bool(is_dir)))
        finally:
            cfrelease(cpath)

    app_path = _create_test_app_bundle()
    try:
        print(f"    [+] Test app bundle created: {app_path}")

        try:
            list_type = int(ctypes.c_void_p.in_dll(ls, "kLSSharedFileListSessionLoginItems").value)
            item_last = int(ctypes.c_void_p.in_dll(ls, "kLSSharedFileListItemLast").value)
        except Exception as e:
            print(f"    [!] Could not resolve LaunchServices constants: {e}")
            return False

        ls.LSSharedFileListCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        ls.LSSharedFileListCreate.restype = ctypes.c_void_p
        sfl = int(ls.LSSharedFileListCreate(None, ctypes.c_void_p(list_type), None))
        if not sfl:
            print("    [!] LSSharedFileListCreate failed")
            return False

        item = 0
        try:
            ls.LSSharedFileListInsertItemURL.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            ls.LSSharedFileListInsertItemURL.restype = ctypes.c_void_p

            display = cfstr("EDR Telemetry Test")
            url = cfurl(app_path, is_dir=True)
            try:
                item = int(
                    ls.LSSharedFileListInsertItemURL(
                        ctypes.c_void_p(sfl),
                        ctypes.c_void_p(item_last),
                        ctypes.c_void_p(display),
                        None,
                        ctypes.c_void_p(url),
                        None,
                        None,
                    )
                )
            finally:
                cfrelease(display)
                cfrelease(url)

            if not item:
                print("    [!] LSSharedFileListInsertItemURL failed")
                return False

            print("    [+] Login item inserted")
            time.sleep(2)

            ls.LSSharedFileListItemRemove.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            ls.LSSharedFileListItemRemove.restype = ctypes.c_int
            status = int(ls.LSSharedFileListItemRemove(ctypes.c_void_p(sfl), ctypes.c_void_p(item)))
            print(f"    [+] Login item removed (status={status})")
            time.sleep(1)

            return True
        finally:
            if item:
                cfrelease(item)
            cfrelease(sfl)
    finally:
        _remove_tree(app_path)


if __name__ == "__main__":
    raise SystemExit(0 if loginitem_persistence() else 1)
