#!/usr/bin/env python3
"""macOS Code Signing & Trust Activity (syscall-only).

This module avoids external binaries (`codesign`, `spctl`, `stapler`, `cc`,
`launchctl`). It uses Security.framework APIs where practical and generates
filesystem telemetry via quarantine xattrs and XProtect metadata reads.
"""

from __future__ import annotations

import ctypes
import os
import plistlib
import tempfile
import time

from native import xattr_get, xattr_remove, xattr_set


QUARANTINE_ATTR = "com.apple.quarantine"


def _cf() -> ctypes.CDLL:
    return ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )


def _sec() -> ctypes.CDLL:
    return ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")


def _cfstr(s: str) -> int:
    cf = _cf()
    cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    # kCFStringEncodingUTF8
    return int(cf.CFStringCreateWithCString(None, s.encode("utf-8"), 0x08000100))


def _cfurl_from_path(path: str, is_dir: bool = False) -> int:
    cf = _cf()
    cf.CFURLCreateWithFileSystemPath.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_bool,
    ]
    cf.CFURLCreateWithFileSystemPath.restype = ctypes.c_void_p

    # kCFURLPOSIXPathStyle
    kCFURLPOSIXPathStyle = 0
    cf_path = _cfstr(path)
    try:
        url = cf.CFURLCreateWithFileSystemPath(None, cf_path, kCFURLPOSIXPathStyle, bool(is_dir))
        return int(url)
    finally:
        _cf().CFRelease(ctypes.c_void_p(cf_path))


def _cfrelease(obj: int) -> None:
    if not obj:
        return
    cf = _cf()
    cf.CFRelease.argtypes = [ctypes.c_void_p]
    cf.CFRelease.restype = None
    cf.CFRelease(ctypes.c_void_p(obj))


def verify_code_signature(path: str) -> bool:
    """Signature validity check via Security.framework.

    Uses an explicit requirement ("anchor apple") so that ad-hoc/unsigned code
    does not appear as "valid".
    """
    print(f"\n    === Signature Validity Check: {path} ===")
    if not os.path.exists(path):
        print("    [!] Path not found")
        return False

    sec = _sec()
    url = _cfurl_from_path(path, is_dir=os.path.isdir(path))
    code_ref = ctypes.c_void_p()
    req_ref = ctypes.c_void_p()

    try:
        sec.SecStaticCodeCreateWithPath.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecStaticCodeCreateWithPath.restype = ctypes.c_int

        sec.SecStaticCodeCheckValidity.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        sec.SecStaticCodeCheckValidity.restype = ctypes.c_int

        # SecRequirementCreateWithString(CFStringRef, SecCSFlags, SecRequirementRef*)
        sec.SecRequirementCreateWithString.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecRequirementCreateWithString.restype = ctypes.c_int

        cf_req = _cfstr("anchor apple")
        try:
            rcrc = sec.SecRequirementCreateWithString(ctypes.c_void_p(cf_req), 0, ctypes.byref(req_ref))
            if rcrc != 0:
                print(f"    [!] SecRequirementCreateWithString failed: {rcrc}")
                req_ref = ctypes.c_void_p()
        finally:
            _cfrelease(cf_req)

        rc = sec.SecStaticCodeCreateWithPath(ctypes.c_void_p(url), 0, ctypes.byref(code_ref))
        if rc != 0:
            print(f"    [!] SecStaticCodeCreateWithPath failed: {rc}")
            return True

        # Prefer the *WithErrors variant, which tends to perform deeper checks.
        if hasattr(sec, "SecStaticCodeCheckValidityWithErrors"):
            sec.SecStaticCodeCheckValidityWithErrors.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            sec.SecStaticCodeCheckValidityWithErrors.restype = ctypes.c_int

            err = ctypes.c_void_p()
            rc2 = sec.SecStaticCodeCheckValidityWithErrors(
                code_ref,
                0,
                req_ref if req_ref.value else None,
                ctypes.byref(err),
            )
            if err.value:
                _cfrelease(int(err.value))
        else:
            rc2 = sec.SecStaticCodeCheckValidity(code_ref, 0, req_ref if req_ref.value else None)
        if rc2 == 0:
            print("    [+] Signature validity: VALID")
        else:
            print(f"    [!] Signature validity: INVALID (status={rc2})")
        return True
    finally:
        _cfrelease(url)
        if code_ref.value:
            _cfrelease(int(code_ref.value))
        if req_ref.value:
            _cfrelease(int(req_ref.value))


def gatekeeper_assessment(path: str) -> bool:
    """Gatekeeper-style assessment via SecAssessment APIs (spctl equivalent)."""

    print(f"\n    === Gatekeeper Assessment (SecAssessment): {path} ===")
    if not os.path.exists(path):
        print("    [!] Path not found")
        return False

    sec = _sec()
    cf = _cf()

    url = _cfurl_from_path(path, is_dir=os.path.isdir(path))
    try:
        # OSStatus SecAssessmentCreate(CFTypeRef, CFDictionaryRef, SecAssessmentRef*)
        sec.SecAssessmentCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecAssessmentCreate.restype = ctypes.c_int

        # OSStatus SecAssessmentCopyResult(SecAssessmentRef, CFDictionaryRef, CFDictionaryRef*)
        sec.SecAssessmentCopyResult.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecAssessmentCopyResult.restype = ctypes.c_int

        assessment = ctypes.c_void_p()
        rc = sec.SecAssessmentCreate(ctypes.c_void_p(url), None, ctypes.byref(assessment))
        if rc != 0:
            print(f"    [!] SecAssessmentCreate failed: {rc}")
            return True

        try:
            result = ctypes.c_void_p()
            rc2 = sec.SecAssessmentCopyResult(assessment, None, ctypes.byref(result))
            if rc2 != 0:
                print(f"    [!] SecAssessmentCopyResult failed: {rc2}")
                return True

            try:
                # Convert result CFDictionary to a description string
                cf.CFCopyDescription.argtypes = [ctypes.c_void_p]
                cf.CFCopyDescription.restype = ctypes.c_void_p
                cf.CFStringGetCString.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_char_p,
                    ctypes.c_long,
                    ctypes.c_uint32,
                ]
                cf.CFStringGetCString.restype = ctypes.c_bool

                desc = int(cf.CFCopyDescription(result))
                try:
                    buf = ctypes.create_string_buffer(4096)
                    ok = cf.CFStringGetCString(ctypes.c_void_p(desc), buf, ctypes.sizeof(buf), 0x08000100)
                    if ok:
                        print(f"    [+] Result: {buf.value.decode('utf-8', errors='replace')[:400]}")
                    else:
                        print("    [+] Result obtained")
                finally:
                    _cfrelease(desc)
            finally:
                _cfrelease(int(result.value) if result.value else 0)
        finally:
            _cfrelease(int(assessment.value) if assessment.value else 0)

        return True
    finally:
        _cfrelease(url)


def set_quarantine(path: str) -> bool:
    print(f"\n    === Set Quarantine XAttr: {path} ===")
    try:
        # flags;epochhex;app;uuid
        value = f"0083;{hex(int(time.time()))[2:]};EDR Telemetry;00000000-0000-0000-0000-000000000000"
        rc = xattr_set(path, QUARANTINE_ATTR, value.encode("utf-8"))
        if rc != 0:
            print(f"    [!] setxattr failed, errno: {ctypes.get_errno()}")
            return False
        print("    [+] Quarantine attribute set")
        return True
    except Exception as e:
        print(f"    [!] Failed to set quarantine: {e}")
        return False


def read_quarantine(path: str) -> bool:
    print(f"\n    === Read Quarantine XAttr: {path} ===")
    try:
        raw = xattr_get(path, QUARANTINE_ATTR)
        if raw is None:
            print("    [*] No quarantine attribute")
            return True
        print(f"    [+] {raw.decode('utf-8', errors='replace')}")
        return True
    except OSError:
        print("    [*] No quarantine attribute")
        return True
    except Exception as e:
        print(f"    [!] Failed to read quarantine: {e}")
        return False


def remove_quarantine(path: str) -> bool:
    print(f"\n    === Remove Quarantine XAttr: {path} ===")
    try:
        rc = xattr_remove(path, QUARANTINE_ATTR)
        if rc != 0:
            print(f"    [!] removexattr failed, errno: {ctypes.get_errno()}")
            return True
        print("    [+] Quarantine attribute removed")
        return True
    except OSError:
        print("    [*] No quarantine attribute to remove")
        return True
    except Exception as e:
        print(f"    [!] Failed to remove quarantine: {e}")
        return False


def check_xprotect() -> bool:
    print("\n    === XProtect Metadata (filesystem) ===")
    candidates = [
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist",
    ]

    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "rb") as f:
                    plist = plistlib.load(f)
                version = plist.get("Version", "Unknown")
                print(f"    [+] {p}: Version={version}")
                return True
            except Exception as e:
                print(f"    [!] Failed reading {p}: {e}")

    print("    [*] XProtect meta plist not found")
    return True


def _create_test_executable() -> str:
    """Create a test Mach-O by copying a system binary and corrupting it."""

    fd, path = tempfile.mkstemp(prefix="edr_macho_", suffix="")
    os.close(fd)

    src = "/bin/ls" if os.path.exists("/bin/ls") else "/usr/bin/true"
    with open(src, "rb") as fsrc:
        data = fsrc.read()

    # Corrupt a signed page inside the *native arch slice*.
    # System binaries are often fat/universal; flipping bytes outside the slice
    # (padding/fat headers) won't affect signature validity.

    b = bytearray(data)

    def flip(at: int) -> None:
        if 0 <= at < len(b):
            b[at] ^= 0xFF

    # FAT magic values
    FAT_MAGIC = 0xCAFEBABE
    FAT_CIGAM = 0xBEBAFECA
    CPU_TYPE_ARM64 = 0x0100000C
    CPU_TYPE_X86_64 = 0x01000007

    if len(b) >= 8:
        magic_be = int.from_bytes(b[0:4], "big")
        magic_le = int.from_bytes(b[0:4], "little")
        is_fat_be = magic_be == FAT_MAGIC
        is_fat_le = magic_le == FAT_MAGIC  # rare
        is_fat = is_fat_be or is_fat_le or magic_be == FAT_CIGAM or magic_le == FAT_CIGAM

        if is_fat:
            # fat_header: magic (u32), nfat_arch (u32)
            endian = "big" if (magic_be == FAT_MAGIC or magic_be == FAT_CIGAM) else "little"
            nfat = int.from_bytes(b[4:8], endian)
            # fat_arch: cputype,u32 cpusubtype,u32 offset,u32 size,u32 align,u32
            arch_size = 20
            base = 8
            chosen_offset = None
            for i in range(nfat):
                off = base + i * arch_size
                if off + arch_size > len(b):
                    break
                cputype = int.from_bytes(b[off : off + 4], endian)
                offset = int.from_bytes(b[off + 8 : off + 12], endian)
                size = int.from_bytes(b[off + 12 : off + 16], endian)
                if cputype == CPU_TYPE_ARM64:
                    chosen_offset = offset
                    break
            # Fallback to x86_64 if arm64 not found
            if chosen_offset is None:
                for i in range(nfat):
                    off = base + i * arch_size
                    if off + arch_size > len(b):
                        break
                    cputype = int.from_bytes(b[off : off + 4], endian)
                    offset = int.from_bytes(b[off + 8 : off + 12], endian)
                    if cputype == CPU_TYPE_X86_64:
                        chosen_offset = offset
                        break

            if chosen_offset is not None:
                # Flip bytes within the slice
                for rel in (0x100, 0x1000, 0x2000):
                    flip(chosen_offset + rel)
            else:
                # If parsing fails, flip in the general body (skip magic)
                for rel in (0x100, 0x1000, 0x2000):
                    flip(rel)
        else:
            # Thin Mach-O
            for rel in (0x100, 0x1000, 0x2000):
                flip(rel)

    data = bytes(b)


    with open(path, "wb") as fdst:
        fdst.write(data)

    os.chmod(path, 0o755)
    return path


def codesign_trust_events() -> bool:
    print("[*] Running Code Signing & Trust demonstrations (syscall-only)...")

    ok = True
    ok &= verify_code_signature("/bin/ls")

    test_exec = _create_test_executable()
    try:
        ok &= verify_code_signature(test_exec)
        ok &= set_quarantine(test_exec)
        ok &= read_quarantine(test_exec)
        # SecAssessment can terminate the process with SIGTRAP on some systems.
        # Run it in a child so the parent continues even if that happens.
        pid = os.fork()
        if pid == 0:
            try:
                res = gatekeeper_assessment(test_exec)
                os._exit(0 if res else 1)
            except Exception:
                os._exit(1)
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            print(f"    [!] Gatekeeper assessment terminated by signal: {sig}")
            ok &= True
        else:
            ok &= os.WEXITSTATUS(status) == 0
        ok &= remove_quarantine(test_exec)
    finally:
        try:
            os.unlink(test_exec)
        except Exception:
            pass

    ok &= check_xprotect()
    return bool(ok)


if __name__ == "__main__":
    raise SystemExit(0 if codesign_trust_events() else 1)
