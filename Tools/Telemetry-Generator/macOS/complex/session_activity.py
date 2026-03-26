#!/usr/bin/env python3
"""macOS Session Activity (syscall-only).

Full session/login telemetry on macOS is typically sourced from unified logs,
PAM/OpenDirectory, and loginwindow notifications. Many common ways to query or
trigger these involve external binaries (`log`, `last`, `scutil`, `dscl`, etc.).

This syscall-only module focuses on API/syscall primitives:
- Current UID/GID/EUID via libc
- Console user via SystemConfiguration API
- Process presence checks via libproc (instead of pgrep/ps)
"""

from __future__ import annotations

import ctypes
import ctypes.util

from native import get_console_user, list_processes


def get_current_user_info() -> bool:
    print("\n    === Current User Info (syscalls) ===")
    libc = ctypes.CDLL(ctypes.util.find_library("c"))

    uid = int(libc.getuid())
    gid = int(libc.getgid())
    euid = int(libc.geteuid())
    egid = int(libc.getegid())

    print(f"    [+] uid={uid} gid={gid} euid={euid} egid={egid}")
    return True


def console_user_check() -> bool:
    print("\n    === Console User (SystemConfiguration) ===")
    try:
        user, uid, gid = get_console_user()
        print(f"    [+] user={user} uid={uid} gid={gid}")
        return True
    except Exception as e:
        print(f"    [!] Console user lookup failed: {e}")
        return True


def screen_lock_state_check() -> bool:
    print("\n    === Screen Lock Heuristics (process presence) ===")
    procs = list_processes()
    names = {name for _pid, name in procs}

    if "ScreenSaverEngine" in names:
        print("    [+] ScreenSaverEngine running (screen may be locked)")
    else:
        print("    [*] ScreenSaverEngine not running")

    if "loginwindow" in names:
        print("    [+] loginwindow running")

    if "WindowServer" in names:
        print("    [+] WindowServer running")

    return True


def session_activity_events() -> bool:
    print("[*] Running Session Activity demonstrations (syscall-only)...")
    ok1 = get_current_user_info()
    ok2 = console_user_check()
    ok3 = screen_lock_state_check()
    return ok1 and ok2 and ok3


if __name__ == "__main__":
    raise SystemExit(0 if session_activity_events() else 1)
