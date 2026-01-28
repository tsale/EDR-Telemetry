#!/usr/bin/env python3
"""macOS Service Activity (syscall-only).

We avoid calling `launchctl`. This module creates/modifies/deletes a LaunchDaemon
plist and uses launchd XPC (launchctl-equivalent) to load/unload and start it.
"""

from __future__ import annotations

import os
import sys
import plistlib
import tempfile
import time

from .launchd_control import sm_job_remove_system, sm_job_submit_system, start_service_system


_PYTHON = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def _create_program() -> str:
    fd, path = tempfile.mkstemp(prefix="edr_service_", suffix=".py")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write("print('edr service test')\n")
    os.chmod(path, 0o755)
    return path


def _remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def service_activity_events() -> bool:
    print("[*] Running Service Activity demonstrations (syscall-only)...")

    label = "com.edr.telemetry.test.service"
    program = _create_program()

    plist_path = f"/Library/LaunchDaemons/{label}.plist"

    base_plist = {
        "Label": label,
        "ProgramArguments": [_PYTHON, program],
        "RunAtLoad": False,
        "KeepAlive": False,
        "StandardOutPath": f"/tmp/{label}.stdout",
        "StandardErrorPath": f"/tmp/{label}.stderr",
    }

    try:
        print(f"    [*] Creating service plist: {plist_path}")
        with open(plist_path, "wb") as f:
            plistlib.dump(base_plist, f)
        os.chmod(plist_path, 0o644)

        print("    [*] Submitting service via ServiceManagement (SMJobSubmit)...")
        sm_job_submit_system(base_plist)
        print("    [+] SMJobSubmit succeeded")

        print("    [*] Starting service (best effort)...")
        start_rc = start_service_system(label)
        if start_rc not in (None, 0):
            print(f"    [!] Start returned error: {start_rc}")
        else:
            print("    [+] Start attempted")
        time.sleep(2)

        print("    [*] Modifying service (unload, edit plist, reload)...")
        print("    [*] Removing service via ServiceManagement (SMJobRemove)...")
        sm_job_remove_system(label)
        modified = dict(base_plist)
        modified["KeepAlive"] = True
        modified["EnvironmentVariables"] = {"EDR_TEST": "modified"}
        with open(plist_path, "wb") as f:
            plistlib.dump(modified, f)
        os.chmod(plist_path, 0o644)
        sm_job_submit_system(modified)
        start_rc = start_service_system(label)
        if start_rc not in (None, 0):
            print(f"    [!] Start returned error: {start_rc}")
        print("    [+] Modified")
        time.sleep(2)

        print("    [*] Deleting service (unload and remove plist)...")
        sm_job_remove_system(label)
        _remove(plist_path)
        print("    [+] Deleted")
        time.sleep(1)

        btm_dir = os.path.expanduser(
            "~/Library/Application Support/com.apple.backgroundtaskmanagementagent"
        )
        print(f"    [*] Checking BTM directory: {btm_dir}")
        try:
            files = os.listdir(btm_dir)
            print(f"    [+] BTM entries: {len(files)}")
        except FileNotFoundError:
            print("    [*] BTM directory not present")
        except PermissionError:
            print("    [!] Permission denied reading BTM directory")

        return True
    except Exception as e:
        print(f"    [!] ServiceActivity failed: {e}")
        return False
    finally:
        try:
            sm_job_remove_system(label)
        except Exception:
            pass
        _remove(plist_path)
        _remove(program)


if __name__ == "__main__":
    raise SystemExit(0 if service_activity_events() else 1)
