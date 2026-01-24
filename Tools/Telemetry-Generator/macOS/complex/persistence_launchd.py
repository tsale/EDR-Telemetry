#!/usr/bin/env python3
"""macOS Launchd Persistence (syscall-only).

Goal: perform launchd persistence actions without invoking `launchctl`.

This implementation creates a LaunchDaemon plist, loads it via launchd XPC
(launchctl-equivalent), starts it, then unloads and removes it.
"""

from __future__ import annotations

import os
import sys
import plistlib
import tempfile
import time

from .launchd_control import sm_job_remove_system, sm_job_submit_system, start_service_system


_PYTHON = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def _create_test_program() -> str:
    """Create a harmless program that appends to a log and exits."""

    fd, path = tempfile.mkstemp(prefix="edr_launchd_", suffix=".py")
    os.close(fd)

    with open(path, "w", encoding="utf-8") as f:
        f.write(
            "import time\n"
            "with open('/tmp/edr_launchd_test.log','a') as fp:\n"
            "    fp.write(f'launchd job ran {time.time()}\\n')\n"
        )
    os.chmod(path, 0o755)
    return path

def _job(label: str, program_path: str, run_at_load: bool = True) -> dict:
    return {
        "Label": label,
        "ProgramArguments": [_PYTHON, program_path],
        "RunAtLoad": run_at_load,
        # Ensure launchd actually executes the job shortly after submission
        # even if RunAtLoad is ignored in some contexts.
        "StartInterval": 1,
        "KeepAlive": False,
        "StandardOutPath": f"/tmp/{label}.stdout",
        "StandardErrorPath": f"/tmp/{label}.stderr",
    }


def _remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def launchd_persistence() -> bool:
    print("[*] Running Launchd Persistence demonstrations (syscall-only)...")

    label = "com.edr.telemetry.test.daemon"
    program_path = _create_test_program()
    plist_path = f"/Library/LaunchDaemons/{label}.plist"

    plist_data = {
        "Label": label,
        "ProgramArguments": [_PYTHON, program_path],
        "RunAtLoad": False,
        "KeepAlive": False,
        "StandardOutPath": f"/tmp/{label}.stdout",
        "StandardErrorPath": f"/tmp/{label}.stderr",
    }

    try:
        print(f"    [*] Writing LaunchDaemon plist: {plist_path}")
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)
        os.chmod(plist_path, 0o644)

        print("    [*] Submitting LaunchDaemon via ServiceManagement (SMJobSubmit)...")
        sm_job_submit_system(plist_data)
        print("    [+] SMJobSubmit succeeded")

        print("    [*] Starting service (best effort)...")
        start_rc = start_service_system(label)
        if start_rc not in (None, 0):
            print(f"    [!] Start returned error: {start_rc}")
        else:
            print("    [+] Start attempted")

        time.sleep(2)

        print("    [*] Removing LaunchDaemon via ServiceManagement (SMJobRemove)...")
        sm_job_remove_system(label)
        print("    [+] Removed")

        print(f"    [*] Removing plist: {plist_path}")
        _remove(plist_path)
        print("    [+] Plist removed")

        return True
    except Exception as e:
        print(f"    [!] LaunchdPersistence failed: {e}")
        return False
    finally:
        try:
            sm_job_remove_system(label)
        except Exception:
            pass
        _remove(plist_path)
        _remove(program_path)


if __name__ == "__main__":
    raise SystemExit(0 if launchd_persistence() else 1)
