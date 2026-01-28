#!/usr/bin/env python3
"""macOS User Account Activity (syscall-only).

Goal: perform user account create/modify/delete activity without calling `dscl`
or `sysadminctl`.

We directly manipulate dslocal records under `/var/db/dslocal/...` (the backing
store `dscl` ultimately affects) to generate concrete on-host changes.

Notes:
- Requires root to actually create/modify/remove the record files.
- We create a locked user (passwd="*") without a usable password.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import time
import uuid


class UserAccountManager:
    def __init__(self) -> None:
        self.dslocal_users_dir = "/var/db/dslocal/nodes/Default/users"
        self.test_username = "edr_telem_test"
        self.test_uid = "599"
        self.test_gid_initial = "20"
        self.test_gid_modified = "80"
        self.home_dir = f"/Users/{self.test_username}"

    def _user_plist_path(self) -> str:
        return os.path.join(self.dslocal_users_dir, f"{self.test_username}.plist")

    def _write_user_record(self, *, realname: str, gid: str) -> bool:
        record = {
            "generateduid": [str(uuid.uuid4()).upper()],
            "gid": [gid],
            "home": [self.home_dir],
            "name": [self.test_username],
            "passwd": ["*"],
            "realname": [realname],
            "shell": ["/bin/zsh"],
            "uid": [self.test_uid],
        }

        path = self._user_plist_path()
        print(f"    [*] Writing user record: {path}")

        try:
            os.makedirs(self.dslocal_users_dir, exist_ok=True)
            with open(path, "wb") as f:
                plistlib.dump(record, f)
            return True
        except PermissionError:
            print("    [!] Permission denied writing user record (expected without root)")
            return True
        except Exception as e:
            print(f"    [-] Failed writing user record: {e}")
            return False

    def _remove_user_record(self) -> bool:
        path = self._user_plist_path()
        print(f"    [*] Removing user record: {path}")
        try:
            if os.path.exists(path):
                os.unlink(path)
            return True
        except PermissionError:
            print("    [!] Permission denied removing user record (expected without root)")
            return True
        except Exception as e:
            print(f"    [-] Failed removing user record: {e}")
            return False

    def _create_home_dir(self) -> bool:
        print(f"    [*] Creating home directory: {self.home_dir}")
        try:
            os.makedirs(self.home_dir, exist_ok=True)
            with open(os.path.join(self.home_dir, "edr_telem.txt"), "w", encoding="utf-8") as f:
                f.write("edr telemetry test\n")
            return True
        except PermissionError:
            print("    [!] Permission denied creating home directory (expected without root)")
            return True
        except Exception as e:
            print(f"    [-] Failed creating home directory: {e}")
            return False

    def _remove_home_dir(self) -> bool:
        print(f"    [*] Removing home directory: {self.home_dir}")
        try:
            if os.path.exists(self.home_dir):
                shutil.rmtree(self.home_dir)
            return True
        except PermissionError:
            print("    [!] Permission denied removing home directory (expected without root)")
            return True
        except Exception as e:
            print(f"    [-] Failed removing home directory: {e}")
            return False

    def run(self) -> bool:
        print("[*] Running User Account Activity demonstrations (syscall-only)...")

        # Create
        print("\n    === User Create ===")
        ok1 = self._write_user_record(realname="EDR Telemetry Test User", gid=self.test_gid_initial)
        ok2 = self._create_home_dir()
        time.sleep(2)

        # Modify
        print("\n    === User Modify ===")
        ok3 = self._write_user_record(realname="EDR Telemetry Test User (Modified)", gid=self.test_gid_initial)
        time.sleep(2)

        # Group membership change (simulated by changing primary gid)
        print("\n    === Group Membership Change ===")
        ok4 = self._write_user_record(realname="EDR Telemetry Test User (Modified)", gid=self.test_gid_modified)
        time.sleep(2)

        # Delete
        print("\n    === User Delete ===")
        ok5 = self._remove_user_record()
        ok6 = self._remove_home_dir()

        return ok1 and ok2 and ok3 and ok4 and ok5 and ok6


def user_account_events() -> bool:
    return UserAccountManager().run()


if __name__ == "__main__":
    raise SystemExit(0 if user_account_events() else 1)
