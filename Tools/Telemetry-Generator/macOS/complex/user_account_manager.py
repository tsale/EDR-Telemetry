#!/usr/bin/env python3
"""macOS User Account Activity (system API only).

This module uses OpenDirectory.framework APIs (no dscl/sysadminctl execution,
no direct dslocal plist writes) to generate user create/modify/delete activity.

Notes:
- Requires root for create/modify/delete effects.
- Creates a temporary local user record intended only for telemetry generation.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import time
from typing import Optional


class _OpenDirectoryClient:
    def __init__(self) -> None:
        cf_path = ctypes.util.find_library("CoreFoundation") or \
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        od_path = ctypes.util.find_library("OpenDirectory") or \
            "/System/Library/Frameworks/OpenDirectory.framework/OpenDirectory"

        self.cf = ctypes.CDLL(cf_path)
        self.od = ctypes.CDLL(od_path)

        self.cf.CFStringCreateWithCString.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self.cf.CFStringCreateWithCString.restype = ctypes.c_void_p

        self.cf.CFStringGetCString.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_long,
            ctypes.c_uint32,
        ]
        self.cf.CFStringGetCString.restype = ctypes.c_bool

        self.cf.CFCopyDescription.argtypes = [ctypes.c_void_p]
        self.cf.CFCopyDescription.restype = ctypes.c_void_p

        self.cf.CFRelease.argtypes = [ctypes.c_void_p]
        self.cf.CFRelease.restype = None

        self.od.ODSessionCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.od.ODSessionCreate.restype = ctypes.c_void_p

        self.od.ODNodeCreateWithName.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.od.ODNodeCreateWithName.restype = ctypes.c_void_p

        self.od.ODNodeCopyRecord.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.od.ODNodeCopyRecord.restype = ctypes.c_void_p

        self.od.ODNodeCreateRecord.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.od.ODNodeCreateRecord.restype = ctypes.c_void_p

        self.od.ODRecordSetValue.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.od.ODRecordSetValue.restype = ctypes.c_bool

        self.od.ODRecordSynchronize.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.od.ODRecordSynchronize.restype = ctypes.c_bool

        self.od.ODRecordDelete.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.od.ODRecordDelete.restype = ctypes.c_bool

    @staticmethod
    def _utf8() -> int:
        return 0x08000100  # kCFStringEncodingUTF8

    def _cfstr(self, value: str) -> int:
        return int(self.cf.CFStringCreateWithCString(None, value.encode("utf-8"), self._utf8()))

    def _release(self, value: int) -> None:
        if value:
            self.cf.CFRelease(ctypes.c_void_p(value))

    def _cf_error_str(self, err_ref: ctypes.c_void_p) -> str:
        if not err_ref or not err_ref.value:
            return "unknown OpenDirectory error"

        desc = int(self.cf.CFCopyDescription(ctypes.c_void_p(int(err_ref.value))))
        if not desc:
            return "unknown OpenDirectory error"

        try:
            buf = ctypes.create_string_buffer(2048)
            ok = self.cf.CFStringGetCString(ctypes.c_void_p(desc), buf, ctypes.sizeof(buf), self._utf8())
            if not ok:
                return "unknown OpenDirectory error"
            return buf.value.decode("utf-8", errors="replace")
        finally:
            self._release(desc)

    def _open_local_node(self) -> tuple[int, int]:
        err = ctypes.c_void_p()
        session = int(self.od.ODSessionCreate(None, None, ctypes.byref(err)) or 0)
        if not session:
            raise RuntimeError(f"ODSessionCreate failed: {self._cf_error_str(err)}")

        node_name = self._cfstr("/Local/Default")
        try:
            node = int(
                self.od.ODNodeCreateWithName(
                    None,
                    ctypes.c_void_p(session),
                    ctypes.c_void_p(node_name),
                    ctypes.byref(err),
                )
                or 0
            )
        finally:
            self._release(node_name)

        if not node:
            self._release(session)
            raise RuntimeError(f"ODNodeCreateWithName failed: {self._cf_error_str(err)}")

        return session, node

    def _copy_user_record(self, node: int, username: str) -> int:
        err = ctypes.c_void_p()
        rec_type = self._cfstr("dsRecTypeStandard:Users")
        rec_name = self._cfstr(username)
        try:
            return int(
                self.od.ODNodeCopyRecord(
                    ctypes.c_void_p(node),
                    ctypes.c_void_p(rec_type),
                    ctypes.c_void_p(rec_name),
                    None,
                    ctypes.byref(err),
                )
                or 0
            )
        finally:
            self._release(rec_type)
            self._release(rec_name)

    def _create_user_record(self, node: int, username: str) -> int:
        err = ctypes.c_void_p()
        rec_type = self._cfstr("dsRecTypeStandard:Users")
        rec_name = self._cfstr(username)
        try:
            record = int(
                self.od.ODNodeCreateRecord(
                    ctypes.c_void_p(node),
                    ctypes.c_void_p(rec_type),
                    ctypes.c_void_p(rec_name),
                    None,
                    ctypes.byref(err),
                )
                or 0
            )
            if not record:
                raise RuntimeError(f"ODNodeCreateRecord failed: {self._cf_error_str(err)}")
            return record
        finally:
            self._release(rec_type)
            self._release(rec_name)

    def _set_record_value(self, record: int, attr: str, value: str) -> None:
        err = ctypes.c_void_p()
        cf_attr = self._cfstr(attr)
        cf_value = self._cfstr(value)
        try:
            ok = bool(
                self.od.ODRecordSetValue(
                    ctypes.c_void_p(record),
                    ctypes.c_void_p(cf_attr),
                    ctypes.c_void_p(cf_value),
                    ctypes.byref(err),
                )
            )
            if not ok:
                raise RuntimeError(f"ODRecordSetValue({attr}) failed: {self._cf_error_str(err)}")
        finally:
            self._release(cf_attr)
            self._release(cf_value)

    def _sync_record(self, record: int) -> None:
        err = ctypes.c_void_p()
        ok = bool(self.od.ODRecordSynchronize(ctypes.c_void_p(record), ctypes.byref(err)))
        if not ok:
            raise RuntimeError(f"ODRecordSynchronize failed: {self._cf_error_str(err)}")

    def upsert_user(
        self,
        *,
        username: str,
        realname: str,
        uid: str,
        gid: str,
        home_dir: str,
    ) -> bool:
        session = 0
        node = 0
        record = 0
        try:
            session, node = self._open_local_node()
            record = self._copy_user_record(node, username)
            created = False
            if not record:
                record = self._create_user_record(node, username)
                created = True

            attributes = [
                ("dsAttrTypeStandard:RealName", realname),
                ("dsAttrTypeStandard:PrimaryGroupID", gid),
                ("dsAttrTypeStandard:NFSHomeDirectory", home_dir),
                ("dsAttrTypeStandard:UserShell", "/bin/zsh"),
            ]
            if created:
                attributes.append(("dsAttrTypeStandard:UniqueID", uid))
                # GeneratedUID is commonly managed by the system; attempting to
                # set it can fail with "Session does not have privileges" even
                # under sudo on modern macOS.

            for attr, value in attributes:
                self._set_record_value(record, attr, value)

            self._sync_record(record)
            return True
        finally:
            self._release(record)
            self._release(node)
            self._release(session)

    def delete_user(self, username: str) -> bool:
        session = 0
        node = 0
        record = 0
        try:
            session, node = self._open_local_node()
            record = self._copy_user_record(node, username)
            if not record:
                print(f"    [*] OpenDirectory record not present: {username}")
                return True

            err = ctypes.c_void_p()
            ok = bool(self.od.ODRecordDelete(ctypes.c_void_p(record), ctypes.byref(err)))
            if not ok:
                raise RuntimeError(f"ODRecordDelete failed: {self._cf_error_str(err)}")
            return True
        finally:
            self._release(record)
            self._release(node)
            self._release(session)


class UserAccountManager:
    def __init__(self) -> None:
        self.test_username = "edr_telem_test"
        self.test_uid = str(55000 + (os.getpid() % 1000))
        self.test_gid_initial = "20"
        self.test_gid_modified = "80"
        # Avoid touching /Users directly. Some systems enforce additional
        # protections and may return EPERM even for root. Use /tmp for
        # predictable permissions and easier cleanup.
        self.home_base = "/tmp/edr_telem_userhomes"
        self.home_dir = os.path.join(self.home_base, self.test_username)

        self.od_client: Optional[_OpenDirectoryClient] = None
        try:
            self.od_client = _OpenDirectoryClient()
        except Exception as e:
            print(f"    [!] OpenDirectory API unavailable: {e}")

    def _is_safe_home_path(self, path: str) -> bool:
        base = os.path.realpath(self.home_base)
        target = os.path.realpath(path)
        if not target.startswith(base + os.sep):
            return False
        if target in ("/", "/private", "/private/var", "/private/var/tmp", base):
            return False
        return True

    def _create_home_dir(self) -> bool:
        print(f"    [*] Creating home directory: {self.home_dir}")
        try:
            os.makedirs(self.home_base, exist_ok=True)
            try:
                os.chown(self.home_base, 0, 0)
                os.chmod(self.home_base, 0o700)
            except Exception:
                pass

            os.makedirs(self.home_dir, exist_ok=True)
            try:
                os.chown(self.home_dir, 0, 0)
                os.chmod(self.home_dir, 0o700)
            except Exception:
                pass
            with open(os.path.join(self.home_dir, "edr_telem.txt"), "w", encoding="utf-8") as f:
                f.write("edr telemetry test\n")
            return True
        except Exception as e:
            print(f"    [-] Failed creating home directory: {e}")
            return False

    def _remove_home_dir(self) -> bool:
        print(f"    [*] Removing home directory: {self.home_dir}")
        try:
            if not self._is_safe_home_path(self.home_dir):
                print("    [-] Refusing to remove unexpected home path")
                return False

            if os.path.exists(self.home_dir):
                def _onerror(func, path, exc_info):
                    try:
                        # Clear immutable flags if set (best-effort).
                        try:
                            libc_path = ctypes.util.find_library('c') or '/usr/lib/libSystem.B.dylib'
                            libc = ctypes.CDLL(libc_path, use_errno=True)
                            if hasattr(libc, 'chflags'):
                                libc.chflags.argtypes = [ctypes.c_char_p, ctypes.c_uint]
                                libc.chflags.restype = ctypes.c_int
                                libc.chflags(os.fsencode(path), 0)
                        except Exception:
                            pass

                        os.chmod(path, 0o700)
                        func(path)
                    except Exception:
                        raise

                shutil.rmtree(self.home_dir, onerror=_onerror)
            return True
        except PermissionError as e:
            # Cleanup failure should not fail the telemetry action itself.
            print(f"    [!] Cleanup permission error (continuing): {e}")
            print(f"    [!] Leftover path: {self.home_dir}")
            return True
        except Exception as e:
            # Some environments may still refuse removal (ACLs / flags / policy).
            # Treat as non-fatal, but keep it noisy so the operator can clean up.
            print(f"    [!] Failed removing home directory (continuing): {e}")
            print(f"    [!] Leftover path: {self.home_dir}")
            return True

    def _record_exists(self) -> bool:
        if not self.od_client:
            return False
        try:
            session, node = self.od_client._open_local_node()
            try:
                rec = self.od_client._copy_user_record(node, self.test_username)
                exists = bool(rec)
                if rec:
                    self.od_client._release(rec)
                return exists
            finally:
                self.od_client._release(node)
                self.od_client._release(session)
        except Exception:
            return False

    def run(self) -> bool:
        print("[*] Running User Account Activity demonstrations (system API-only)...")
        if not self.od_client:
            print("    [-] OpenDirectory APIs unavailable; cannot run UserAccountEvents")
            return False

        try:
            # Pre-clean stale artifacts from previous interrupted runs.
            self.od_client.delete_user(self.test_username)
            self._remove_home_dir()

            print("\n    === User Create (OpenDirectory) ===")
            ok1 = self.od_client.upsert_user(
                username=self.test_username,
                realname="EDR Telemetry Test User",
                uid=self.test_uid,
                gid=self.test_gid_initial,
                home_dir=self.home_dir,
            )
            ok1 = ok1 and self._record_exists()
            ok2 = self._create_home_dir()
            time.sleep(2)

            print("\n    === User Modify (OpenDirectory) ===")
            ok3 = self.od_client.upsert_user(
                username=self.test_username,
                realname="EDR Telemetry Test User (Modified)",
                uid=self.test_uid,
                gid=self.test_gid_initial,
                home_dir=self.home_dir,
            )
            ok3 = ok3 and self._record_exists()
            time.sleep(2)

            print("\n    === Group Membership Change (OpenDirectory) ===")
            ok4 = self.od_client.upsert_user(
                username=self.test_username,
                realname="EDR Telemetry Test User (Modified)",
                uid=self.test_uid,
                gid=self.test_gid_modified,
                home_dir=self.home_dir,
            )
            ok4 = ok4 and self._record_exists()
            time.sleep(2)

            print("\n    === User Delete (OpenDirectory) ===")
            ok5 = self.od_client.delete_user(self.test_username)
            ok5 = ok5 and (not self._record_exists())
            ok6 = self._remove_home_dir()

            return ok1 and ok2 and ok3 and ok4 and ok5 and ok6
        except Exception as e:
            print(f"    [-] OpenDirectory user flow failed: {e}")
            # Best-effort cleanup to avoid leaving a partial record/artifacts.
            try:
                if self.od_client:
                    self.od_client.delete_user(self.test_username)
            except Exception:
                pass
            try:
                self._remove_home_dir()
            except Exception:
                pass
            return False


def user_account_events() -> bool:
    return UserAccountManager().run()


if __name__ == "__main__":
    raise SystemExit(0 if user_account_events() else 1)
