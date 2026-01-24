#!/usr/bin/env python3
"""
macOS Telemetry Generator

This script generates various telemetry events for EDR (Endpoint Detection and Response)
testing on macOS. It performs controlled actions using syscalls and API calls to produce
known events that can be used to validate EDR telemetry capture capabilities.

The script avoids reliance on system binaries where possible, using direct syscalls
and API calls instead, which prevents EDRs from inferring activity based solely on
command line arguments or binaries executed.

Usage:
    python3 macos_telem_gen.py [Event1 Event2 ...]

If no events are specified, all available events will be executed.

Author: @kostastsale - EDR Telemetry Project Author
"""

import os
import sys
import time
import socket
import signal
import csv
import traceback
import ctypes
import ctypes.util
import struct
import tempfile
import plistlib
import time
from pathlib import Path
from datetime import datetime

from native import find_processes_by_name, xattr_get, xattr_remove, xattr_set

# Import complex modules
from complex.process_injection import process_injection_demo
from complex.persistence_launchd import launchd_persistence
from complex.persistence_loginitem import loginitem_persistence
from complex.user_account_manager import UserAccountManager
from complex.kext_operations import kext_operations
from complex.tcc_operations import tcc_operations
from complex.session_activity import session_activity_events
from complex.codesign_trust import codesign_trust_events
from complex.service_activity import service_activity_events

try:
    from prettytable import PrettyTable
    HAS_PRETTYTABLE = True
except ImportError:
    HAS_PRETTYTABLE = False
    print("Note: prettytable not installed. Install with: pip3 install prettytable so you can see a nice table of what your EDR missed")

# Load libc for syscalls (capture errno reliably)
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

# macOS syscall numbers (x86_64) from the official XNU kernel source (https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master)
SYS_fork = 2
SYS_read = 3
SYS_write = 4
SYS_open = 5
SYS_close = 6
SYS_kill = 37
SYS_getpid = 20
SYS_socket = 97
SYS_connect = 98
SYS_bind = 104
SYS_listen = 106
SYS_ptrace = 26


class ProcessActivityManager:
    """
    Manages process-related telemetry events including:
    - Process Creation (fork/exec)
    - Process Termination (kill/signal)
    """

    @staticmethod
    def process_creation():
        """
        Creates a child process using fork() syscall.
        This generates process creation telemetry.
        """
        print("[*] Triggering Process Creation via fork()...")
        try:
            pid = os.fork()
            if pid == 0:
                # Child process
                print(f"    [Child] Process created with PID: {os.getpid()}")
                time.sleep(2)
                os._exit(0)
            else:
                # Parent process
                print(f"    [Parent] Created child process with PID: {pid}")
                os.waitpid(pid, 0)
                print(f"    [Parent] Child process {pid} completed")
            return True
        except Exception as e:
            print(f"[-] Process creation failed: {e}")
            return False

    @staticmethod
    def process_termination():
        """
        Creates and terminates a process using kill() syscall.
        This generates process termination telemetry.
        """
        print("[*] Triggering Process Termination via kill()...")
        try:
            pid = os.fork()
            if pid == 0:
                # Child process - sleep indefinitely
                while True:
                    time.sleep(1)
            else:
                # Parent process
                print(f"    [Parent] Created child process with PID: {pid}")
                time.sleep(1)
                
                # Send SIGTERM signal
                os.kill(pid, signal.SIGTERM)
                print(f"    [Parent] Sent SIGTERM to process {pid}")
                
                # Wait for child to terminate
                os.waitpid(pid, 0)
                print(f"    [Parent] Process {pid} terminated successfully")
            return True
        except Exception as e:
            print(f"[-] Process termination failed: {e}")
            return False

    @staticmethod
    def privilege_escalation_sudo():
        """
        Demonstrates privilege escalation-related syscalls.

        Project goal is syscall/API-driven telemetry without invoking system
        utilities like `sudo`. This test attempts privilege transitions via
        set*id calls which should generate relevant telemetry (success or EPERM).
        """
        print("[*] Triggering Privilege Escalation via setuid/seteuid...")
        try:
            libc.seteuid.argtypes = [ctypes.c_uint]
            libc.seteuid.restype = ctypes.c_int
            libc.setegid.argtypes = [ctypes.c_uint]
            libc.setegid.restype = ctypes.c_int

            original_euid = os.geteuid()
            original_egid = os.getegid()

            # Attempt to become root (will fail with EPERM when not privileged)
            res_gid = libc.setegid(0)
            if res_gid != 0:
                print(f"    [!] setegid(0) failed, errno: {ctypes.get_errno()}")
            else:
                print("    [+] setegid(0) succeeded")

            res_uid = libc.seteuid(0)
            if res_uid != 0:
                print(f"    [!] seteuid(0) failed, errno: {ctypes.get_errno()}")
            else:
                print("    [+] seteuid(0) succeeded")

            # Best-effort restore
            libc.seteuid(original_euid)
            libc.setegid(original_egid)

            return True
        except Exception as e:
            print(f"[-] Privilege escalation test failed: {e}")
            return False


class FunActivityManager:
    @staticmethod
    def edr_marketing_hype():
        print("[*] Running EDR reality check...")
        time.sleep(2)
        print("    [+] Achieving 100% detection rate...")
        time.sleep(2)
        print("    [+] Establishing all the coverage...")
        time.sleep(2)
        print("    [+] Securing Gartner quadrant position...")
        time.sleep(2)
        print("    [+] Your RAM is mine, but at least you're safe...")
        time.sleep(2)
        print("    [+] Creating fake threat actor names...")
        time.sleep(2)
        print("    [+] Achieving 100% detection rate for the 2nd time...")
        time.sleep(3)
        print("    [+] Melting your CPU while attempting to push the telemetry to the cloud.")
        time.sleep(3)
        print("    [+] Almost done, dealing with the false positives...")
        time.sleep(3)
        print("    [+] 100% detection rate achieved. (for 3rd time but who's counting)")
        time.sleep(3)
        return True


class FileActivityManager:
    """
    Manages file-related telemetry events including:
    - File Creation
    - File Modification
    - File Deletion
    - File Attribute Change
    """

    def __init__(self):
        # Use /tmp explicitly to avoid per-user /var/folders permission issues
        # when running under sudo with inherited TMPDIR.
        self.test_dir = tempfile.mkdtemp(prefix="edr_telem_", dir="/tmp")
        self.test_file = os.path.join(self.test_dir, "test_file.txt")

    @staticmethod
    def _syscall_open(path, flags, mode=0o644):
        """Open file using syscall"""
        path_bytes = path.encode('utf-8')
        return libc.open(path_bytes, flags, mode)

    @staticmethod
    def _syscall_write(fd, data):
        """Write to file using syscall"""
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        return libc.write(fd, data_bytes, len(data_bytes))

    @staticmethod
    def _syscall_close(fd):
        """Close file using syscall"""
        return libc.close(fd)

    @staticmethod
    def _syscall_read(fd, size=4096):
        """Read from file using syscall"""
        buf = ctypes.create_string_buffer(size)
        n = libc.read(fd, buf, size)
        if n < 0:
            return None
        return buf.raw[:n]

    def file_creation(self):
        """
        Creates a file using open() syscall with O_CREAT flag.
        This generates file creation telemetry.
        """
        print("[*] Triggering File Creation via open() syscall...")
        try:
            O_CREAT = 0x0200
            O_WRONLY = 0x0001
            O_TRUNC = 0x0400
            
            fd = self._syscall_open(self.test_file, O_CREAT | O_WRONLY | O_TRUNC, 0o644)
            if fd < 0:
                raise OSError(f"Failed to create file, errno: {ctypes.get_errno()}")
            
            self._syscall_write(fd, "This file was written, but your Gartner quadrant position is safe\n")
            self._syscall_close(fd)

            # Ensure predictable permissions regardless of umask.
            path_bytes = self.test_file.encode('utf-8')
            libc.chmod(path_bytes, 0o644)
            
            print(f"    [+] File created: {self.test_file}")
            return True
        except Exception as e:
            print(f"[-] File creation failed: {e}")
            return False

    def file_modification(self):
        """
        Modifies a file using write() syscall.
        This generates file modification telemetry.
        """
        print("[*] Triggering File Modification via write() syscall...")
        try:
            O_WRONLY = 0x0001
            O_APPEND = 0x0008
            
            fd = self._syscall_open(self.test_file, O_WRONLY | O_APPEND)
            if fd < 0:
                # Create file if it doesn't exist
                self.file_creation()
                fd = self._syscall_open(self.test_file, O_WRONLY | O_APPEND)
            
            timestamp = datetime.now().isoformat()
            self._syscall_write(fd, f"Modified at: {timestamp} - your 'behavioral AI' is still buffering\n")
            self._syscall_close(fd)
            
            print(f"    [+] File modified: {self.test_file}")
            return True
        except Exception as e:
            print(f"[-] File modification failed: {e}")
            return False

    def file_deletion(self):
        """
        Deletes a file using unlink() syscall.
        This generates file deletion telemetry.
        """
        print("[*] Triggering File Deletion via unlink() syscall...")
        try:
            if not os.path.exists(self.test_file):
                self.file_creation()
            
            path_bytes = self.test_file.encode('utf-8')
            result = libc.unlink(path_bytes)
            
            if result != 0:
                raise OSError(f"Failed to delete file, errno: {ctypes.get_errno()}")
            
            print(f"    [+] File deleted: {self.test_file}")
            return True
        except Exception as e:
            print(f"[-] File deletion failed: {e}")
            return False

    def file_attribute_change(self):
        """
        Changes file attributes using chmod() and chown() syscalls.
        This generates file attribute change telemetry.
        """
        print("[*] Triggering File Attribute Change via chmod()/chown()...")
        try:
            if not os.path.exists(self.test_file):
                self.file_creation()
            
            path_bytes = self.test_file.encode('utf-8')
            
            # Change file mode using chmod syscall
            result = libc.chmod(path_bytes, 0o755)
            if result != 0:
                print(f"    [!] chmod failed, errno: {ctypes.get_errno()}")
            else:
                print(f"    [+] File mode changed to 755: {self.test_file}")
            
            # Change back to original
            libc.chmod(path_bytes, 0o644)
            print(f"    [+] File mode restored to 644: {self.test_file}")
            
            return True
        except Exception as e:
            print(f"[-] File attribute change failed: {e}")
            return False

    def extended_attributes(self):
        """
        Sets and removes extended attributes using setxattr/removexattr.
        This generates extended attribute telemetry.
        """
        print("[*] Triggering Extended Attribute operations...")
        try:
            if not os.path.exists(self.test_file):
                self.file_creation()

            xattr_name = "user.edr_test"
            xattr_value = b"telemetry_test_value_mitre_100_coverage"

            rc = xattr_set(self.test_file, xattr_name, xattr_value)
            if rc != 0:
                print(f"    [!] setxattr failed, errno: {ctypes.get_errno()}")
            else:
                print(f"    [+] Extended attribute set: {xattr_name}")

            value = xattr_get(self.test_file, xattr_name)
            print(f"    [+] Extended attribute read: {value}")

            rc = xattr_remove(self.test_file, xattr_name)
            if rc != 0:
                print(f"    [!] removexattr failed, errno: {ctypes.get_errno()}")
            else:
                print(f"    [+] Extended attribute removed: {xattr_name}")

            return True
        except Exception as e:
            print(f"[-] Extended attribute operations failed: {e}")
            return False

    def file_open_access(self):
        """Open an existing file and read bytes (no modification).

        Intended to generate File Open/Access telemetry (e.g. ES open events).
        """

        print("[*] Triggering File Open/Access via open()/read()...")
        try:
            if not os.path.exists(self.test_file):
                self.file_creation()

            O_RDONLY = 0x0000
            ctypes.set_errno(0)
            fd = self._syscall_open(self.test_file, O_RDONLY)
            if fd < 0:
                # Retry once after recreating the file (handles races / stale path)
                errno1 = ctypes.get_errno()
                print(f"    [!] open() failed, errno: {errno1} ({os.strerror(errno1) if errno1 else 'unknown'})")
                self.file_creation()
                ctypes.set_errno(0)
                fd = self._syscall_open(self.test_file, O_RDONLY)
                if fd < 0:
                    errno2 = ctypes.get_errno()
                    raise OSError(f"Failed to open file, errno: {errno2} ({os.strerror(errno2) if errno2 else 'unknown'})")

            data = self._syscall_read(fd, 64)
            self._syscall_close(fd)

            if data is None:
                print(f"    [+] Opened file (read returned no data): {self.test_file}")
            else:
                print(f"    [+] Opened and read {len(data)} bytes: {self.test_file}")

            return True
        except Exception as e:
            print(f"[-] File open/access failed: {e}")
            return False

    def cleanup(self):
        """Clean up test files and directories"""
        try:
            import shutil
            if os.path.exists(self.test_dir):
                shutil.rmtree(self.test_dir)
        except Exception:
            pass


class NetworkActivityManager:
    """
    Manages network-related telemetry events including:
    - Network Connection
    - Network Socket Listen
    - DNS Query
    """

    @staticmethod
    def network_connection():
        """
        Creates an outbound TCP connection using socket() and connect() syscalls.
        This generates network connection telemetry.
        """
        print("[*] Triggering Network Connection via socket()/connect()...")
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Connect to a well-known service (Google DNS)
            target = ("8.8.8.8", 53)
            print(f"    [*] Connecting to {target[0]}:{target[1]}...")
            
            sock.connect(target)
            print(f"    [+] Connection established to {target[0]}:{target[1]}")
            
            sock.close()
            print("    [+] Connection closed")
            return True
        except socket.timeout:
            print("    [!] Connection timed out (event still generated)")
            return True
        except Exception as e:
            print(f"[-] Network connection failed: {e}")
            return False

    @staticmethod
    def network_listen():
        """
        Creates a listening socket using socket(), bind(), and listen() syscalls.
        This generates network socket listen telemetry.
        """
        print("[*] Triggering Network Socket Listen via bind()/listen()...")
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to a high port
            port = 54321
            sock.bind(('127.0.0.1', port))
            sock.listen(5)
            
            print(f"    [+] Listening on 127.0.0.1:{port}")
            
            # Brief pause to allow telemetry capture
            time.sleep(1)
            
            sock.close()
            print("    [+] Listener closed")
            return True
        except Exception as e:
            print(f"[-] Network listen failed: {e}")
            return False

    @staticmethod
    def dns_query():
        """
        Performs DNS resolution using getaddrinfo().
        This generates DNS query telemetry.
        """
        print("[*] Triggering DNS Query via getaddrinfo()...")
        try:
            domains = [
                "google.com",
                "apple.com",
                "gartner.com"
            ]
            
            for domain in domains:
                try:
                    result = socket.getaddrinfo(domain, 80, socket.AF_INET)
                    ip = result[0][4][0]
                    print(f"    [+] DNS query: {domain} -> {ip}")
                except socket.gaierror as e:
                    print(f"    [!] DNS query failed for {domain}: {e}")
            
            return True
        except Exception as e:
            print(f"[-] DNS query failed: {e}")
            return False

    @staticmethod
    def raw_socket():
        """
        Creates a raw socket (requires root privileges).
        This generates raw socket telemetry.
        """
        print("[*] Triggering Raw Socket creation...")
        try:
            # Raw sockets require root
            if os.geteuid() != 0:
                print("    [!] Raw socket creation requires root privileges")
                print("    [!] Skipping raw socket test")
                return True
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            print("    [+] Raw socket created (ICMP)")
            sock.close()
            print("    [+] Raw socket closed")
            return True
        except PermissionError:
            print("    [!] Permission denied for raw socket (requires root)")
            return True
        except Exception as e:
            print(f"[-] Raw socket creation failed: {e}")
            return False


class ScheduledTaskManager:
    """
    Manages scheduled task and persistence-related telemetry events including:
    - Cron job creation/deletion
    - Launchd item management
    - Login item management
    """

    @staticmethod
    def cron_task():
        """
        Creates and removes a cron job.
        This generates scheduled task telemetry.
        """
        print("[*] Triggering Cron Task creation/deletion...")
        try:
            # Avoid `crontab` binary; directly modify cron tab files.
            marker = "# EDR Telemetry Test (edr_telem_test)\n"
            cron_line = "* * * * * /usr/bin/true # edr_telem_test\n"
            cron_entry = marker + cron_line

            # Determine which user's cron to target.
            username = os.environ.get('SUDO_USER') or os.environ.get('USER') or None
            if not username:
                try:
                    username = os.getlogin()
                except Exception:
                    username = None

            if not username:
                print("    [!] Could not determine username for cron tabs")
                return True

            tab_dirs = ['/usr/lib/cron/tabs', '/private/var/at/tabs', '/var/at/tabs']
            tab_dir = next((d for d in tab_dirs if os.path.isdir(d)), None)
            if not tab_dir:
                print("    [!] Cron tabs directory not found on this system")
                return True

            tab_path = os.path.join(tab_dir, username)
            print(f"    [*] Target cron tab file: {tab_path}")

            try:
                try:
                    with open(tab_path, 'r', encoding='utf-8', errors='replace') as f:
                        original = f.read()
                except FileNotFoundError:
                    original = ""

                cleaned = original.replace(cron_entry, "")
                if cleaned and not cleaned.endswith("\n"):
                    cleaned += "\n"

                with open(tab_path, 'w', encoding='utf-8') as f:
                    f.write(cleaned + cron_entry)
                os.chmod(tab_path, 0o600)
                print("    [+] Cron tab modified (entry added)")

                # Ask cron to reload, mirroring what crontab does.
                for pid, name in find_processes_by_name(["cron"]):
                    try:
                        os.kill(pid, signal.SIGHUP)
                        print(f"    [+] Sent SIGHUP to {name} ({pid})")
                    except Exception:
                        pass

                time.sleep(2)

                with open(tab_path, 'r', encoding='utf-8', errors='replace') as f:
                    current = f.read()

                restored = current.replace(cron_entry, "")
                with open(tab_path, 'w', encoding='utf-8') as f:
                    f.write(restored)
                os.chmod(tab_path, 0o600)
                print("    [+] Cron tab modified (entry removed)")

                for pid, name in find_processes_by_name(["cron"]):
                    try:
                        os.kill(pid, signal.SIGHUP)
                        print(f"    [+] Sent SIGHUP to {name} ({pid})")
                    except Exception:
                        pass

            except PermissionError:
                print("    [!] Permission denied modifying cron tabs (expected without root)")
                return True

            return True
        except Exception as e:
            print(f"[-] Cron task operation failed: {e}")
            return False


class AccessActivityManager:
    """
    Manages access-related telemetry events including:
    - Raw Device Access
    - Process Access (ptrace)
    """

    @staticmethod
    def raw_device_access():
        """
        Attempts to read from a raw device.
        This generates raw device access telemetry.
        """
        print("[*] Triggering Raw Device Access...")
        try:
            # Try to read from /dev/rdisk0 (requires root)
            device = "/dev/rdisk0"
            
            if os.geteuid() != 0:
                print(f"    [!] Raw device access requires root privileges")
                print(f"    [!] Attempting read on {device} anyway...")
            
            try:
                with open(device, 'rb') as f:
                    data = f.read(512)  # Read first sector
                    print(f"    [+] Read {len(data)} bytes from {device}")
            except PermissionError:
                print(f"    [!] Permission denied for {device} (expected without root)")
            except FileNotFoundError:
                # Try alternative device
                device = "/dev/disk0"
                try:
                    with open(device, 'rb') as f:
                        data = f.read(512)
                        print(f"    [+] Read {len(data)} bytes from {device}")
                except Exception as e:
                    print(f"    [!] Could not access {device}: {e}")
            
            return True
        except Exception as e:
            print(f"[-] Raw device access failed: {e}")
            return False

    @staticmethod
    def process_access():
        """
        Demonstrates process access using task_for_pid or ptrace.
        Note: ptrace is limited on macOS and task_for_pid requires entitlements.
        """
        print("[*] Triggering Process Access detection...")
        try:
            # On macOS, ptrace is very limited
            # We'll demonstrate by attempting to trace our own process
            
            # PT_DENY_ATTACH = 31 (prevents debugging)
            # PT_TRACE_ME = 0
            PT_TRACE_ME = 0
            
            # Fork a child and attempt to trace it
            pid = os.fork()
            if pid == 0:
                # Child: allow tracing
                time.sleep(5)
                os._exit(0)
            else:
                # Parent: attempt to trace child
                print(f"    [*] Attempting to trace process {pid}...")
                
                # ptrace on macOS has limited functionality
                # Most operations require special entitlements
                try:
                    result = libc.ptrace(26, pid, 0, 0)  # PT_ATTACH = 26 on macOS
                    if result == 0:
                        print(f"    [+] Successfully attached to process {pid}")
                        libc.ptrace(27, pid, 0, 0)  # PT_DETACH = 27
                        print(f"    [+] Detached from process {pid}")
                    else:
                        print(f"    [!] ptrace attach failed (expected on macOS)")
                except Exception as e:
                    print(f"    [!] ptrace operation failed: {e}")
                
                os.kill(pid, signal.SIGTERM)
                os.waitpid(pid, 0)
            
            return True
        except Exception as e:
            print(f"[-] Process access failed: {e}")
            return False


class ScriptActivityManager:
    """
    Manages script execution telemetry events.
    """

    @staticmethod
    def script_execution():
        """
        Executes various script types to generate script execution telemetry.
        """
        print("[*] Triggering Script Execution events...")
        try:
            # Create and execute a Python script
            script_path = "/tmp/edr_test_script.py"
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write("print(\"Script executed, your 'next-gen' protection missed it\")\n")
            os.chmod(script_path, 0o755)
            
            # Execute script via execve() (no shell)
            print("    [*] Executing script via execve()...")
            pid = os.fork()
            if pid == 0:
                os.execve(sys.executable, [sys.executable, script_path], os.environ.copy())
            os.waitpid(pid, 0)
            print("    [+] Script executed")
            
            # Additional script types (shell/AppleScript) intentionally omitted
            # to avoid invoking external binaries.

            # Cleanup
            os.unlink(script_path)
            
            return True
        except Exception as e:
            print(f"[-] Script execution failed: {e}")
            return False


class DeviceActivityManager:
    """
    Manages device-related telemetry events.
    """

    @staticmethod
    def external_media_detection():
        """
        Lists mounted volumes to demonstrate external media detection.
        Note: Actual mount/unmount requires physical devices or disk images.
        """
        print("[*] Checking for External Media (mounted volumes)...")
        try:
            # List volumes in /Volumes
            volumes_path = "/Volumes"
            if os.path.exists(volumes_path):
                volumes = os.listdir(volumes_path)
                print(f"    [+] Found {len(volumes)} mounted volume(s):")
                for vol in volumes:
                    vol_path = os.path.join(volumes_path, vol)
                    print(f"        - {vol}")
            
            # Mount/unmount telemetry requires DiskArbitration / mounting APIs.
            # We intentionally avoid `hdiutil` and other external binaries.
            print("    [!] Disk image mount/unmount not performed in syscall-only mode")
            
            return True
        except Exception as e:
            print(f"[-] External media detection failed: {e}")
            return False


file_activity = FileActivityManager()

# Event function mapping
event_functions = {
    # Process Activity
    'ProcessCreation': ProcessActivityManager.process_creation,
    'ProcessTermination': ProcessActivityManager.process_termination,
    'PrivilegeEscalation': ProcessActivityManager.privilege_escalation_sudo,
    
    # File Activity
    'FileCreation': file_activity.file_creation,
    'FileModification': file_activity.file_modification,
    'FileDeletion': file_activity.file_deletion,
    'FileAttributeChange': file_activity.file_attribute_change,
    'ExtendedAttributes': file_activity.extended_attributes,
    'FileOpenAccess': file_activity.file_open_access,
    
    # Network Activity
    'NetworkConnection': NetworkActivityManager.network_connection,
    'NetworkListen': NetworkActivityManager.network_listen,
    'DNSQuery': NetworkActivityManager.dns_query,
    'RawSocket': NetworkActivityManager.raw_socket,
    
    # User & Session Activity
    'SessionActivity': session_activity_events,
    
    # Scheduled Task & Persistence
    'CronTask': ScheduledTaskManager.cron_task,
    'LaunchdPersistence': launchd_persistence,
    'LoginItemPersistence': loginitem_persistence,
    
    # User Account Activity
    'UserAccountEvents': UserAccountManager().run,
    
    # Access Activity
    'RawDeviceAccess': AccessActivityManager.raw_device_access,
    'ProcessAccess': AccessActivityManager.process_access,
    'ProcessInjection': process_injection_demo,
    
    # System Extension & Driver Activity
    'KextOperations': kext_operations,
    
    # Code Signing & Trust Activity
    'CodeSignTrust': codesign_trust_events,
    
    # Privacy & TCC Activity
    'TCCOperations': tcc_operations,
    
    # Script Activity
    'ScriptExecution': ScriptActivityManager.script_execution,

    'EDRCoverageEvaluation': FunActivityManager.edr_marketing_hype,
    
    # Device Activity
    'ExternalMedia': DeviceActivityManager.external_media_detection,
    
    # Service Activity
    'ServiceActivity': service_activity_events,
}


EXPLICIT_ONLY_EVENTS = {
    'EDRCoverageEvaluation',
}


def log_to_csv(function_name, output, error=None):
    """Log function execution results to CSV file."""
    with open('macos_telemetry_log.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        timestamp = datetime.now().isoformat()
        writer.writerow([timestamp, function_name, output, error or ""])


def print_banner():
    """Print the tool banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ███╗   ███╗ █████╗  ██████╗ ██████╗ ███████╗                  ║
║   ████╗ ████║██╔══██╗██╔════╝██╔═══██╗██╔════╝                  ║
║   ██╔████╔██║███████║██║     ██║   ██║███████╗                  ║
║   ██║╚██╔╝██║██╔══██║██║     ██║   ██║╚════██║                  ║
║   ██║ ╚═╝ ██║██║  ██║╚██████╗╚██████╔╝███████║                  ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝                  ║
║                                                                  ║
║   Telemetry Generator for EDR Testing                           ║
║   https://github.com/tsale/EDR-Telemetry                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def main():
    """Main function to run telemetry generation tests."""
    print_banner()

    if os.geteuid() != 0:
        print("[-] This tool must be run as root to generate the expected telemetry.")
        print("    Re-run with: sudo python3 macos_telem_gen.py")
        sys.exit(1)
    
    # Initialize CSV log file
    with open('macos_telemetry_log.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Function", "Status", "Error"])
    
    # Parse command-line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print("Usage: sudo python3 macos_telem_gen.py [Event1 Event2 ...]")
            print("\nAvailable events:")
            for event in sorted(event_functions.keys()):
                print(f"  - {event}")
            sys.exit(0)
        selected_events = sys.argv[1:]
    else:
        selected_events = [
            event for event in event_functions.keys()
            if event not in EXPLICIT_ONLY_EVENTS
        ]
    
    # Validate selected events
    valid_events = set(selected_events).intersection(event_functions.keys())
    invalid_events = set(selected_events) - valid_events
    
    if invalid_events:
        print(f"[!] Warning: Unknown events will be skipped: {', '.join(invalid_events)}")
    
    if not valid_events:
        print("[-] No valid events specified.")
        print("Available events:", ', '.join(sorted(event_functions.keys())))
        sys.exit(1)
    
    # Initialize counters
    total_events = len(valid_events)
    successful_events = 0
    failed_events = 0
    failed_event_names = []
    
    print(f"\n[*] Running {total_events} telemetry event(s)...\n")
    print("Your EDR starts sweatin'...\n")
    print("=" * 70)
    
    # Execute selected events
    for i, event in enumerate(sorted(valid_events), 1):
        print(f"\n[{i}/{total_events}] Running: {event}")
        print("-" * 50)
        
        try:
            result = event_functions[event]()
            if result:
                log_to_csv(event, "Success")
                successful_events += 1
                print(f"[+] {event}: SUCCESS")
            else:
                log_to_csv(event, "Failed", "Function returned False")
                failed_events += 1
                failed_event_names.append(event)
                print(f"[-] {event}: FAILED")
        except Exception as e:
            error_msg = traceback.format_exc()
            log_to_csv(event, "Error", str(e))
            failed_events += 1
            failed_event_names.append(event)
            print(f"[-] {event}: ERROR - {e}")
        
        # Brief delay between events
        time.sleep(1)
    
    # Print summary
    print("\n" + "=" * 70)
    print("\n[*] SUMMARY")
    print("-" * 50)
    
    if HAS_PRETTYTABLE:
        table = PrettyTable()
        table.field_names = ["Total Events", "Successful", "Failed"]
        table.add_row([total_events, successful_events, failed_events])
        print(table)
    else:
        print(f"Total Events:  {total_events}")
        print(f"Successful:    {successful_events}")
        print(f"Failed:        {failed_events}")
    
    if failed_event_names:
        print("\nFailed Events:")
        for event in failed_event_names:
            print(f"  - {event}")
    
    print(f"\n[*] Results logged to: macos_telemetry_log.csv")
    print("[*] Script execution completed.")
    print("[*] Time to see what your EDR saw... (or didn't)")

    # Cleanup artifacts created by file tests
    file_activity.cleanup()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
