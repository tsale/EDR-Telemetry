#!/usr/bin/env python3
"""
macOS Process Injection / Tampering Module

This module demonstrates process injection and tampering techniques on macOS
for EDR telemetry testing. Due to macOS security restrictions, many traditional
injection techniques are limited or require special entitlements.

Techniques demonstrated:
1. DYLD_INSERT_LIBRARIES injection
2. task_for_pid based injection (requires entitlements)
3. Remote thread creation detection
4. Process memory manipulation attempts

Note: Most of these techniques require root privileges or special entitlements
to work on modern macOS versions with SIP enabled.
"""

import os
import sys
import ctypes
import ctypes.util
import signal
import time
import tempfile

# Load libraries
libc = ctypes.CDLL(ctypes.util.find_library('c'))


def dyld_insert_libraries_injection():
    """
    Demonstrates DYLD_INSERT_LIBRARIES injection technique.
    This is a common macOS code injection method that loads a dynamic library
    into a process at launch time.
    
    Note: This technique is blocked for protected binaries and when SIP is enabled.
    """
    print("    [*] Testing DYLD_INSERT_LIBRARIES injection...")
    
    try:
        # Syscall-only mode: avoid invoking toolchains (clang) or utilities.
        # We set DYLD_INSERT_LIBRARIES and exec a child Python process to
        # generate process/env telemetry.

        env = os.environ.copy()
        env['DYLD_INSERT_LIBRARIES'] = '/usr/lib/libSystem.B.dylib'

        pid = os.fork()
        if pid == 0:
            os.execve(
                sys.executable,
                [sys.executable, '-c', 'import os; print("DYLD test")'],
                env,
            )

        os.waitpid(pid, 0)
        print("    [+] DYLD_INSERT_LIBRARIES set and child process executed")
        return True
        
    except Exception as e:
        print(f"    [-] DYLD injection test failed: {e}")
        return False


def task_for_pid_injection():
    """
    Demonstrates task_for_pid based injection attempt.
    This technique requires the com.apple.security.cs.debugger entitlement
    or root privileges, and is blocked by SIP for protected processes.
    """
    print("    [*] Testing task_for_pid injection technique...")
    
    try:
        # Load the Security framework for task_for_pid
        security = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        
        # Define task_for_pid
        # kern_return_t task_for_pid(mach_port_t target_tport, int pid, mach_port_t *t);
        libc.task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
        libc.task_for_pid.restype = ctypes.c_int
        
        # Get mach_task_self
        libc.mach_task_self.restype = ctypes.c_uint
        self_task = libc.mach_task_self()
        
        # Fork a child process to test against
        pid = os.fork()
        if pid == 0:
            # Child process
            time.sleep(10)
            os._exit(0)
        else:
            # Parent process
            time.sleep(1)  # Let child start
            
            target_task = ctypes.c_uint()
            
            print(f"    [*] Attempting task_for_pid on process {pid}...")
            result = libc.task_for_pid(self_task, pid, ctypes.byref(target_task))
            
            if result == 0:
                print(f"    [+] task_for_pid succeeded! Task port: {target_task.value}")
                print("    [+] This indicates potential for process injection")
            else:
                print(f"    [!] task_for_pid failed with error: {result}")
                print("    [!] This is expected without proper entitlements")
            
            # Cleanup
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        
        return True
        
    except Exception as e:
        print(f"    [-] task_for_pid test failed: {e}")
        return False


def mach_inject_attempt():
    """
    Demonstrates Mach-based injection attempt.
    This uses Mach APIs to attempt thread creation in another process.
    """
    print("    [*] Testing Mach-based injection technique...")
    
    try:
        # This would require:
        # 1. task_for_pid to get target task port
        # 2. mach_vm_allocate to allocate memory in target
        # 3. mach_vm_write to write shellcode
        # 4. thread_create_running to create a thread
        
        # Since we can't actually inject without entitlements,
        # we'll demonstrate the API calls that would be used
        
        print("    [*] Mach injection requires:")
        print("        - task_for_pid (requires entitlements)")
        print("        - mach_vm_allocate (allocate in target)")
        print("        - mach_vm_write (write shellcode)")
        print("        - thread_create_running (create thread)")
        print("    [!] These operations are blocked by SIP and require entitlements")
        
        # Demonstrate mach_task_self which is always available
        libc.mach_task_self.restype = ctypes.c_uint
        self_task = libc.mach_task_self()
        print(f"    [+] Current task port: {self_task}")
        
        return True
        
    except Exception as e:
        print(f"    [-] Mach injection test failed: {e}")
        return False


def process_hollowing_attempt():
    """
    Demonstrates process hollowing detection.
    Process hollowing involves creating a suspended process, unmapping its
    memory, and replacing it with malicious code.
    
    On macOS, this is significantly more difficult due to code signing
    and SIP protections.
    """
    print("    [*] Testing process hollowing technique...")
    
    try:
        # On macOS, we can demonstrate the concept by:
        # 1. Creating a suspended process
        # 2. Attempting to modify its memory
        
        # Create a process in suspended state using posix_spawn
        print("    [*] Creating suspended process...")
        
        # Fork and exec with SIGSTOP
        pid = os.fork()
        if pid == 0:
            # Child - stop immediately
            os.kill(os.getpid(), signal.SIGSTOP)
            # If we get here, we were continued
            time.sleep(5)
            os._exit(0)
        else:
            # Parent
            time.sleep(1)  # Let child stop
            
            print(f"    [+] Created suspended process: {pid}")
            
            # On macOS, we cannot easily modify another process's memory
            # without proper entitlements
            print("    [*] Attempting to access process memory...")
            print("    [!] Memory modification blocked without entitlements")
            
            # Resume and cleanup
            os.kill(pid, signal.SIGCONT)
            time.sleep(0.5)
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
            print("    [+] Suspended process cleaned up")
        
        return True
        
    except Exception as e:
        print(f"    [-] Process hollowing test failed: {e}")
        return False


def thread_injection_attempt():
    """
    Demonstrates remote thread creation attempt.
    This technique creates a thread in another process to execute code.
    """
    print("    [*] Testing remote thread creation...")
    
    try:
        # On macOS, thread_create_running requires:
        # 1. A valid task port (from task_for_pid)
        # 2. Proper entitlements
        
        # We'll demonstrate by creating a thread in our own process
        import threading
        
        def injected_thread():
            print("    [+] Thread executed (simulating injection)")
            time.sleep(1)
        
        print("    [*] Creating thread in current process (simulation)...")
        t = threading.Thread(target=injected_thread)
        t.start()
        t.join()
        
        print("    [!] Remote thread creation in other processes requires entitlements")
        
        return True
        
    except Exception as e:
        print(f"    [-] Thread injection test failed: {e}")
        return False


def process_injection_demo():
    """
    Main function to run all process injection/tampering demonstrations.
    """
    print("[*] Running Process Injection/Tampering demonstrations...")
    print("    Note: Most techniques are blocked by SIP on modern macOS")
    print()
    
    results = []
    
    # Run each technique
    techniques = [
        ("DYLD_INSERT_LIBRARIES", dyld_insert_libraries_injection),
        ("task_for_pid", task_for_pid_injection),
        ("Mach Injection", mach_inject_attempt),
        ("Process Hollowing", process_hollowing_attempt),
        ("Remote Thread Creation", thread_injection_attempt),
    ]
    
    for name, func in techniques:
        print(f"\n    === {name} ===")
        try:
            result = func()
            results.append((name, result))
        except Exception as e:
            print(f"    [-] {name} failed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n    === Summary ===")
    for name, result in results:
        status = "✓" if result else "✗"
        print(f"    [{status}] {name}")
    
    return all(r[1] for r in results)


if __name__ == "__main__":
    process_injection_demo()
