import ctypes
import ctypes.util
import os
import shutil
import time

# memfd_create flags from <sys/mman.h> / <linux/memfd.h>
MFD_CLOEXEC = 0x0001
MFD_ALLOW_SEALING = 0x0002
MFD_HUGETLB = 0x0004
MFD_NOEXEC_SEAL = 0x0008
MFD_EXEC = 0x0010


def _libc():
    libc_path = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libc_path, use_errno=True)
    # int memfd_create(const char *name, unsigned int flags);
    libc.memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    libc.memfd_create.restype = ctypes.c_int
    return libc


def _memfd_create(libc, name: bytes, flags: int) -> int:
    fd = libc.memfd_create(name, flags)
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), name.decode("utf-8", "replace"))
    return fd


def _flags_to_str(flags: int) -> str:
    parts = []
    for value, label in (
        (MFD_CLOEXEC, "MFD_CLOEXEC"),
        (MFD_ALLOW_SEALING, "MFD_ALLOW_SEALING"),
        (MFD_HUGETLB, "MFD_HUGETLB"),
        (MFD_NOEXEC_SEAL, "MFD_NOEXEC_SEAL"),
        (MFD_EXEC, "MFD_EXEC"),
    ):
        if flags & value:
            parts.append(label)
    return "|".join(parts) if parts else "0"


def _create_variants(libc):
    """Exercise memfd_create with several flag combinations to surface
    process.Ext.memfd.flag.* fields in EDR telemetry."""
    variants = [
        (b"telemgen-payload-default", 0),
        (b"telemgen-payload-cloexec", MFD_CLOEXEC),
        (b"telemgen-payload-sealing", MFD_CLOEXEC | MFD_ALLOW_SEALING),
        (b"telemgen-payload-noexec", MFD_CLOEXEC | MFD_NOEXEC_SEAL),
        (b"telemgen-payload-exec", MFD_CLOEXEC | MFD_EXEC),
    ]
    fds = []
    for name, flags in variants:
        try:
            fd = _memfd_create(libc, name, flags)
        except OSError as e:
            print(f"[!] memfd_create({name!r}, {_flags_to_str(flags)}) failed: {e}")
            continue
        print(f"[+] memfd_create({name.decode()}, {_flags_to_str(flags)}) -> fd={fd}")
        fds.append((fd, name.decode()))
    return fds


def _copy_into_fd(src_path: str, dst_fd: int) -> None:
    with open(src_path, "rb") as src:
        while True:
            chunk = src.read(64 * 1024)
            if not chunk:
                break
            os.write(dst_fd, chunk)


def _exec_from_memfd(libc):
    """Stage /bin/true (or /bin/sh) into an exec-flagged memfd and exec it
    from /proc/self/fd/<fd>. Confirms memfd-backed execution telemetry."""
    src = shutil.which("true") or "/bin/true"
    if not os.path.isfile(src):
        print(f"[!] Skipping memfd-backed exec: {src} not present")
        return

    name = b"telemgen-loader"
    flags = MFD_CLOEXEC | MFD_EXEC
    try:
        fd = _memfd_create(libc, name, flags)
    except OSError as e:
        # Older kernels (pre-6.3) reject MFD_EXEC. Fall back to plain CLOEXEC.
        try:
            fd = _memfd_create(libc, name, MFD_CLOEXEC)
        except OSError as e2:
            print(f"[!] memfd_create for exec failed: {e2}")
            return

    try:
        _copy_into_fd(src, fd)
        proc_path = f"/proc/self/fd/{fd}"
        print(f"[+] Forking child to execve {proc_path} (memfd-backed exec of {src})")
        pid = os.fork()
        if pid == 0:
            try:
                os.execv(proc_path, ["telemgen-loader"])
            except Exception as e:
                print(f"[child] execv failed: {e}")
                os._exit(127)
        else:
            _, status = os.waitpid(pid, 0)
            print(f"[+] memfd-backed child exited with status {status}")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def run_memfd_create():
    """Entry point invoked by lnx_telem_gen.py."""
    libc = _libc()
    fds = _create_variants(libc)
    time.sleep(0.5)
    _exec_from_memfd(libc)
    for fd, _ in fds:
        try:
            os.close(fd)
        except OSError:
            pass
    return "memfd_create variants emitted"


if __name__ == "__main__":
    run_memfd_create()
