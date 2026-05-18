import os
import secrets
import tempfile
from typing import Optional

# Sample magic-byte headers so EDRs can populate file.Ext.header_bytes /
# file.Ext.entropy with deterministic, recognisable inputs.
_FIXTURES = [
    # (file_name, header_bytes, body_bytes, expected_extension)
    ("telemgen_high_entropy.bin", b"", None, "bin"),                # random body, no header
    ("telemgen_low_entropy.txt", b"", b"A" * 8192, "txt"),          # repeating ASCII
    ("telemgen_elf_stub.elf", b"\x7fELF\x02\x01\x01\x00", None, "elf"),
    ("telemgen_zip_stub.zip", b"PK\x03\x04", None, "zip"),
    ("telemgen_xz_stub.xz", b"\xfd7zXZ\x00", None, "xz"),
    ("telemgen_gzip_stub.gz", b"\x1f\x8b\x08", None, "gz"),
    ("telemgen_pdf_stub.pdf", b"%PDF-1.7\n", None, "pdf"),
]


def _write_fixture(out_dir: str, name: str, header: bytes, body: Optional[bytes]) -> str:
    path = os.path.join(out_dir, name)
    with open(path, "wb") as fh:
        if header:
            fh.write(header)
        if body is None:
            # Pad with random bytes so EDR-side entropy calculation has signal
            fh.write(secrets.token_bytes(4096))
        else:
            fh.write(body)
    return path


def _modify_fixture(path: str) -> None:
    """Append data to the file to trigger a file.modification event with a
    fresh entropy/header sample on EDRs that recompute on every change."""
    with open(path, "ab") as fh:
        fh.write(b"\n# telemgen modification\n")
        fh.write(secrets.token_bytes(512))


def _rename_fixture(path: str) -> str:
    """Rename to a path with a different extension so EDRs that key entropy
    collection on extension still emit the field."""
    base, ext = os.path.splitext(path)
    new_path = f"{base}.renamed{ext}"
    os.rename(path, new_path)
    return new_path


def run_file_metadata():
    """Entry point invoked by lnx_telem_gen.py.

    Generates a small set of files with known headers and varying entropy
    so EDRs that collect file.Ext.header_bytes and file.Ext.entropy on file
    creation/modification events have something to populate.
    """
    out_dir = tempfile.mkdtemp(prefix="telemgen-file-metadata-")
    print(f"[+] Writing file-metadata fixtures into {out_dir}")
    written = []
    for name, header, body, _ in _FIXTURES:
        try:
            path = _write_fixture(out_dir, name, header, body)
            print(f"[+] created {path} (header={header!r}, size={os.path.getsize(path)})")
            written.append(path)
        except Exception as exc:
            print(f"[!] failed to create {name}: {exc}")

    for path in written:
        try:
            _modify_fixture(path)
            new_path = _rename_fixture(path)
            print(f"[+] modified+renamed {path} -> {new_path}")
        except Exception as exc:
            print(f"[!] post-creation activity failed for {path}: {exc}")

    return f"file metadata fixtures written under {out_dir}"


if __name__ == "__main__":
    run_file_metadata()
