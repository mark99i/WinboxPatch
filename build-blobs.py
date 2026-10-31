#!/usr/bin/env python3
"""
build-blobs.py - assemble the v4 converter blobs with the REAL GNU toolchain.

    python build-blobs.py

Sources: bytes_impl.S, bigbytes_impl.S - the 'bytes' (u32) and 'bigbytes'
(u64) converter blobs for patch set v4 (verbatim from ANALYSIS-FRAG.md /
ANALYSIS-SHM.md section G.1 - Intel syntax, GNU as dialect).
Outputs: bytes_impl.bin    (VA 0x657400, 0x419 bytes) and
         bigbytes_impl.bin (VA 0x638500, 0x41A bytes).

Pipeline per blob (same encodings the reference build v98 was made with):

    as  --64 -o <blob>.o   <blob>.S        # GNU assembler, x86-64
    ld  -Ttext=<vma> -e _start -o <blob>.elf <blob>.o
    objcopy -O binary <blob>.elf <blob>.bin

The .org directives inside the sources zero-pad the gap between the parser
core and the stub3 tail, so the flat binary is exactly the region the
patched exe expects. Only the blob length is checked here; the blobs are
not verified separately - build-patched-v4.py verifies the final patched
exe as a whole by its SHA-256.

Requires binutils (as/ld/objcopy) on PATH: preinstalled on GitHub Actions
ubuntu runners; on Windows use WSL or MinGW-w64 binutils.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# name, source, output, load VA (VA of blob start inside the exe),
# expected length (the blob must fill its reserved zero zone exactly)
TARGETS = [
    ("bytes",     "bytes_impl.S",     "bytes_impl.bin",     0x657400, 0x419),
    ("bigbytes",  "bigbytes_impl.S",  "bigbytes_impl.bin",  0x638500, 0x41A),
]


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"{' '.join(cmd)} failed (exit {r.returncode}):\n"
            f"{r.stdout}{r.stderr}")
    if r.stderr.strip():
        print(f"  [w] {' '.join(cmd)}: {r.stderr.strip()}")


def build(name, src, out, vma, length):
    src_path = os.path.join(HERE, src)
    out_path = os.path.join(HERE, out)
    with tempfile.TemporaryDirectory() as td:
        obj = os.path.join(td, name + ".o")
        elf = os.path.join(td, name + ".elf")
        run(["as", "--64", "-o", obj, src_path])
        run(["ld", f"-Ttext={vma:#x}", "-e", "_start", "-o", elf, obj])
        run(["objcopy", "-O", "binary", elf, out_path])
    data = open(out_path, "rb").read()
    if len(data) != length:
        die(f"{name}: assembled {len(data)} bytes, expected {length}")
    print(f"  {name}: {out} ({len(data)} bytes @ VA {vma:#x}) OK")


def main():
    for tool in ("as", "ld", "objcopy"):
        if shutil.which(tool) is None:
            die(f"{tool} not found on PATH - install binutils "
                f"(on Windows: WSL or MinGW-w64)")
    print("Assembling v4 converter blobs with GNU as:")
    for t in TARGETS:
        build(*t)
    print("Done - blobs written, build-patched-v4.py will pick them up.")


if __name__ == "__main__":
    main()
