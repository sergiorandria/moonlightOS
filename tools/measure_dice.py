#!/usr/bin/env python3
"""DICE provisioning: measure the exact byte ranges kernel/src/dice.c hashes
([_text_start,_dice_expected_start) + [_dice_expected_end,_bss)) by
reconstructing the loaded image from the ELF's PT_LOAD segments, then emit a
C file defining the .dice_expected slot.

Because the slot itself is excluded from the measurement, provisioning is a
fixed point: build -> measure -> rebuild links the hash in, and re-measuring
the provisioned image yields the identical hash (verified by make
provision-dice). No external dependencies (struct only).
"""
import struct
import sys

PT_LOAD = 1


def parse_elf(path):
    with open(path, "rb") as f:
        img = f.read()
    if img[:4] != b"\x7fELF":
        sys.exit(f"not an ELF: {path}")
    if img[4] != 2 or img[5] != 1:
        sys.exit("need 64-bit little-endian ELF")
    (e_type, e_machine, e_version, e_entry, phoff, shoff, e_flags,
     e_ehsize, phentsize, phnum, shentsize, shnum,
     shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", img, 0x10)
    segs = []
    for i in range(phnum):
        p = struct.unpack_from("<IIQQQQQQ", img, phoff + i * phentsize)
        if p[0] == PT_LOAD:
            segs.append(p)  # (type,flags,off,vaddr,paddr,filesz,memsz,align)
    shstr = None
    syms = {}
    if shnum and shstrndx != 0:
        shdrs = []
        for i in range(shnum):
            shdrs.append(struct.unpack_from("<IIQQQQIIQQ", img, shoff + i * shentsize))
        shstr_off = shdrs[shstrndx][4]
        symtab = strtab = None
        symtab_entsize = 0
        for h in shdrs:
            name = h[0]
            sname = img[shstr_off + name:].split(b"\x00", 1)[0]
            if sname == b".symtab":
                symtab = h
            elif sname == b".strtab":
                strtab = h
        if symtab is not None and strtab is not None:
            n = symtab[5] // 24
            for i in range(n):
                # Elf64_Sym: name(I) info(B) other(B) shndx(H) value(Q) size(Q)
                st = struct.unpack_from("<IBBHQQ", img, symtab[4] + i * 24)
                nm = img[strtab[4] + st[0]:].split(b"\x00", 1)[0].decode()
                syms[nm] = st[4]
    return img, segs, syms


def mem_bytes(img, segs, addr, length):
    """Bytes the hart would read at [addr, addr+length): file bytes where a
    PT_LOAD covers them, zeros elsewhere. Zeros are correct in both cases:
    memsz-only tails are zero-filled by the loader, and holes between
    segments read as zero from freshly-zeroed guest RAM. (A hole once made
    this script silently SKIP bytes while the hart hashed zeros - hence the
    explicit zero-fill: every address in range contributes exactly one byte.
    If guest RAM ever held nondeterminism here, the boot-time verify would
    fail closed instead of silently agreeing.)"""
    out = bytearray()
    end = addr + length
    cur = addr
    cov = sorted(segs, key=lambda s: s[3])
    while cur < end:
        hit = None
        for s in cov:
            if s[3] <= cur < s[3] + s[6]:
                hit = s
                break
        if hit is None:
            nxt = end
            for s in cov:
                if cur < s[3] < nxt:
                    nxt = s[3]
            out += b"\x00" * (nxt - cur)
            cur = nxt
            continue
        _, _, poff, pvaddr, _, pfilesz, pmemsz, _ = hit
        seg_end = min(end, pvaddr + pmemsz)
        file_end = min(seg_end, pvaddr + pfilesz)
        if cur < file_end:
            out += img[poff + (cur - pvaddr):poff + (file_end - pvaddr)]
            cur = file_end
        if cur < seg_end:
            out += b"\x00" * (seg_end - cur)
            cur = seg_end
    return bytes(out)


def measure(path):
    img, segs, syms = parse_elf(path)
    need = ["_text_start", "_dice_expected_start", "_dice_expected_end", "_bss"]
    missing = [s for s in need if s not in syms]
    if missing:
        sys.exit(f"missing symbols (DICE not linked?): {missing}")
    t0, d0, d1, b0 = (syms[s] for s in need)
    if not (t0 <= d0 <= d1 <= b0):
        sys.exit(f"slot ordering broken: {t0:#x} {d0:#x} {d1:#x} {b0:#x}")
    if d1 - d0 != 32:
        sys.exit(f"expected slot is not 32 bytes: {d1 - d0}")
    import hashlib
    h = hashlib.sha256()
    h.update(mem_bytes(img, segs, t0, d0 - t0))
    h.update(mem_bytes(img, segs, d1, b0 - d1))
    return h.digest()


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} kernel.elf [--digest | --expect HEX]")
    if sys.argv[1] == "--digest" and len(sys.argv) == 3:
        print(measure(sys.argv[2]).hex())
        return
    if sys.argv[1] == "--expect" and len(sys.argv) == 4:
        got = measure(sys.argv[3]).hex()
        print(f"measured:  {got}")
        print(f"expected:  {sys.argv[2]}")
        if got != sys.argv[2].lower():
            sys.exit("MISMATCH: provisioned image does not re-measure")
        print("MATCH: fixed point holds")
        return
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} kernel.elf [--digest | --expect HEX]")
    digest = measure(sys.argv[1])
    print("/* Generated by tools/measure_dice.py - do not edit.")
    print(" * Rebuild with: make -C kernel provision-dice */")
    print("#include <stdint.h>")
    print('__attribute__((section(".dice_expected")))'
          " const uint8_t expected_kernel_hash[32] = {")
    print("    " + ", ".join(f"0x{b:02x}" for b in digest))
    print("};")


if __name__ == "__main__":
    main()
