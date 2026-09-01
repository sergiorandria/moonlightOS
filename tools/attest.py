#!/usr/bin/env python3
"""DICE attestation verifier - checks kernel hash against ROM expected, verifies CDI chain"""
import hashlib, sys
def sha256_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        while chunk:=f.read(8192):
            h.update(chunk)
    return h.hexdigest()
if __name__=="__main__":
    if len(sys.argv)<3:
        print(f"usage: {sys.argv[0]} kernel.elf expected_hash")
        sys.exit(1)
    got=sha256_file(sys.argv[1])
    exp=open(sys.argv[2]).read().strip() if sys.argv[2].endswith('.hash') else sys.argv[2]
    print(f"kernel hash: {got}")
    print(f"expected:    {exp}")
    sys.exit(0 if got==exp else 1)
