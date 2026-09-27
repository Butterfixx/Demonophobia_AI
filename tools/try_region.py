# -*- coding: utf-8 -*-
import struct
from capstone import *

mem = bytearray(open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read())
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)


def dec(s, e):
    for p in range(s, e):
        k = (p * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        mem[p - BASE] ^= (k & 0xFF)


for s, e in ((0x431C44, 0x431C8A), (0x431CAF, 0x431CEA)):
    dec(s, e)
print("解密 0x431C44..0x431C8A 与 0x431CAF..0x431CEA\n")
for ins in md.disasm(bytes(mem[0x431CAF - BASE:0x431D60 - BASE]), 0x431CAF):
    x = ''
    if ins.mnemonic == 'push':
        try:
            v = int(ins.op_str, 16)
            if BASE <= v < BASE + len(mem):
                t = ''.join(chr(c) if 32 <= c < 127 else '?' for c in
                            bytes(mem[v - BASE:v - BASE + 32]).split(b'\x00')[0])
                if len(t) >= 3:
                    x = '   ; "%s"' % t
        except ValueError:
            pass
    print("0x%08X  %-18s %s %s%s" % (ins.address, ins.bytes.hex(),
                                     ins.mnemonic, ins.op_str, x))
    if ins.address > 0x431D40:
        break
