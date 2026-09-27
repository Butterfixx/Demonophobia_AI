# -*- coding: utf-8 -*-
import struct
from capstone import *

mem = bytearray(open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read())
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)

REGIONS = [(0x431C44, 0x431C8A), (0x431CAF, 0x431CEA), (0x431CC1, 0x431D16),
           (0x431D16, 0x431D43)]
for s, e in REGIONS:
    for p in range(s, e):
        k = (p * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        mem[p - BASE] ^= (k & 0xFF)

open(r"e:\迅雷下载\Demonophobia\_unpack\memory_dec.bin", 'wb').write(bytes(mem))
for ins in md.disasm(bytes(mem[0x431CC1 - BASE:0x431D50 - BASE]), 0x431CC1):
    print("0x%08X  %-18s %s %s" % (ins.address, ins.bytes.hex(),
                                   ins.mnemonic, ins.op_str))
    if ins.address > 0x431D43:
        break
