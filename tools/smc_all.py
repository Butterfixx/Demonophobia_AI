# -*- coding: utf-8 -*-
"""扫描并解密全部 SMC 自解密区域: push A ; call 0x42EB7E"""
import struct
from capstone import *

mem = bytearray(open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read())
BASE = 0x400000
DISP = 0x42EB7E

regions = []
for i in range(len(mem) - 10):
    if mem[i] == 0x68 and mem[i + 5] == 0xE8:
        rel = struct.unpack_from('<i', mem, i + 6)[0]
        tgt = (i + 5 + BASE + 5 + rel) & 0xFFFFFFFF
        if tgt == DISP:
            A = struct.unpack_from('<I', mem, i + 1)[0]
            ret = i + 10 + BASE
            s = ret - (A & 0xFFFF)
            e = ret + (A >> 16)
            if BASE <= s < e <= BASE + len(mem):
                regions.append((s, e, ret, A))

print("找到 SMC 区域 %d 处" % len(regions))
for s, e, ret, A in regions:
    print("   0x%X..0x%X (%2d 字节) A=0x%X ret=0x%X" % (s, e, e - s, A, ret))
    for p in range(s, e):
        k = (p * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        mem[p - BASE] ^= (k & 0xFF)

open(r"e:\迅雷下载\Demonophobia\_unpack\memory_full.bin", 'wb').write(bytes(mem))
print("\n已写入 memory_full.bin")

md = Cs(CS_ARCH_X86, CS_MODE_32)
for s, e, ret, A in regions:
    if 0x431000 <= s <= 0x432000:
        print("\n== 0x%X..0x%X 解密后 ==" % (s, e))
        for ins in md.disasm(bytes(mem[s - BASE:s - BASE + (e - s) + 0x60]), s):
            print("0x%08X  %-20s %s %s" % (ins.address, ins.bytes.hex(),
                                            ins.mnemonic, ins.op_str))
            if ins.address > e + 0x30:
                break
