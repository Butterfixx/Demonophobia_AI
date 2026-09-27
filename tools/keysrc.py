# -*- coding: utf-8 -*-
"""找 IDEA 密钥来源：谁调用 IDEA 密钥展开函数、谁写全局变量 0x442718"""
import struct

mem = open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read()


def va2off(va):
    return va - 0x400000


# 1) 所有 call 到 0x4332E1 (IDEA 密钥展开) / 0x433389 (IDEA 轮函数)
for target in (0x4332E1, 0x433389, 0x43368A, 0x43598D, 0x4358AF, 0x42EB7E, 0x431BC6):
    hits = []
    for i in range(len(mem) - 5):
        if mem[i] == 0xE8:
            rel = struct.unpack_from('<i', mem, i + 1)[0]
            if (i + 5 + rel) & 0xFFFFFFFF == target:
                hits.append(0x400000 + i)
    print("call 0x%X 的调用点(%d): %s" %
          (target, len(hits), ['0x%X' % h for h in hits[:12]]))

# 2) 写 [0x442718] 的指令（A3 18 27 44 00 / 89 xx ...）
print("\n[0x442718] 相关指令上下文:")
pat = struct.pack('<I', 0x442718)
i = 0
while True:
    i = mem.find(pat, i)
    if i < 0:
        break
    va = 0x400000 + i
    pre = mem[max(0, i - 3):i]
    print("   0x%X  前置字节 %s" % (va, ' '.join('%02X' % b for b in pre)))
    i += 1
