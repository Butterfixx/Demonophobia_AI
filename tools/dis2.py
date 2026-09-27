# -*- coding: utf-8 -*-
import sys
from capstone import *

f = sys.argv[1] if len(sys.argv) > 1 else 'memory_full.bin'
va = int(sys.argv[2], 16)
ln = int(sys.argv[3], 16)
mem = open(r"e:\迅雷下载\Demonophobia\_unpack\%s" % f, 'rb').read()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for ins in md.disasm(mem[va - BASE:va - BASE + ln], va):
    x = ''
    if ins.mnemonic == 'push':
        try:
            v = int(ins.op_str, 16)
            if BASE <= v < BASE + len(mem):
                s = bytes(mem[v - BASE:v - BASE + 32]).split(b'\x00')[0]
                t = ''.join(chr(c) if 32 <= c < 127 else '?' for c in s)
                if len(t) >= 3:
                    x = '   ; "%s"' % t
        except ValueError:
            pass
    print("0x%08X  %-18s %s %s%s" % (ins.address, ins.bytes.hex(),
                                     ins.mnemonic, ins.op_str, x))
