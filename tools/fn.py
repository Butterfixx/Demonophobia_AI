import struct, sys
from capstone import *

mem = open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)


def find_prologue(va, maxback=0x400):
    off = va - BASE
    best = None
    for i in range(off, max(0, off - maxback), -1):
        if mem[i] == 0x55 and mem[i + 1] == 0x8B and mem[i + 2] == 0xEC:
            best = i
            break
        if mem[i] == 0x55 and mem[i + 1] == 0x89 and mem[i + 2] == 0xE5:
            best = i
            break
    return BASE + best if best is not None else va


def dump(va, length=0x320):
    off = va - BASE
    for ins in md.disasm(mem[off:off + length], va):
        extra = ''
        if ins.mnemonic == 'push':
            try:
                v = int(ins.op_str, 16)
                if BASE <= v < BASE + len(mem):
                    s = mem[v - BASE:v - BASE + 44].split(b'\x00')[0]
                    txt = ''.join(chr(c) if 32 <= c < 127 else '?' for c in s)
                    if len(txt) >= 3:
                        extra = '   ; "%s"' % txt
            except ValueError:
                pass
        print("0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, extra))
        if ins.mnemonic == 'ret':
            print("   ---- ret ----")
            break


if len(sys.argv) >= 3:
    va = int(sys.argv[1], 16)
    ln = int(sys.argv[2], 16)
    p = find_prologue(va) if len(sys.argv) >= 4 else va
    print("函数起始 0x%06X" % p)
    dump(p, ln)
else:
    for t in (0x4396E4, 0x439738):
        p = find_prologue(t)
        print("\n===== 函数起始 0x%06X (包含 0x%06X) =====" % (p, t))
        dump(p)
