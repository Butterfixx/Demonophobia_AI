import sys
from capstone import *

mem = open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read()
BASE = 0x400000
start = int(sys.argv[1], 16)
length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x200
off = start - BASE
md = Cs(CS_ARCH_X86, CS_MODE_32)
n = 0
for ins in md.disasm(mem[off:off + length], start):
    extra = ''
    if ins.mnemonic == 'push':
        try:
            v = int(ins.op_str, 16)
            if BASE <= v < BASE + len(mem):
                s = mem[v - BASE:v - BASE + 48].split(b'\x00')[0]
                if len(s) >= 3:
                    extra = '  ; "%s"' % s.decode('latin1', 'replace')
        except ValueError:
            pass
    print("0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, extra))
    n += 1
    if n > 220:
        break
