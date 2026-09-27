import struct
from capstone import *

PATH = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
data = open(PATH, 'rb').read()
BASE = 0x400000


def rva2off(rva):
    # 节: VA->file
    tbl = [(0x1000, 0x23FFA, 0x1000), (0x25000, 0x381A, 0x16000), (0x29000, 0x2FF8, 0x18000),
           (0x2C000, 0xBDC, 0x19000), (0x2D000, 0x11BAF, 0x1A000), (0x3F000, 0xD86, 0x26000),
           (0x40000, 0x7198, 0x27000)]
    for va, vs, ra in tbl:
        if va <= rva < va + vs:
            return ra + (rva - va)
    return None


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

start_rva = 0x2E2E0   # file 0x1B2E0
off = rva2off(start_rva)
code = data[off:off + 0x400]
for ins in md.disasm(code, BASE + start_rva):
    print("0x%08X  %-24s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    if ins.address >= BASE + start_rva + 0x1C0 and ins.mnemonic in ('ret', 'retn'):
        break
