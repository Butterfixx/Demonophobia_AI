import struct
from capstone import *

mem = bytearray(open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read())
BASE = 0x400000


def smc(start, end):
    for p in range(start, end):
        key = (p * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        mem[p - BASE] ^= (key & 0xFF)


# 主分支体：0x431CAF..0x431CEA (59 字节)
smc(0x431CAF, 0x431CEA)
print("解密后 59 字节:", bytes(mem[0x431CAF - BASE:0x431CEA - BASE]).hex())
md = Cs(CS_ARCH_X86, CS_MODE_32)
for ins in md.disasm(bytes(mem[0x431CAF - BASE:0x431CAF - BASE + 0x80]), 0x431CAF):
    print("0x%08X  %-20s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    if ins.mnemonic == 'ret':
        break
