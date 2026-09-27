import struct
from capstone import *

mem = bytearray(open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read())
BASE = 0x400000
print("boot 数据区 0x441C00 起 32 字节:", bytes(mem[0x441C00 - BASE:0x441C00 - BASE + 32]).hex())
print("  XOR 常量字节 = 0x%02X" % mem[0x441C00 - BASE])

# 第二处 SMC: push 0x120000 @0x431CA5, ret=0x431CAF -> [ret-0, ret+0x12)
A2 = 0x120000
RET2 = 0x431CAF
s2 = RET2 - (A2 & 0xFFFF)
e2 = RET2 + (A2 >> 16)
print("\n第二处自解密区: 0x%X..0x%X" % (s2, e2))
print("  解密前:", bytes(mem[s2 - BASE:e2 - BASE]).hex())
for p in range(s2, e2):
    key = (p * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
    mem[p - BASE] ^= (key & 0xFF)
print("  解密后:", bytes(mem[s2 - BASE:e2 - BASE]).hex())
md = Cs(CS_ARCH_X86, CS_MODE_32)
for ins in md.disasm(bytes(mem[s2 - BASE:s2 - BASE + 0x40]), s2):
    print("  0x%08X  %-18s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
