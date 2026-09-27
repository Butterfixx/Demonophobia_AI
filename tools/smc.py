import struct
from capstone import *

mem = bytearray(open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read())
BASE = 0x400000

# 0x43598D(ecx=&arg) -> 0x4358AF:  region = [ret - (a & 0xFFFF), ret + (a >> 16))
#   key = p*0x19660D + 0x3C6EF35F ; *p ^= key & 0xFF
A = 0x460000
RET = 0x431C44
start = RET - (A & 0xFFFF)
end = RET + (A >> 16)
print("解密代码区: 0x%X .. 0x%X (%d 字节)" % (start, end, end - start))
print("解密前:", bytes(mem[start - BASE:end - BASE]).hex())

for p in range(start, end):
    key = (p * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
    mem[p - BASE] ^= (key & 0xFF)

print("解密后:", bytes(mem[start - BASE:end - BASE]).hex())
open(r"e:\迅雷下载\Demonophobia\_unpack\memory2.bin", 'wb').write(bytes(mem))

md = Cs(CS_ARCH_X86, CS_MODE_32)
print("\n== 反汇编解密出的代码 (含后续未加密部分) ==")
for ins in md.disasm(bytes(mem[start - BASE:start - BASE + 0x120]), start):
    extra = ''
    if ins.mnemonic == 'push':
        try:
            v = int(ins.op_str, 16)
            if BASE <= v < BASE + len(mem):
                s = bytes(mem[v - BASE:v - BASE + 40]).split(b'\x00')[0]
                t = ''.join(chr(c) if 32 <= c < 127 else '?' for c in s)
                if len(t) >= 3:
                    extra = '   ; "%s"' % t
        except ValueError:
            pass
    print("0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, extra))
