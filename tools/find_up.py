import struct, re
from capstone import *

mem = open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read()
BASE = 0x400000

targets = {0x441E14: '-up1.txt', 0x441E20: '-up.txt', 0x441ED0: 'PACKED DLL OR BOXFILE CORRUPTED',
           0x441FB0: 'BOXFILE CORRUPTED', 0x441FD8: 'COULD NOT OPEN BOXFILE', 0x442170: '_splashscreen.bmp',
           0x441BB4: ':BOX:ReadCompressedSection'}

print("== 引用这些字符串的指令位置 ==")
for t, name in targets.items():
    pat = b'\x68' + struct.pack('<I', t)     # push imm32
    i = 0
    locs = []
    while True:
        i = mem.find(pat, i)
        if i < 0:
            break
        locs.append(BASE + i)
        i += 1
    print("  %-32s (0x%06X) <- %s" % (name, t, ['0x%06X' % x for x in locs]))

print("\n== 附近代码 (-up.txt 引用) ==")
md = Cs(CS_ARCH_X86, CS_MODE_32)
for t in (0x441E14, 0x441E20):
    pat = b'\x68' + struct.pack('<I', t)
    i = mem.find(pat)
    if i < 0:
        continue
    va = BASE + i
    start = va - 0x120
    print("\n--- 0x%06X 附近 ---" % va)
    for ins in md.disasm(mem[start - BASE:start - BASE + 0x200], start):
        extra = ''
        if ins.mnemonic == 'push':
            try:
                v = int(ins.op_str, 16)
                if BASE <= v < BASE + len(mem):
                    s = mem[v - BASE:v - BASE + 40].split(b'\x00')[0]
                    if len(s) >= 3:
                        extra = '  ; "%s"' % s.decode('latin1', 'replace')
            except ValueError:
                pass
        print("  0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, extra))
