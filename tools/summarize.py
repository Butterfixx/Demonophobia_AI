import sys, re
from capstone import *

mem = open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)

NAMES = {0x44273c: 'CreateFileA', 0x442794: 'GetFileSize', 0x442810: 'ReadFile',
         0x44281c: 'SetFilePointer', 0x442850: 'WriteFile', 0x442868: 'lstrcatA',
         0x4427a8: 'GetModuleFileNameA', 0x4427ac: 'GetModuleHandleA',
         0x43f018: 'GetModuleHandleA_k', 0x43f010: 'raise', 0x43f014: 'VirtualAlloc'}

start = int(sys.argv[1], 16)
ln = int(sys.argv[2], 16)
mode = sys.argv[3] if len(sys.argv) > 3 else 'filter'
off = start - BASE
n = 0
for ins in md.disasm(mem[off:off + ln], start):
    txt = "%s %s" % (ins.mnemonic, ins.op_str)
    show = False
    note = ''
    if ins.mnemonic in ('call', 'jmp'):
        show = True
        m = re.search(r'\[(0x[0-9a-f]+)\]', txt)
        if m:
            v = int(m.group(1), 16)
            note = ' [%s]' % NAMES.get(v, hex(v))
        m2 = re.search(r'0x([0-9a-f]+)$', txt)
        if m2:
            v = int(m2.group(1), 16)
            note += ' -> fn 0x%X' % v
    elif re.search(r'0x44[12][0-9a-f]{4}', txt):
        show = True
    if mode == 'all':
        show = True
    if show:
        print("0x%08X  %-20s %s%s" % (ins.address, ins.bytes.hex(), txt, note))
    n += 1
    if ins.mnemonic == 'ret' and n > 20:
        print("   -------- ret at 0x%X --------" % ins.address)
        break
