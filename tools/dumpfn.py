import sys
from capstone import *

mem = open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

NAMES = {
    0x44273c: 'CreateFileA', 0x442794: 'GetFileSize', 0x442810: 'ReadFile',
    0x44281c: 'SetFilePointer', 0x442850: 'WriteFile', 0x442868: 'lstrcatA',
    0x4427a8: 'GetModuleFileNameA', 0x4427ac: 'GetModuleHandleA',
    0x442758: 'lock', 0x4427e8: 'unlock', 0x4427c0: 'time?',
    0x43f018: 'GetModuleHandleA_', 0x43f010: 'raise', 0x43f014: 'VirtualAlloc',
}


def ann(ins):
    extra = ''
    if ins.mnemonic == 'push':
        try:
            v = int(ins.op_str, 16)
            if BASE <= v < BASE + len(mem):
                s = mem[v - BASE:v - BASE + 44].split(b'\x00')[0]
                t = ''.join(chr(c) if 32 <= c < 127 else '?' for c in s)
                if len(t) >= 3:
                    extra = '   ; "%s"' % t
        except ValueError:
            pass
    elif ins.mnemonic in ('call', 'jmp'):
        s = ins.op_str
        if 'dword ptr [' in s:
            try:
                v = int(s[s.index('[') + 1:s.index(']')], 16)
                if v in NAMES:
                    extra = '   ; [%s]' % NAMES[v]
            except Exception:
                pass
    return extra


start = int(sys.argv[1], 16)
ln = int(sys.argv[2], 16)
off = start - BASE
for ins in md.disasm(mem[off:off + ln], start):
    print("0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, ann(ins)))
    if ins.mnemonic == 'ret':
        print("   -------- ret --------")
        break
