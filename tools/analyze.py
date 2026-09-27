import struct, re
from capstone import *

PATH = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
data = open(PATH, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, pe + 6)[0]
optsize = struct.unpack_from('<H', data, pe + 20)[0]
opt = pe + 24
imagebase = struct.unpack_from('<I', data, opt + 28)[0]
entry = struct.unpack_from('<I', data, opt + 16)[0]
secs = []
st = opt + optsize
for i in range(nsec):
    o = st + 40 * i
    name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ra = struct.unpack_from('<IIII', data, o + 8)
    secs.append(dict(name=name, va=va, vs=vs, rs=rs, ra=ra))

print("ImageBase 0x%08X  Entry RVA 0x%08X" % (imagebase, entry))
for s in secs:
    print("  %-6s VA 0x%06X VSize 0x%06X Raw 0x%06X@0x%06X" % (s['name'], s['va'], s['vs'], s['rs'], s['ra']))


def mem_section(i):
    s = secs[i]
    buf = bytearray(s['vs'])
    n = min(s['rs'], s['vs'])
    buf[:n] = data[s['ra']:s['ra'] + n]
    return buf, s['va']


def lcg_xor(buf, va, seed=None):
    key = ((imagebase + va) & 0xFFFFFFFF) if seed is None else (seed & 0xFFFFFFFF)
    out = bytearray(buf)
    for i in range(0, len(out) - 3, 4):
        key = (key * 0x19660D + 0x3C6EF375) & 0xFFFFFFFF
        k = struct.pack('<I', key)
        out[i] ^= k[0]
        out[i + 1] ^= k[1]
        out[i + 2] ^= k[2]
        out[i + 3] ^= k[3]
    return out


def printable_ratio(b):
    if not b:
        return 0.0
    n = sum(1 for c in b if 0x20 <= c < 0x7f or c in (9, 10, 13))
    return n / len(b)


print("\n== 用 LCG-XOR(key0=imagebase+VA) 尝试解密各节 ==")
for i, s in enumerate(secs):
    buf, va = mem_section(i)
    before = printable_ratio(bytes(buf))
    dec = lcg_xor(buf, va)
    after = printable_ratio(bytes(dec))
    print("  %-6s 可打印率 %.3f -> %.3f %s" % (s['name'], before, after, "  <== 疑似解密成功" if after > 0.55 else ""))

print("\n== 第7节解密后 0x41408 起 128 字节 ==")
buf, va = mem_section(6)
dec = lcg_xor(buf, va)
off = 0x41408 - va
print(repr(bytes(dec[off:off + 128])))
