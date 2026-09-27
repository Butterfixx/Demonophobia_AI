import struct, os, re

PATH = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
OUT = r"e:\迅雷下载\Demonophobia\_unpack\sec"
os.makedirs(OUT, exist_ok=True)
data = open(PATH, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, pe + 6)[0]
opt = pe + 24
optsize = struct.unpack_from('<H', data, pe + 20)[0]
imagebase = struct.unpack_from('<I', data, opt + 28)[0]
secs = []
for i in range(nsec):
    o = opt + optsize + 40 * i
    name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
    name = ''.join(c for c in name if 32 <= ord(c) < 127) or 'sec%d' % (i + 1)
    vs, va, rs, ra = struct.unpack_from('<IIII', data, o + 8)
    secs.append(dict(name=name, va=va, vs=vs, rs=rs, ra=ra))


def mem(i):
    s = secs[i]
    b = bytearray(s['vs'])
    n = min(s['rs'], s['vs'])
    b[:n] = data[s['ra']:s['ra'] + n]
    return b


def lcg_xor(buf, va):
    key = (imagebase + va) & 0xFFFFFFFF
    out = bytearray(buf)
    for i in range(0, len(out) - 3, 4):
        key = (key * 0x19660D + 0x3C6EF375) & 0xFFFFFFFF
        k = struct.pack('<I', key)
        for j in range(4):
            out[i + j] ^= k[j]
    return out


for i, s in enumerate(secs):
    raw = mem(i)
    dec = lcg_xor(raw, s['va'])
    open(os.path.join(OUT, "%d_%s.bin" % (i + 1, s['name'])), 'wb').write(bytes(dec))
    d = [struct.unpack_from('<I', dec, 4 * k)[0] for k in range(min(8, s['vs'] // 4))]
    print("== 节%d %s  VA 0x%06X 解密后头部 ==" % (i + 1, s['name'], s['va']))
    print("   " + " ".join("0x%08X" % x for x in d))
    m = re.findall(rb'[ -~]{6,}', bytes(dec[:min(len(dec), 0x3000)]))
    if m:
        print("   明文串: " + " | ".join(x.decode('latin1') for x in m[:12]))
    print()
