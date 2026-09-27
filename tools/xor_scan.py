import struct, zlib

d = bytearray(open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read())
BOX = 0x29000
n = len(d)
LIMIT = 65600

small = bytearray((n - BOX) // 4)
for i in range(len(small)):
    v = struct.unpack_from('<I', d, BOX + 4 * i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        small[i] = 1
runs = []
i = 0
while i < len(small):
    if small[i]:
        j = i
        while j < len(small) and small[j]:
            j += 1
        if j - i >= 2:
            runs.append((BOX + 4 * i, j - i))
        i = j
    else:
        i += 1

def try_inflate(buf, csize):
    for w in (15, -15):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(bytes(buf[:csize + 32]), 70000)
            if o.eof and len(r) > 0:
                return r
        except Exception:
            pass
    return None

print("扫描 %d 个候选块表，XOR 全 256 试探\n" % len(runs))
hits = []
for off, cnt in runs:
    ds = off + 4 * cnt
    first = struct.unpack_from('<I', d, off)[0]
    csize = first & 0x7FFFFFFF
    if first & 0x80000000 or csize == 0 or ds + csize > n:
        continue
    raw = bytes(d[ds:ds + csize])
    for b in range(256):
        if (raw[0] ^ b) != 0x78:
            continue
        f = raw[1] ^ b if csize > 1 else 0
        if (0x78 * 256 + f) % 31:
            continue
        x = bytearray(c ^ b for c in raw)
        r = try_inflate(x, csize)
        if r:
            hits.append((off, cnt, b, csize, len(r), r))
            break

print("命中 %d 个:" % len(hits))
for off, cnt, b, cs, ol, r in hits[:12]:
    pr = sum(1 for c in r if 32 <= c < 127) / len(r)
    print("  表@0x%-8X 块数%-3d XOR=0x%02X 压缩%-7d -> %-7d 可打印%.2f" % (off, cnt, b, cs, ol, pr))
    print("      %r" % r[:80])
