import struct, zlib

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
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

print("run 数 %d；逐个尝试 zlib/raw 解压第一块\n" % len(runs))
good = []
for off, cnt in runs:
    ds = off + 4 * cnt
    first = struct.unpack_from('<I', d, off)[0]
    csize = first & 0x7FFFFFFF
    if first & 0x80000000 or csize == 0:
        continue
    for delta in (0, 1, -1, 2, -2):
        s = ds + delta
        if s + csize > n:
            continue
        for w in (15, -15, 47):
            try:
                o = zlib.decompressobj(w)
                r = o.decompress(d[s:s + csize + 64], 70000)
                if o.eof and len(r) >= 32:
                    pr = sum(1 for c in r if 32 <= c < 127) / len(r)
                    good.append((off, cnt, csize, delta, w, len(r), pr, r[:48], d[s:s + 4].hex()))
                    break
            except Exception:
                pass
        else:
            continue
        break

print("成功: %d / %d" % (len(good), len(runs)))
for g in good[:20]:
    print("  表@0x%-8X 块数%-3d 压缩%-6d off%+d wbits%d -> %-7d 字节 可打印%.2f 头=%s"
          % (g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[8]))
    print("      %r" % g[7])
