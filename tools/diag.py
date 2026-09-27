import struct, zlib, math, glob, os

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX = 0x29000
n = len(d)
XOR = 0xA3
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
        runs.append((BOX + 4 * i, j - i))
        i = j
    else:
        i += 1


def ent(b):
    c = {}
    for x in b:
        c[x] = c.get(x, 0) + 1
    e = 0.0
    for v in c.values():
        p = v / len(b)
        e -= p * math.log(p, 2)
    return e


print("== 第一块解压失败(疑似 IDEA 加密)的候选段 ==")
cnt = 0
for p, c in runs:
    ds = p + 4 * c
    t = struct.unpack_from('<I', d, p)[0]
    cs = t & 0x7FFFFFFF
    if t & 0x80000000 or cs == 0 or ds + cs > n:
        continue
    chunk = bytes(b ^ XOR for b in d[ds:ds + cs])
    ok = False
    for w in (15, -15):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(chunk, 70000)
            if o.eof:
                ok = True
        except Exception:
            pass
    if not ok:
        cnt += 1
        print("  表@0x%-8X 块%-3d 首块%d 字节  XOR后前16=%s" % (p, c, cs, chunk[:16].hex()))
print("  合计 %d 个\n" % cnt)

print("== 已提取段中'乱码'文件的性质 ==")
for f in sorted(glob.glob(r"e:\迅雷下载\Demonophobia\_unpack\out\sec_*.bin")):
    b = open(f, 'rb').read()
    if b.startswith(b'BM'):
        continue
    if len(b) < 1000:
        continue
    # 是否还能再解压?
    again = None
    for w in (15, -15):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(b[:len(b)], 200000)
            if o.eof:
                again = len(r)
        except Exception:
            pass
    print("  %-22s %8d 字节 熵%.2f  二次解压=%s" %
          (os.path.basename(f), len(b), ent(b[:20000]), again))
