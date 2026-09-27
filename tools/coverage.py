import struct, zlib, os, glob

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX = 0x29000
n = len(d)
XOR = 0xA3
LIMIT = 65600

spans = []
for f in glob.glob(r"e:\迅雷下载\Demonophobia\_unpack\out2\s_*.bin"):
    p = int(os.path.basename(f)[2:10], 16)
    b = open(f, 'rb').read()
    # 重新计算数据结束：表 + 各块压缩大小之和
    tbl = []
    q = p
    while True:
        v = struct.unpack_from('<I', d, q)[0]
        if 0 < (v & 0x7FFFFFFF) <= LIMIT:
            tbl.append(v & 0x7FFFFFFF)
            q += 4
        else:
            break
    end = p + 4 * len(tbl) + sum(tbl)
    spans.append((p, end, len(b)))
spans.sort()
total = sum(e - s for s, e, _ in spans)
print("已提取段覆盖: %d 字节 / 箱 %d 字节 (%.1f%%)" % (total, n - BOX, 100 * total / (n - BOX)))

print("\n== 未覆盖的空洞 (>2000 字节) ==")
cur = BOX
gaps = []
for s, e, _ in spans:
    if s > cur:
        gaps.append((cur, s))
    cur = max(cur, e)
if cur < n:
    gaps.append((cur, n))
for a, b in gaps:
    if b - a > 2000:
        print("  0x%X .. 0x%X  (%d 字节)" % (a, b, b - a))
print("  空洞合计 %d 字节, 共 %d 段" % (sum(b - a for a, b in gaps), len(gaps)))


def inflate(buf):
    for w in (15, -15):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(buf, 300000)
            if o.eof:
                return r
        except Exception:
            pass
    return None


print("\n== 空洞内的内容探测 ==")
for a, b in gaps[:12]:
    if b - a < 2000:
        continue
    blk = d[a:a + min(4000, b - a)]
    for xb in (XOR, None):
        x = blk if xb is None else bytes(c ^ xb for c in blk)
        r = inflate(x)
        if r:
            print("  0x%X %s -> 解压 %d 字节 %r" % (a, ('XOR%02X' % xb) if xb else 'plain', len(r), r[:48]))
            break
    else:
        # 尝试在空洞内逐字节找块表
        found = None
        for i in range(0, min(len(blk), 2000)):
            v = struct.unpack_from('<I', d, a + i)[0]
            cs = v & 0x7FFFFFFF
            if 0 < cs <= LIMIT and a + i + 4 + cs <= n:
                for xb in (XOR, None):
                    chunk = d[a + i + 4:a + i + 4 + cs]
                    if xb is not None:
                        chunk = bytes(c ^ xb for c in chunk)
                    r = inflate(chunk)
                    if r:
                        found = (a + i, cs, xb, len(r), r[:40])
                        break
                if found:
                    break
        if found:
            print("  0x%X 内找到块表@0x%X 首块%d %s -> %d 字节 %r" %
                  (a, found[0], found[1], ('XOR%02X' % found[2]) if found[2] else 'plain', found[3], found[4]))
        else:
            print("  0x%X  (%d 字节) 前32: %s" % (a, b - a, blk[:32].hex()))
