import struct, zlib, collections

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
G = 0x151ACA
print("== 0x%X 起 256 字节 ==" % G)
for i in range(0, 256, 16):
    row = d[G + i:G + i + 16]
    print("  %06X  %s  %s" % (G + i, ' '.join('%02X' % b for b in row),
          ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)))

# 8 字节块重复统计（ECB 特征）
blk = d[G:G + 65536]
c = collections.Counter(bytes(blk[i:i + 8]) for i in range(0, len(blk) - 8, 8))
rep = [(v, k) for k, v in c.items() if v > 1]
rep.sort(reverse=True)
print("\n8字节块重复 TOP: %s" % [(v, k.hex()) for v, k in rep[:5]])
print("(随机数据应几乎无重复)")

# 小块尺寸 dword 分布
LIMIT = 65600
hits = []
for i in range(G, min(G + 0x40000, len(d) - 4)):
    v = struct.unpack_from('<I', d, i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        hits.append((i, v))
print("\n前 0x40000 内'小块尺寸'dword 数: %d" % len(hits))
for i, v in hits[:15]:
    print("   0x%X: 0x%08X" % (i, v))


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


print("\n== 在该区域逐字节找可解压块 ==")
found = []
for i in range(G, min(G + 0x20000, len(d) - 4)):
    v = struct.unpack_from('<I', d, i)[0]
    cs = v & 0x7FFFFFFF
    if 0 < cs <= LIMIT and i + 4 + cs <= len(d):
        for xb in (0xA3, None):
            chunk = d[i + 4:i + 4 + cs]
            if xb is not None:
                chunk = bytes(c ^ xb for c in chunk)
            r = inflate(chunk)
            if r:
                found.append((i, cs, xb, len(r), r[:40]))
                break
    if len(found) >= 6:
        break
for f in found:
    print("  块表@0x%X 首块%d %s -> %d 字节 %r" %
          (f[0], f[1], ('XOR%02X' % f[2]) if f[2] else 'plain', f[3], f[4]))
if not found:
    print("  未找到 -> 该区域数据为 IDEA(或其它)加密")
