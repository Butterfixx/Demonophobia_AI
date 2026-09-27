import struct, zlib, os

PATH = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
OUTD = r"e:\迅雷下载\Demonophobia\_unpack\out2"
os.makedirs(OUTD, exist_ok=True)
d = open(PATH, 'rb').read()
BOX = 0x29000
n = len(d)
XOR = 0xA3
LIMIT = 65600

# 逐字节粒度：每个偏移都当作可能的块表起点
small = bytearray(n - BOX)
for i in range(n - BOX - 4):
    v = struct.unpack_from('<I', d, BOX + i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        small[i] = 1

runs = []
i = 0
while i < len(small) - 4:
    if small[i]:
        j = i
        while j < len(small) and small[j]:
            j += 4
        if j - i >= 4:                      # 至少 1 项 + 下一项
            runs.append((BOX + i, (j - i) // 4))
        i = j
    else:
        i += 1
print("逐字节扫描候选块表: %d 个" % len(runs))


def inflate(buf):
    for w in (15, -15):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(buf, 200000)
            if o.eof and r:
                return r
        except Exception:
            pass
    return None


def pull(p, cnt, xor):
    """按块表提取一段，成功返回 (数据, 数据结束偏移)"""
    ds = p + 4 * cnt
    off = ds
    out = []
    for k in range(cnt):
        t = struct.unpack_from('<I', d, p + 4 * k)[0]
        cs = t & 0x7FFFFFFF
        raw = bool(t & 0x80000000)
        if cs == 0 or off + cs > n:
            return None
        chunk = d[off:off + cs]
        if xor is not None:
            chunk = bytes(b ^ xor for b in chunk)
        if raw:
            out.append(chunk)
        else:
            r = inflate(chunk)
            if r is None:
                return None
            out.append(r)
        off += cs
    return b''.join(out), off


sections = []
for p, cnt in runs:
    for xor in (XOR, None):
        r = pull(p, cnt, xor)
        if r:
            sections.append((p, cnt, xor, r[0], r[1]))
            break

# 按起始排序并去重（保留不重叠、最长的）
sections.sort(key=lambda s: s[0])
kept = []
last_end = 0
for s in sections:
    if s[0] < last_end:
        continue
    kept.append(s)
    last_end = s[4]

print("成功提取段: %d\n" % len(kept))
SIG = [(b'BM', 'BMP'), (b'RIFF', 'WAV/AVI'), (b'OggS', 'OGG'), (b'MZ', 'EXE'),
       (b'PK\x03\x04', 'ZIP'), (b'\x89PNG', 'PNG'), (b'GIF8', 'GIF')]
for p, cnt, xor, data, end in kept:
    sig = '?'
    for m, nm in SIG:
        if data.startswith(m):
            sig = nm
            break
    pr = sum(1 for c in data if 32 <= c < 127) / max(1, len(data))
    print("  0x%-8X 块%-3d %-6s 解%-9d %-5s 可打印%.2f" %
          (p, cnt, ('XOR%02X' % xor) if xor else 'plain', len(data), sig, pr))
    open(os.path.join(OUTD, "s_%08X.bin" % p), 'wb').write(data)
print("\n输出目录:", OUTD)
