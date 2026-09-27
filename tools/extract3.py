import struct, zlib, os

PATH = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
OUTD = r"e:\迅雷下载\Demonophobia\extracted_files"
os.makedirs(OUTD, exist_ok=True)
d = open(PATH, 'rb').read()
BOX = 0x29000
n = len(d)
XOR = 0xA3
LIMIT = 65600


def inflate(buf):
    for w in (15, -15):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(buf, 400000)
            if o.eof:
                return r
        except Exception:
            pass
    return None


def pull(p, cnt, xor):
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


# 1) 逐字节找所有"小块尺寸"dword 的极大 run
small = bytearray(n)
for i in range(n - 4):
    v = struct.unpack_from('<I', d, i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        small[i] = 1
runs = []
i = BOX
while i < n - 4:
    if small[i]:
        j = i
        while j < n and small[j]:
            j += 4
        runs.append((i, (j - i) // 4))
        i = j
    else:
        i += 1
print("候选块表 %d 个" % len(runs))

# 2) 对每个起点求最大可行的块数
best = {}
for p, cnt in runs:
    for c in range(cnt, 0, -1):
        for xor in (XOR, None):
            r = pull(p, c, xor)
            if r:
                prev = best.get(p)
                if prev is None or c > prev[0]:
                    best[p] = (c, xor, r[0], r[1])
                break
        if p in best:
            break
print("可成功提取的起点 %d 个" % len(best))

# 3) 链式顺序遍历整箱
starts = sorted(best)
pos = starts[0]
results = []
gaps = []
while pos < n:
    if pos not in best:
        nxt = [s for s in starts if s > pos]
        if not nxt:
            break
        gaps.append((pos, nxt[0]))
        pos = nxt[0]
        continue
    c, xor, data, end = best[pos]
    results.append((pos, c, xor, data, end))
    # 下一段起点：end 之后 0..8 字节内
    cand = [s for s in starts if end <= s <= end + 8]
    if cand:
        pos = cand[0]
    else:
        nxt = [s for s in starts if s > end]
        if not nxt:
            break
        gaps.append((end, nxt[0]))
        pos = nxt[0]

print("\n链式提取 %d 段" % len(results))
SIG = [(b'BM', 'BMP'), (b'RIFF', 'WAV/AVI'), (b'OggS', 'OGG'), (b'MZ', 'EXE'),
       (b'PK\x03\x04', 'ZIP'), (b'\x89PNG', 'PNG'), (b'GIF8', 'GIF')]
with open(os.path.join(OUTD, "_manifest.csv"), 'w', encoding='utf-8') as fp:
    fp.write("idx,box_offset,blocks,xor,size,type,width,height\n")
    for i, (p, c, xor, data, end) in enumerate(results):
        sig = 'BIN'
        w = h = 0
        for m, nm in SIG:
            if data.startswith(m):
                sig = nm
                break
        if sig == 'BMP' and len(data) > 54:
            w, h = struct.unpack_from('<ii', data, 18)
        fn = "%03d_%s%s" % (i, sig.lower(), '.bmp' if sig == 'BMP' else '.bin')
        if sig != 'BMP':
            fn = "%03d_unk%05X.bin" % (i, p)
        open(os.path.join(OUTD, fn), 'wb').write(data)
        fp.write("%d,0x%X,%d,%s,%d,%s,%d,%d\n" %
                 (i, p, c, ('%02X' % xor) if xor else '-', len(data), sig, abs(w), abs(h)))
print("空洞 %d 处" % len(gaps))
for a, b in gaps[:15]:
    print("   0x%X..0x%X (%d)" % (a, b, b - a))
print("\n输出:", OUTD)
