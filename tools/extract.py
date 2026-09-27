import struct, zlib, os, re

PATH = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
OUTD = r"e:\迅雷下载\Demonophobia\_unpack\out"
os.makedirs(OUTD, exist_ok=True)
d = open(PATH, 'rb').read()
BOX = 0x29000
n = len(d)
XOR = 0xA3
LIMIT = 65600

# ---- 1) 找所有"小块尺寸"dword 的极大连续 run ----
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


def inflate(buf):
    for w in (15, -15):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(buf, 70000)
            if o.eof and r:
                return r
        except Exception:
            pass
    return None


# ---- 2) 逐段提取 ----
sections = []
for p, cnt in runs:
    table = [struct.unpack_from('<I', d, p + 4 * i)[0] for i in range(cnt)]
    ds = p + 4 * cnt
    blocks = []
    ok = True
    off = ds
    for t in table:
        cs = t & 0x7FFFFFFF
        raw_flag = bool(t & 0x80000000)
        if off + cs > n or cs == 0:
            ok = False
            break
        chunk = bytes(b ^ XOR for b in d[off:off + cs])
        if raw_flag:
            blocks.append(chunk)
        else:
            r = inflate(chunk)
            if r is None:
                ok = False
                break
            blocks.append(r)
        off += cs
    if not ok or not blocks:
        continue
    sections.append((p, cnt, off, b''.join(blocks)))

# 去重(保留起始最小、覆盖最长的)
sections.sort(key=lambda s: (-len(s[3]), s[0]))
kept = []
used = []
for s in sections:
    if any(not (s[0] >= a or s[2] <= a) for a in used):
        continue
    kept.append(s)
    used.append(s[0])
    used.append(s[2])
kept.sort(key=lambda s: s[0])

print("提取到 %d 个段\n" % len(kept))
SIG = [(b'BM', 'BMP'), (b'RIFF', 'RIFF/WAV/AVI'), (b'OggS', 'OGG'), (b'MZ', 'EXE/DLL'),
       (b'PK\x03\x04', 'ZIP'), (b'\x89PNG', 'PNG'), (b'GIF8', 'GIF'), (b'HSP', 'HSP?')]
for p, cnt, end, data in kept:
    sig = '?'
    for m, name in SIG:
        if data.startswith(m):
            sig = name
            break
    pr = sum(1 for c in data if 32 <= c < 127) / max(1, len(data))
    print("  表@0x%-8X 块%-3d 数据0x%X-0x%X  大小%-9d %-6s 可打印%.2f" %
          (p, cnt, p + 4 * cnt, end, len(data), sig, pr))
    fn = os.path.join(OUTD, "sec_%08X.bin" % p)
    open(fn, 'wb').write(data)
print("\n已保存到 %s" % OUTD)
