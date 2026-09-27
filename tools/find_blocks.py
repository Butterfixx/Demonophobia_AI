import struct, zlib, os

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX = 0x29000
n = len(d)
LIMIT = 65600          # 块压缩大小上限（64KB + 余量）

# 1) 标记每个 dword 是否为"小块尺寸"
small = bytearray((n - BOX) // 4)
for i in range(len(small)):
    v = struct.unpack_from('<I', d, BOX + 4 * i)[0]
    w = v & 0x7FFFFFFF
    if 0 < w <= LIMIT:
        small[i] = 1

# 2) 找连续 run（>=2）
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
print("候选块表 run 数: %d" % len(runs))
for off, cnt in runs[:40]:
    vals = [struct.unpack_from('<I', d, off + 4 * k)[0] for k in range(min(cnt, 8))]
    print("  0x%08X (%d) 块数=%d  %s" % (off, off - BOX, cnt,
          ['0x%08X' % v for v in vals]))

# 3) 对每个 run，尝试在其后解压第一块
print("\n== 尝试解压（run 结束后即为数据起点）==")
ok = []
for off, cnt in runs:
    data_start = off + 4 * cnt
    first = struct.unpack_from('<I', d, off)[0]
    csize = first & 0x7FFFFFFF
    raw = bool(first & 0x80000000)
    if raw:
        continue
    if data_start + csize > n:
        continue
    try:
        o = zlib.decompressobj(-15)
        r = o.decompress(d[data_start:data_start + csize], 70000)
        if len(r) >= 64 and o.eof:
            pr = sum(1 for c in r if 32 <= c < 127) / len(r)
            ok.append((off, cnt, csize, len(r), pr, r[:64]))
    except Exception:
        pass
print("成功解压的块: %d" % len(ok))
for o in ok[:15]:
    print("  表@0x%X 块数%d 压缩%d -> 解压%d 可打印率%.2f" % (o[0], o[1], o[2], o[3], o[4]))
    print("     %r" % o[5])
