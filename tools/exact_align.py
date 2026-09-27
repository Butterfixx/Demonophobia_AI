# -*- coding: utf-8 -*-
"""用'间隙里的明文块表'精确还原每个文件在打包清单中的序号"""
import struct, zlib, os, re, json

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX, n, XOR, LIMIT = 0x29000, len(d), 0xA3, 65600


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


# 1) 全文件逐字节标记"小块尺寸 dword"
small = bytearray(n)
for i in range(n - 4):
    v = struct.unpack_from('<I', d, i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        small[i] = 1

# 2) 极大 run（步长 4）
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
runset = {p: c for p, c in runs}


def pull(p, cnt, xor):
    ds = p + 4 * cnt
    off, out = ds, []
    for k in range(cnt):
        t = struct.unpack_from('<I', d, p + 4 * k)[0]
        cs = t & 0x7FFFFFFF
        if cs == 0 or off + cs > n:
            return None
        chunk = d[off:off + cs]
        if xor is not None:
            chunk = bytes(b ^ xor for b in chunk)
        if t & 0x80000000:
            out.append(chunk)
        else:
            r = inflate(chunk)
            if r is None:
                return None
            out.append(r)
        off += cs
    return b''.join(out), off


best = {}
for p, cnt in runs:
    for c in range(cnt, 0, -1):
        for xor in (XOR, None):
            r = pull(p, c, xor)
            if r:
                if p not in best or c > best[p][0]:
                    best[p] = (c, xor, r[0], r[1])
                break
        if p in best:
            break

# 3) 链式顺序遍历
starts = sorted(best)
pos, chain, gaps = starts[0], [], []
while pos < n:
    if pos not in best:
        nxt = [s for s in starts if s > pos]
        if not nxt:
            break
        gaps.append((pos, nxt[0]))
        pos = nxt[0]
        continue
    c, xor, data, end = best[pos]
    chain.append((pos, c, end, len(data)))
    cand = [s for s in starts if end <= s <= end + 8]
    if cand:
        pos = cand[0]
    else:
        nxt = [s for s in starts if s > end]
        if not nxt:
            break
        gaps.append((end, nxt[0]))
        pos = nxt[0]

print("已解压段 %d，间隙 %d" % (len(chain), len(gaps)))

# 4) 每个间隙里的文件数 = 间隙内"块表 run"的个数
gap_files = []
for a, b in gaps:
    cnt = 0
    detail = []
    for rp, rc in runs:
        if a <= rp and rp + 4 * rc <= b:
            cnt += 1
            detail.append((rp, rc))
    gap_files.append((a, b, b - a, cnt, detail))
big = [(a, b, sz, c) for a, b, sz, c, _ in gap_files if sz > 100]
print("大间隙(>100B) %d 处，小间隙(<=100B) %d 处" %
      (len(big), len(gap_files) - len(big)))
print("大间隙合计可识别块表数: %d" % sum(c for _, _, _, c in big))
for a, b, sz, c in big[:20]:
    print("   0x%X..0x%X (%6d 字节) 表%d个" % (a, b, sz, c))
tiny = [x for x in gap_files if x[2] <= 100]
print("小间隙中带块表的: %d" % sum(1 for x in tiny if x[3]))
print("小间隙尺寸分布:", {s: sum(1 for x in tiny if x[2] == s) for s in
                     sorted(set(x[2] for x in tiny))[:10]})

# 5) 精确序号：间隙里的文件占据清单中的名额
names = re.findall(r'\+(\S+)', open(
    r"e:\迅雷下载\Demonophobia\unpacked\packfile_list.txt", 'rb').read().decode('latin1'))
gapmap = {(a, b): c for a, b, _, c, _ in gap_files}
slot, result = 0, []
prev_end = None
for idx, (p, c, end, size) in enumerate(chain):
    if prev_end is not None:
        g = [x for x in gap_files if x[0] == prev_end]
        if g:
            slot += g[0][3]
    result.append((idx, slot, p, size))
    slot += 1
    prev_end = end

print("\n清单总数 %d，精确对齐后最大序号 %d" % (len(names), slot - 1))
print("\n锚点校验:")
for i, s, p, sz in result:
    if i in (8, 28, 65, 236):
        print("   提取#%d -> 清单#%d = %s" % (i, s, names[s]))
json.dump([[i, s, p, sz] for i, s, p, sz in result],
          open(r"e:\迅雷下载\Demonophobia\_unpack\align.json", 'w'))
