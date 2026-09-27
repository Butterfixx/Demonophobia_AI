# -*- coding: utf-8 -*-
"""顺序走一遍整箱，记录每段(表起点,块数,数据止点)与段间间隙，并打印间隙字节"""
import struct, zlib, json

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


small = bytearray(n)
for i in range(n - 4):
    v = struct.unpack_from('<I', d, i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        small[i] = 1
runs, i = [], BOX
while i < n - 4:
    if small[i]:
        j = i
        while j < n and small[j]:
            j += 4
        runs.append((i, (j - i) // 4))
        i = j
    else:
        i += 1


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
    chain.append([pos, c, end, len(data)])
    cand = [s for s in starts if end <= s <= end + 8]
    if cand:
        pos = cand[0]
    else:
        nxt = [s for s in starts if s > end]
        if not nxt:
            break
        gaps.append((end, nxt[0]))
        pos = nxt[0]

json.dump({'chain': chain, 'gaps': gaps},
          open(r"e:\迅雷下载\Demonophobia\_unpack\walk.json", 'w'))
print("段 %d 间隙 %d 已保存" % (len(chain), len(gaps)))
print("\n段间填充字节（前 12 处）:")
for i in range(1, min(13, len(chain))):
    de = chain[i - 1][2]
    nxt = chain[i][0]
    gap = d[de:nxt]
    print("  段%d 数据止0x%X → 段%d 表@0x%X 填充%2d: %s" %
          (i - 1, de, i, nxt, len(gap), ' '.join('%02X' % b for b in gap)))
print("\n大间隙(>100) 首 8 处开头 32 字节:")
for a, b in [g for g in gaps if g[1] - g[0] > 100][:8]:
    print("  0x%X (%6d) %s" % (a, b - a, ' '.join('%02X' % x for x in d[a:a + 32])))
