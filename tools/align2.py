# -*- coding: utf-8 -*-
"""把间隙按"块表+数据+填充"精确切分，得到箱内全部段的真实顺序"""
import struct, json, re, sys

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
N, LIMIT = len(d), 65600
PADS = (3, 7, 11, 15)
sys.setrecursionlimit(3000)

small = bytearray(N)
for i in range(N - 4):
    v = struct.unpack_from('<I', d, i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        small[i] = 1


def read_run(p):
    """从 p 起连续的小 dword"""
    vals, q = [], p
    while q + 4 <= N and small[q]:
        vals.append(struct.unpack_from('<I', d, q)[0] & 0x7FFFFFFF)
        q += 4
    return vals


W = json.load(open(r"e:\迅雷下载\Demonophobia\_unpack\walk.json"))
chain, gaps = W['chain'], W['gaps']

newsecs = []
for a, b in gaps:
    target = b
    memo = {}

    def solve(pos, acc):
        if (target - pos) in PADS:
            return acc
        if pos in memo:
            return None
        for pad in PADS:
            p = pos + pad
            if p >= target:
                continue
            vals = read_run(p)
            for n in range(min(len(vals), 40), 0, -1):
                end = p + 4 * n + sum(vals[:n])
                if end > target:
                    continue
                r = solve(end, acc + [(p, n)])
                if r is not None:
                    return r
        memo[pos] = 1
        return None

    if b - a <= 20:
        continue
    r = solve(a, [])
    if r is None:
        print("  间隙 0x%X..0x%X (%d) 切分失败" % (a, b, b - a))
        newsecs.append((a, b))
    else:
        newsecs += r

allsecs = sorted([(c[0], 'ok', c[3]) for c in chain] +
                 [(s[0], 'enc', 0) for s in newsecs])
print("解压段 %d + 加密段 %d = %d 段" %
      (len(chain), len(newsecs), len(allsecs)))

names = re.findall(r'\+(\S+)', open(
    r"e:\迅雷下载\Demonophobia\unpacked\packfile_list.txt", 'rb').read().decode('latin1'))
print("清单 %d 项" % len(names))

okmap = {c[0]: i for i, c in enumerate(chain)}
print("\n锚点校验(应=8/35/74/267):")
res = []
for k, (p, t, sz) in enumerate(allsecs):
    res.append((k, p, t, okmap.get(p)))
    if t == 'ok' and okmap[p] in (8, 28, 65, 236):
        nm = names[k] if k < len(names) else '?'
        print("   提取#%-3d 全局#%-3d -> %s" % (okmap[p], k, nm))
json.dump(res, open(r"e:\迅雷下载\Demonophobia\_unpack\order.json", 'w'))
