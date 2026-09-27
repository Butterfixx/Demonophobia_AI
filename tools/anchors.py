# -*- coding: utf-8 -*-
"""从 HSP 源码里的 picload 尺寸注释提取锚点，校验/修正文件名映射"""
import re, os, struct, glob, collections

src = open(r"e:\迅雷下载\Demonophobia\unpacked\demono_as_源码.txt", 'rb').read().decode('latin1')
names = re.findall(r'\+(\S+)', open(
    r"e:\迅雷下载\Demonophobia\unpacked\packfile_list.txt", 'rb').read().decode('latin1'))
idx = {n.lower(): i for i, n in enumerate(names)}

# picload "xxx.bmp" ;(w,h)
pairs = re.findall(r'picload\s*"([^"]+)"\s*;\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', src)
print("带尺寸注释的 picload: %d 条" % len(pairs))
dim = {}
for nm, w, h in pairs:
    dim.setdefault((int(w), int(h)), set()).add(nm.lower())
print("不同尺寸: %d" % len(dim))
for k, v in list(dim.items())[:15]:
    print("   %-12s -> %s" % (str(k), sorted(v)[:4]))

# 已提取 BMP 的尺寸
bmp = {}
for f in glob.glob(r"e:\迅雷下载\Demonophobia\unpacked\bmp\*"):
    b = open(f, 'rb').read()
    i = int(os.path.basename(f)[:3])
    if b[:2] == b'BM' and len(b) > 54:
        w, h = struct.unpack_from('<ii', b, 18)
        bmp[i] = (abs(w), abs(h))
print("\n提取的 BMP: %d 个" % len(bmp))

# 匹配：尺寸唯一对应的名字
anchors = []
for i, wh in sorted(bmp.items()):
    cand = dim.get(wh)
    if cand and len(cand) == 1:
        nm = next(iter(cand))
        if nm in idx:
            anchors.append((i, idx[nm], nm, wh))
print("\n由尺寸唯一确定的锚点: %d 个" % len(anchors))
for a in anchors[:30]:
    print("   提取#%-3d -> 清单#%-3d %-16s %s" % a)
