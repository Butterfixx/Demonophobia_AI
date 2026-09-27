# -*- coding: utf-8 -*-
"""把解包结果整合为一个完整的 HSP 源代码工程文件夹"""
import os, re, csv, shutil, struct, glob, collections

BASE = r"e:\迅雷下载\Demonophobia"
SRC_UNP = os.path.join(BASE, "unpacked")
SRC_EXT = os.path.join(BASE, "extracted_files")
OUT = os.path.join(BASE, "Demonophobia_source")

# ---------- 读入元数据 ----------
lst = open(os.path.join(SRC_UNP, "packfile_list.txt"), 'rb').read().decode('latin1')
names = re.findall(r'\+(\S+)', lst)

mapping = {}                       # 提取序号 -> 清单序号
with open(os.path.join(SRC_UNP, "_index.csv"), encoding='utf-8') as f:
    for row in csv.DictReader(f):
        mapping[int(row['extracted_idx'])] = int(row['list_idx'])

meta = {}                          # 提取序号 -> (箱偏移, 块数, 大小, 宽, 高)
with open(os.path.join(SRC_EXT, "_manifest.csv")) as f:
    for row in csv.DictReader(f):
        meta[int(row['idx'])] = (row['box_offset'], int(row['blocks']),
                                 int(row['size']), abs(int(row['width'])),
                                 abs(int(row['height'])))

# 提取序号 -> 原始文件
files = {}
for p in glob.glob(os.path.join(SRC_UNP, "bmp", "*")) + glob.glob(os.path.join(SRC_UNP, "other", "*")):
    files[int(os.path.basename(p)[:3])] = p

# ---------- 建目录 ----------
if os.path.isdir(OUT):
    shutil.rmtree(OUT)
os.makedirs(OUT)
os.makedirs(os.path.join(OUT, "_meta", "encrypted"))
os.makedirs(os.path.join(OUT, "tools"))
os.makedirs(os.path.join(OUT, "bmp"), exist_ok=True)

placed, enc_rows, csv_rows = [], [], []
for i in sorted(files):
    j = mapping.get(i, i)
    name = names[j] if j < len(names) else "unknown_%03d" % i
    src = files[i]
    b = open(src, 'rb').read()
    off, blocks, size, w, h = meta.get(i, ('?', 0, len(b), 0, 0))
    isbmp = b[:2] == b'BM'

    SPECIAL = ('demono.as', 'demono.hsp', 'start.ax', 'packfile')
    if b[:4] == b'HSP3':
        dst = os.path.join(OUT, "start.ax")
        tag = "HSP3 编译脚本"
    elif b'packfile list' in b[:64]:
        dst = os.path.join(OUT, "packfile_list.txt")
        tag = "打包清单"
    elif b[:2] != b'BM' and b'Demonophobia' in b[:200] and not b[:4] == b'\x00\x00\x01\x00':
        dst = os.path.join(OUT, "demono.hsp")
        tag = "HSP 源码"
    elif name.lower().endswith('.ico') or b[:4] == b'\x00\x00\x01\x00':
        dst = os.path.join(OUT, "icon7.ico" if name.lower().endswith('.ico') else name)
        tag = "图标"
    elif isbmp and name.lower() in SPECIAL:
        dst = os.path.join(OUT, "bmp", "%03d_%s" % (i, name))
        tag = "BMP(原名冲突) %dx%d" % (w, h)
    elif isbmp:
        dst = os.path.join(OUT, name)
        tag = "BMP %dx%d" % (w, h)
    else:
        dst = os.path.join(OUT, "_meta", "encrypted", "%03d_%s.bin" % (i, name))
        tag = "未还原(疑似 IDEA 加密)"
        enc_rows.append((i, name, len(b)))
    shutil.copy(src, dst)
    placed.append((i, j, name, len(b), tag))
    csv_rows.append((i, name, off, blocks, len(b), w if isbmp else '', h if isbmp else '', tag))

# ---------- 缺件名单 ----------
used = set(mapping.values())
missing = [(k, n) for k, n in enumerate(names) if k not in used]

# ---------- 对照表 ----------
with open(os.path.join(OUT, "_meta", "_mapping.csv"), 'w', encoding='utf-8', newline='') as f:
    wcsv = csv.writer(f)
    wcsv.writerow(["提取序号", "文件名", "箱内偏移", "块数", "大小", "宽", "高", "说明"])
    wcsv.writerows(csv_rows)

with open(os.path.join(OUT, "_meta", "_missing.txt"), 'w', encoding='utf-8') as f:
    f.write("原始打包清单共 %d 个文件，本次成功还原 %d 个。\n" % (len(names), len(placed)))
    f.write("以下 %d 个文件未能还原（IDEA 加密，需动态调试取密钥）：\n\n" % len(missing))
    for k, n in missing:
        f.write("  %3d  %s\n" % (k, n))

# ---------- 工具脚本 ----------
for p in glob.glob(os.path.join(BASE, "_unpack", "*.py")):
    shutil.copy(p, os.path.join(OUT, "tools"))

print("工程目录: %s" % OUT)
print("  还原文件 %d 个 (BMP %d, 其它 %d)" %
      (len(placed), sum(1 for r in placed if r[4].startswith('BMP')),
       len(placed) - sum(1 for r in placed if r[4].startswith('BMP'))))
print("  缺失 %d 个" % len(missing))
print("  未还原(加密) %d 个" % len(enc_rows))
print("\n缺失清单(前 40):")
for k, n in missing[:40]:
    print("   %3d %s" % (k, n))
