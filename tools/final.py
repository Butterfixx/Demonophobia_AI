import os, re, glob, struct, shutil, csv

SRC = r"e:\迅雷下载\Demonophobia\extracted_files"
DST = r"e:\迅雷下载\Demonophobia\unpacked"
for p in (DST, os.path.join(DST, 'bmp'), os.path.join(DST, 'other')):
    os.makedirs(p, exist_ok=True)

lst = open(os.path.join(SRC, "065_unk177EDA.bin"), 'rb').read().decode('latin1')
names = re.findall(r'\+(\S+)', lst)

files = [f for f in glob.glob(os.path.join(SRC, "*.*")) if not f.endswith('_manifest.csv')]
files.sort(key=lambda f: int(os.path.basename(f)[:3]))

# 锚点: 提取序号 -> 清单序号
anchors = [(8, 8), (28, 35), (65, 74), (236, 267)]


def map_idx(i):
    if i <= anchors[0][0]:
        return i
    for a, b in zip(anchors, anchors[1:]):
        if a[0] <= i <= b[0]:
            r = (i - a[0]) / (b[0] - a[0])
            return int(round(a[1] + r * (b[1] - a[1])))
    return i + (anchors[-1][1] - anchors[-1][0])


used = set()
report = []
for f in files:
    i = int(os.path.basename(f)[:3])
    b = open(f, 'rb').read()
    j = min(map_idx(i), len(names) - 1)
    while j in used and j < len(names) - 1:
        j += 1
    used.add(j)
    name = names[j]
    safe = name.replace('/', '_').replace('\\', '_')
    enc = ''
    if b[:2] == b'BM':
        sub = 'bmp'
    else:
        sub = 'other'
        if len(b) > 64 and sum(1 for c in b[:64] if 32 <= c < 127) < 8:
            enc = ' [IDEA加密,未还原]'
    safe = "%03d_%s" % (i, safe)
    out = os.path.join(DST, sub, safe)
    k = 1
    while os.path.exists(out):
        out = os.path.join(DST, sub, "%s.%d" % (safe, k))
        k += 1
    shutil.copy(f, out)
    report.append((i, j, len(b), safe, enc))

with open(os.path.join(DST, "_index.csv"), 'w', encoding='utf-8') as fp:
    fp.write("extracted_idx,list_idx,size,filename,note\n")
    for r in report:
        fp.write("%d,%d,%d,%s,%s\n" % (r[0], r[1], r[2], r[3], r[4]))

shutil.copy(os.path.join(SRC, "008_unk47DE7.bin"),
            os.path.join(DST, "demono_as_源码.txt"))
shutil.copy(os.path.join(SRC, "236_unk8C9283.bin"),
            os.path.join(DST, "start.ax"))
shutil.copy(os.path.join(SRC, "065_unk177EDA.bin"),
            os.path.join(DST, "packfile_list.txt"))

print("输出目录: %s" % DST)
print("  命名文件 %d 个 (bmp %d / other %d)" %
      (len(report),
       sum(1 for r in report if r[3].endswith('.bmp')),
       sum(1 for r in report if not r[3].endswith('.bmp'))))
print("  清单总数 %d，缺失 %d 个" % (len(names), len(names) - len(used)))
print("\n前 25 个映射:")
for r in report[:25]:
    print("   %3d -> %-22s %8d%s" % (r[0], r[3], r[2], r[4]))
print("\n非 bmp 命名:")
for r in report:
    if not r[3].endswith('.bmp'):
        print("   %3d -> %-22s %8d%s" % (r[0], r[3], r[2], r[4]))
