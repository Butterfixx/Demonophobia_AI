# -*- coding: utf-8 -*-
"""用真实文件名表给 283 个文件命名，生成最终工程目录"""
import sys, os, re, glob, struct, shutil, csv
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt, dec_keys, expand

BASE = r"e:\迅雷下载\Demonophobia"
SRC = os.path.join(BASE, "all_files")
OUT = os.path.join(BASE, "Demonophobia_source")

KEY = open(r"e:\迅雷下载\Demonophobia\_unpack\key.bin", 'rb').read()
SUB = dec_keys(expand(KEY))
d = open(os.path.join(BASE, "Demonophobia.exe"), 'rb').read()

# ---- 文件名表 ----
raw = d[0x953999:0x955891]
n = (len(raw) // 8) * 8
dec = b''.join(idea_decrypt(raw[i:i + 8], KEY, False, SUB) for i in range(0, n, 8)) + raw[n:]
names = []
for s in dec.split(b'\x00'):
    if not s:
        continue
    t = s.decode('latin1')
    if not re.fullmatch(r'[\x21-\x7e]{1,40}', t) or ' ' in t:
        break
    names.append(t)
print("文件名表: %d 个" % len(names))

files = sorted(glob.glob(os.path.join(SRC, "[0-9][0-9][0-9]_*.bin")))
print("提取文件: %d 个" % len(files))
assert len(files) == len(names), "数量不一致 %d vs %d" % (len(files), len(names))

if os.path.isdir(OUT):
    shutil.rmtree(OUT)
os.makedirs(OUT)
os.makedirs(os.path.join(OUT, "_meta"))
os.makedirs(os.path.join(OUT, "tools"))

rows = []
for i, f in enumerate(files):
    b = open(f, 'rb').read()
    name = names[i]
    if b[:4] == b'HSP3':
        name, kind = 'start.ax', 'HSP3 编译脚本'
    elif b[:4] == b'\x00\x00\x01\x00':
        name, kind = 'icon7.ico', '图标'
    elif b[:2] == b'BM':
        w, h = struct.unpack_from('<ii', b, 18)
        kind = 'BMP %dx%d' % (abs(w), abs(h))
    elif name.lower() in ('packfile', 'packfile.txt'):
        name, kind = 'packfile_list.txt', '打包清单'
    elif b'Demonophobia' in b[:200]:
        name, kind = 'demono.hsp', 'HSP 源码'
    else:
        kind = '数据'
    open(os.path.join(OUT, name), 'wb').write(b)
    rows.append((i, name, len(b), kind))

with open(os.path.join(OUT, "_meta", "_mapping.csv"), 'w', encoding='utf-8',
          newline='') as fp:
    w = csv.writer(fp)
    w.writerow(["箱内序号", "文件名", "大小", "类型"])
    w.writerows(rows)

for p in glob.glob(os.path.join(BASE, "_unpack", "*.py")):
    shutil.copy(p, os.path.join(OUT, "tools"))
shutil.copy(os.path.join(BASE, "_unpack", "key.bin"), os.path.join(OUT, "_meta"))

open(os.path.join(OUT, "_meta", "_idea_key.txt"), 'w').write(
    "IDEA 主密钥(16字节): %s\n取自运行时 [0x442718]->+0x2C->+0x20\n" % KEY.hex().upper())

print("\n生成 %d 个文件到 %s" % (len(rows), OUT))
kinds = {}
for _, _, _, k in rows:
    kinds[k.split()[0]] = kinds.get(k.split()[0], 0) + 1
print("类型分布:", kinds)
print("\n关键文件:")
for i, nm, sz, k in rows:
    if k not in ('BMP 0x0',) and not k.startswith('BMP'):
        print("   #%-3d %-20s %8d  %s" % (i, nm, sz, k))
