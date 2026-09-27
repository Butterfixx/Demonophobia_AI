import os, re, glob, struct

DST = r"e:\迅雷下载\Demonophobia\extracted_files"
lst = open(os.path.join(DST, "065_unk177EDA.bin"), 'rb').read().decode('latin1')
names = re.findall(r'\+(\S+)', lst)
idx = {}
for i, n in enumerate(names):
    idx[n.lower()] = i
for k in ('demono.as', 'demono.ax', 'demono.hsp', 'icon7.ico'):
    print("清单中 %-12s 序号 %s" % (k, idx.get(k, '无')))
print("packfile: ", [(i, n) for i, n in enumerate(names) if 'packfile' in n.lower()])
print("非 bmp 条目: ", [(i, n) for i, n in enumerate(names) if not n.lower().endswith('.bmp')])

files = sorted(glob.glob(os.path.join(DST, "*.*")))
files = [f for f in files if not f.endswith('_manifest.csv')]
seq = sorted(files, key=lambda f: int(os.path.basename(f)[:3]))

print("\n== 已提取文件中的特殊项 ==")
for f in seq:
    b = open(f, 'rb').read()
    i = int(os.path.basename(f)[:3])
    tag = ''
    if b[:4] == b'HSP3':
        tag = 'HSP3(ax)'
    elif b[:2] == b'BM':
        tag = 'BMP'
    elif b[:4] == b'\x00\x00\x01\x00' and len(b) < 5000:
        tag = 'ICO?'
    elif b[:4] == b'RIFF':
        tag = 'RIFF'
    elif b[:1] == b'\x0d' or b[:1] == b';':
        tag = 'TEXT'
    elif len(b) < 100:
        tag = 'TINY'
    else:
        tag = '??'
    if tag in ('HSP3(ax)', 'ICO?', 'TEXT', 'TINY', 'RIFF'):
        print("  %3d  %-18s %8d  %s" % (i, os.path.basename(f), len(b), tag))
