import os, re, glob, struct, collections

DST = r"e:\迅雷下载\Demonophobia\extracted_files"
lst = open(os.path.join(DST, "065_unk177EDA.bin"), 'rb').read().decode('latin1')
names = re.findall(r'\+(\S+)', lst)
print("清单条目数: %d" % len(names))
print("前 12:", names[:12])
ext = collections.Counter(n.rsplit('.', 1)[-1].lower() for n in names)
print("扩展名分布:", dict(ext))

files = [f for f in sorted(glob.glob(os.path.join(DST, "*.*")))
         if not f.endswith('_manifest.csv') and 'unk177EDA' not in f]
print("待命名文件: %d" % len(files))

# 按顺序对应
seq = [int(os.path.basename(f)[:3]) for f in files]
files = [f for _, f in sorted(zip(seq, files))]
print("\n编号序列连续性: %d..%d" % (min(seq), max(seq)))
print("\n== 顺序对照（前 40）==")
for i, f in enumerate(files[:40]):
    b = open(f, 'rb').read()
    info = ''
    if b[:2] == b'BM' and len(b) > 54:
        w, h = struct.unpack_from('<ii', b, 18)
        info = "%dx%d" % (abs(w), abs(h))
    else:
        info = b[:8].hex()
    nm = names[i] if i < len(names) else '<无>'
    print("  %-16s %-9d %-12s -> %s" % (os.path.basename(f), len(b), info, nm))
