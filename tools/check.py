import os, struct, glob, collections, zlib

DST = r"e:\迅雷下载\Demonophobia\extracted_files"
rows = []
for f in sorted(glob.glob(os.path.join(DST, "*.*"))):
    if f.endswith('_manifest.csv'):
        continue
    b = open(f, 'rb').read()
    rows.append((os.path.basename(f), b))
print("文件数:", len(rows))
sig = collections.Counter()
for name, b in rows:
    if b[:2] == b'BM':
        sig['BMP'] += 1
    elif b[:4] == b'RIFF':
        sig['RIFF'] += 1
    elif b[:2] == b'MZ':
        sig['MZ'] += 1
    else:
        sig['BIN'] += 1
print("类型分布:", dict(sig))
print("\n非 BMP 文件:")
for name, b in rows:
    if not b.startswith(b'BM'):
        print("   %-24s %8d  %s" % (name, len(b), b[:24].hex()))

print("\nBMP 尺寸分布 TOP12:")
c = collections.Counter()
for name, b in rows:
    if b[:2] == b'BM' and len(b) > 54:
        w, h = struct.unpack_from('<ii', b, 18)
        c[(abs(w), abs(h))] += 1
for (w, h), k in c.most_common(12):
    print("   %4d x %-4d : %d" % (w, h, k))

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
print("\n== 两处较大空洞 ==")
for a, b in ((0x9017B, 0x90CAC), (0xB6D0B, 0xB9DB9)):
    blk = d[a:b]
    print("  0x%X..0x%X (%d) 前48: %s" % (a, b, b - a, blk[:48].hex()))
    for xb in (0xA3, None):
        x = blk if xb is None else bytes(v ^ xb for v in blk)
        for w in (15, -15):
            try:
                r = zlib.decompressobj(w).decompress(x, 100000)
                print("     %s wbits%d -> %d 字节 %r" % (xb, w, len(r), r[:40]))
            except Exception:
                pass
