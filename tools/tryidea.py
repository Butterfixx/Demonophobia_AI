# -*- coding: utf-8 -*-
"""用箱头候选 16 字节做 IDEA 解密，验证是否得到 zlib/BMP"""
import struct, csv, sys
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX = 0x29000

hdr = d[BOX:BOX + 0x20]
print("箱头:", hdr.hex())
cands = {
    '+00': hdr[0x00:0x10], '+04': hdr[0x04:0x14],
    '+10': hdr[0x10:0x20], '+00(反转)': hdr[0x00:0x10][::-1],
    '+10(反转)': hdr[0x10:0x20][::-1],
}
for k, v in cands.items():
    print("   候选 %-10s %s" % (k, v.hex()))

# 加密段的原始块数据
rows = list(csv.DictReader(open(r"e:\迅雷下载\Demonophobia\extracted_files\_manifest.csv")))
ENC_IDX = {75, 76, 77, 78, 79, 80, 81, 82, 93, 162, 163, 164, 165, 166,
           198, 209, 232, 233}
enc = [r for r in rows if int(r['idx']) in ENC_IDX]
print("\n加密段 %d 个" % len(enc))

for r in enc[:3]:
    t = int(r['box_offset'], 16)
    n = int(r['blocks'])
    sizes = [struct.unpack_from('<I', d, t + 4 * i)[0] for i in range(n)]
    ds = t + 4 * n
    raw = d[ds:ds + 32]
    print("\n段%s  表@0x%X 块%d 数据@0x%X  前32字节 %s" % (r['idx'], t, n, ds, raw.hex()))
    for name, key in cands.items():
        for little in (False, True):
            out = b''
            for i in range(0, 16, 8):
                out += idea_decrypt(raw[i:i + 8], key, little)
            mark = ''
            if out[:2] in (b'BM',) or out[0] == 0x78:
                mark = '  <<< 命中'
            print("     %-10s %s  %s%s" % (name, 'LE' if little else 'BE', out.hex(), mark))
