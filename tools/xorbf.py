# -*- coding: utf-8 -*-
"""对 18 个未知段做 单字节 XOR 暴力 + zlib 解压 验证"""
import struct, csv, zlib

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
rows = list(csv.DictReader(open(r"e:\迅雷下载\Demonophobia\extracted_files\_manifest.csv")))
ENC = {75, 76, 77, 78, 79, 80, 81, 82, 93, 162, 163, 164, 165, 166, 198, 209, 232, 233}


def inflate(buf):
    for w in (15, -15, 47):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(buf, 300000)
            if o.eof and len(r) > 100:
                return r
        except Exception:
            pass
    return None


for r in rows:
    if int(r['idx']) not in ENC:
        continue
    t = int(r['box_offset'], 16)
    n = int(r['blocks'])
    ds = t + 4 * n
    sizes = [struct.unpack_from('<I', d, t + 4 * i)[0] for i in range(n)]
    tot = sum(s & 0x7FFFFFFF for s in sizes)
    raw = d[ds:ds + min(tot, 4096)]
    hit = None
    for x in range(256):
        if x:
            b = bytes(c ^ x for c in raw[:512])
        else:
            b = raw[:512]
        if b[:2] == b'BM':
            hit = (x, 'BMP 明文', b[:16])
            break
        r2 = inflate(b)
        if r2:
            hit = (x, 'zlib 解压 %d 字节' % len(r2), r2[:16])
            break
    print("段%-3s 表@0x%X 块%d 共%d字节  首字节 %02X  -> %s" %
          (r['idx'], t, n, tot, raw[0],
           ('XOR 0x%02X 命中: %s %s' % (hit[0], hit[1], hit[2].hex())) if hit else '无'))
