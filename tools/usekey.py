# -*- coding: utf-8 -*-
"""用取到的密钥解密加密段"""
import struct, csv, sys, zlib
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt

KEY = open(r"e:\迅雷下载\Demonophobia\_unpack\key.bin", 'rb').read()
d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
rows = list(csv.DictReader(open(r"e:\迅雷下载\Demonophobia\extracted_files\_manifest.csv")))
ENC = {75, 76, 77, 78, 79, 80, 81, 82, 93, 162, 163, 164, 165, 166, 198, 209, 232, 233}

for r in rows:
    if int(r['idx']) not in ENC:
        continue
    t = int(r['box_offset'], 16)
    n = int(r['blocks'])
    ds = t + 4 * n
    raw = d[ds:ds + 64]
    for little in (False, True):
        out = b''.join(idea_decrypt(raw[i:i + 8], KEY, little) for i in range(0, 32, 8))
        tag = ''
        if out[:2] == b'BM':
            tag = '  <<< BMP'
        elif out[0] == 0x78:
            tag = '  <<< zlib'
        print("段%-3s %s %s%s" % (r['idx'], 'LE' if little else 'BE', out[:16].hex(), tag))
    print()
