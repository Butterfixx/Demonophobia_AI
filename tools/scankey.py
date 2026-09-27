# -*- coding: utf-8 -*-
"""在箱头/箱尾 0x200 字节内滑窗搜索 IDEA 密钥"""
import struct, csv, sys
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX = 0x29000
rows = list(csv.DictReader(open(r"e:\迅雷下载\Demonophobia\extracted_files\_manifest.csv")))
ENC = {75, 76, 77, 78, 79, 80, 81, 82, 93, 162, 163, 164, 165, 166, 198, 209, 232, 233}

blocks = []
for r in rows:
    if int(r['idx']) in ENC:
        t = int(r['box_offset'], 16)
        n = int(r['blocks'])
        ds = t + 4 * n
        blocks.append(d[ds:ds + 8])
print("测试块 %d 个, 首块 %s" % (len(blocks), blocks[0].hex()))

ZLIB = (b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e')


def score(key, little):
    """返回前 6 个块中解密后像 zlib/BMP 的个数"""
    good = 0
    for b in blocks[:6]:
        try:
            out = idea_decrypt(b, key, little)
        except Exception:
            return 0
        if out[:2] in ZLIB or out[:2] == b'BM':
            good += 1
    return good


ranges = [(BOX, BOX + 0x200), (BOX + 0x40, BOX + 0x140),
          (len(d) - 0x200, len(d) - 16), (0x29000 - 0x200, 0x29000)]
found = []
for a, b in ranges:
    for off in range(max(0, a), min(b, len(d) - 16)):
        key = d[off:off + 16]
        for little in (False, True):
            s = score(key, little)
            if s >= 1:
                found.append((off, little, s, key))
                print("偏移 0x%X %s 命中%d/6 密钥 %s" %
                      (off, 'LE' if little else 'BE', s, key.hex()))
print("\n候选总数 %d" % len(found))
