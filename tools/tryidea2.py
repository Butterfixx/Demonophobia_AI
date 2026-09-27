# -*- coding: utf-8 -*-
"""扩大密钥候选集: 箱头/箱尾 16 字节 blob 及其派生, 对真实加密块做 IDEA 解密"""
import struct, csv, sys, hashlib
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX = 0x29000
hdr = d[BOX:BOX + 0x20]
tail = d[-32:]

blob_hdr = hdr[0x10:0x20]                 # 45f1a03a...
blob_tail = d[-32:-16]                    # 1af8f5a8...
name = hdr[0x04:0x10]                     # "MAMA_myla_RA"
print("箱头+10 :", blob_hdr.hex())
print("箱尾16  :", blob_tail.hex())
print("名字    :", name)

cands = {}
for nm, v in (('头+00', hdr[0:0x10]), ('头+04', hdr[0x04:0x14]), ('头+10', hdr[0x10:0x20]),
              ('尾16', blob_tail), ('尾16反', blob_tail[::-1]),
              ('头+10反', blob_hdr[::-1])):
    cands[nm] = v
for nm, s in (('名字', name), ('名字+E', name + b'E')):
    cands['MD5(%s)' % nm] = hashlib.md5(s).digest()
    cands['MD5(%s)前16' % nm] = hashlib.md5(s).digest()

rows = list(csv.DictReader(open(r"e:\迅雷下载\Demonophobia\extracted_files\_manifest.csv")))
ENC = {75, 76, 77, 78, 79, 80, 81, 82, 93, 162, 163, 164, 165, 166, 198, 209, 232, 233}
enc = [r for r in rows if int(r['idx']) in ENC]

raw0 = None
for r in enc[:4]:
    t = int(r['box_offset'], 16)
    n = int(r['blocks'])
    ds = t + 4 * n
    raw = d[ds:ds + 16]
    if raw0 is None:
        raw0 = raw
print("\n测试块(段%s) 前16字节: %s" % (enc[0]['idx'], raw0.hex()))

hits = 0
for nm, key in cands.items():
    for little in (False, True):
        out = b''.join(idea_decrypt(raw0[i:i + 8], key, little) for i in (0, 8))
        ok = out[:2] == b'BM' or out[0] == 0x78 or out[:4] == b'\x00\x00\x01\x00'
        if ok:
            hits += 1
        print("  %-18s %s %s%s" % (nm, 'LE' if little else 'BE', out.hex(),
                                   '   <<<< 命中' if ok else ''))
print("\n命中 %d" % hits)
