# -*- coding: utf-8 -*-
"""用 IDEA 密钥解密箱尾文件名索引表"""
import sys
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
KEY = open(r"e:\迅雷下载\Demonophobia\_unpack\key.bin", 'rb').read()

START = 0x953999
END = 0x955891          # 箱尾
n = ((END - START) // 8) * 8
data = d[START:START + n]
out = b''.join(idea_decrypt(data[i:i + 8], KEY) for i in range(0, n, 8))

print("解密 %d 字节" % len(out))
for i in range(0, 96, 16):
    r = out[i:i + 16]
    print("  +%02X %s  %s" % (i, r.hex(),
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in r)))

names = [s.decode('latin1') for s in out.split(b'\x00') if s]
print("\n解析出 %d 个名字" % len(names))
print("前 12:", names[:12])
print("后 12:", names[-12:])
open(r"e:\迅雷下载\Demonophobia\_unpack\names_real.txt", 'w',
     encoding='utf-8').write('\n'.join(names))
print("已保存 names_real.txt")
