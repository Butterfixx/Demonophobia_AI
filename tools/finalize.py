# -*- coding: utf-8 -*-
"""统计各解密方式, 解析文件名表, 校验数量一致"""
import sys, os, re, glob, struct
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt, dec_keys, expand

KEY = open(r"e:\迅雷下载\Demonophobia\_unpack\key.bin", 'rb').read()
SUB = dec_keys(expand(KEY))
d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()

# 1) 各模式统计
modes = {}
for f in sorted(glob.glob(r"e:\迅雷下载\Demonophobia\all_files\*.bin")):
    m = os.path.basename(f)[4:-4]
    modes[m] = modes.get(m, 0) + 1
print("解密方式分布:", modes)
print("总段数:", sum(modes.values()))

# 2) 文件名表
plain = open(r"e:\迅雷下载\Demonophobia\all_files\nametable.bin", 'rb').read()


def idea(b):
    n = (len(b) // 8) * 8
    return b''.join(idea_decrypt(b[i:i + 8], KEY, False, SUB) for i in range(0, n, 8)) + b[n:]


raw = d[0x953999:0x955891]
dec = idea(raw)
names = []
for s in dec.split(b'\x00'):
    if not s:
        continue
    try:
        t = s.decode('latin1')
    except Exception:
        break
    if not re.fullmatch(r'[A-Za-z0-9_\-]+\.[A-Za-z0-9]+', t):
        break
    names.append(t)
print("\n文件名表有效名字 %d 个" % len(names))
print("  前 5:", names[:5])
print("  后 5:", names[-5:])
print("  有效字节偏移: 0x%X" % (len(b'\x00'.join(n.encode('latin1') for n in names)) + 1))
open(r"e:\迅雷下载\Demonophobia\_unpack\names_real.txt", 'w',
     encoding='utf-8').write('\n'.join(names))

# 3) 与旧清单对比
old = re.findall(r'\+(\S+)', open(
    r"e:\迅雷下载\Demonophobia\unpacked\packfile_list.txt", 'rb').read().decode('latin1'))
print("\n旧清单 %d 项, 新表 %d 项" % (len(old), len(names)))
print("前 12 对比:")
for i in range(min(12, len(names))):
    same = (i < len(old) and old[i].lower() == names[i].lower())
    print("   %-3d %-20s %-20s %s" % (i, names[i], old[i] if i < len(old) else '',
                                      '' if same else '<< 不同'))
