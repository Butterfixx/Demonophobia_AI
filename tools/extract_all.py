# -*- coding: utf-8 -*-
"""统一提取器: 顺序走箱, 每块自动识别 (XOR+zlib / IDEA+zlib / IDEA裸 / 裸zlib / 原样)"""
import struct, zlib, sys, os
sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt, dec_keys, expand

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
KEY = open(r"e:\迅雷下载\Demonophobia\_unpack\key.bin", 'rb').read()
SUB = dec_keys(expand(KEY))          # IDEA 解密子密钥（预计算一次）
BOX, END, LIMIT = 0x29000, 0x955891, 65600
OUT = r"e:\迅雷下载\Demonophobia\all_files"
os.makedirs(OUT, exist_ok=True)


def inflate(buf):
    for w in (15, -15, 47):
        try:
            o = zlib.decompressobj(w)
            r = o.decompress(buf, 4000000)
            if o.eof:
                return r
        except Exception:
            pass
    return None


def idea(buf):
    n = (len(buf) // 8) * 8
    return b''.join(idea_decrypt(buf[i:i + 8], KEY, False, SUB) for i in range(0, n, 8)) + buf[n:]


def decode(raw, stored):
    """返回 (方式, 明文) 或 None"""
    if stored:
        r = idea(raw)
        if r[:2] == b'BM' or r[:4] == b'\x00\x00\x01\x00':
            return 'idea_raw', r
        return 'raw', raw
    x = bytes(b ^ 0xA3 for b in raw)
    r = inflate(x)
    if r:
        return 'xor', r
    r = idea(raw)
    if r[:2] == b'BM':
        return 'idea_raw', r
    r2 = inflate(r)
    if r2:
        return 'idea', r2
    r = inflate(raw)
    if r:
        return 'raw_inf', r
    if raw[:2] == b'BM':
        return 'plain', raw
    return None


small = bytearray(len(d))
for i in range(len(d) - 4):
    v = struct.unpack_from('<I', d, i)[0]
    if 0 < (v & 0x7FFFFFFF) <= LIMIT:
        small[i] = 1


def run(p):
    v, q = [], p
    while q + 4 <= len(d) and small[q]:
        v.append(struct.unpack_from('<I', d, q)[0])
        q += 4
        if len(v) > 200:
            break
    return v


def try_section(p):
    """在 p 处尝试解析一段, 返回 (n, 数据, 方式, 数据止点)"""
    vals = run(p)
    for n in range(min(len(vals), 100), 0, -1):
        ds = p + 4 * n
        off, pieces, mode = ds, [], None
        okall = True
        for k in range(n):
            t = vals[k]
            cs = t & 0x7FFFFFFF
            if cs == 0 or off + cs > END + 64:
                okall = False
                break
            raw = d[off:off + cs]
            r = decode(raw, bool(t & 0x80000000))
            if r is None:
                okall = False
                break
            m, plain = r
            if mode is None:
                mode = m
            elif m != mode:
                okall = False
                break
            pieces.append(plain)
            off += cs
        if okall and pieces:
            return n, b''.join(pieces), mode, off
    return None


pos, secs = BOX + 0x20, []
while pos < END - 8:
    got = None
    for delta in range(0, 40):
        got = try_section(pos + delta)
        if got:
            pos += delta
            break
    if not got:
        nxt = pos + 1
        while nxt < END and not small[nxt]:
            nxt += 1
        if nxt >= END:
            break
        pos = nxt
        continue
    n, data, mode, endp = got
    secs.append((pos, n, mode, data))
    pos = endp

log = open(os.path.join(OUT, "_sections.log"), 'w', encoding='utf-8')
for i, (p, n, mode, data) in enumerate(secs):
    log.write("#%-3d 表@0x%-7X 块%-2d %-9s %8d 字节 头 %s\n" %
              (i, p, n, mode, len(data), data[:8].hex()))
log.close()
cnt = {}
for _, _, mode, _ in secs:
    cnt[mode] = cnt.get(mode, 0) + 1
print("顺序解析出 %d 段, 方式分布 %s" % (len(secs), cnt))

for i, (p, n, mode, data) in enumerate(secs):
    open(os.path.join(OUT, "%03d_%s.bin" % (i, mode)), 'wb').write(data)

# 箱尾文件名表（特殊段，无块表）
tail = d[0x953999:0x953999 + 3344]
plain = idea(tail)
open(os.path.join(OUT, "nametable.bin"), 'wb').write(plain)
print("\n文件名表解密 %d 字节, 开头 %s" % (len(plain), plain[:40]))
