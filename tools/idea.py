# -*- coding: utf-8 -*-
"""标准 IDEA (128bit key, 8 byte block) 实现 + 密钥候选验证"""
import struct, zlib

M = 0x10001


def mul(a, b):
    if a == 0:
        a = 0x10000
    if b == 0:
        b = 0x10000
    r = (a * b) % M
    return 0 if r == 0x10000 else r


def add(a, b):
    return (a + b) & 0xFFFF


def inv(a):
    if a == 0:
        return 0
    return pow(a, 0xFFFF, M)


def rotl128(k, n):
    v = int.from_bytes(k, 'big')
    v = ((v << n) | (v >> (128 - n))) & ((1 << 128) - 1)
    return v.to_bytes(16, 'big')


def expand(key16):
    """52 个 16 位子密钥（1-indexed 返回，下标 0 占位）"""
    z = [0]
    k = bytes(key16)
    for g in range(6):
        for t in range(0, 16, 2):
            z.append((k[t] << 8) | k[t + 1])
        k = rotl128(k, 25)
    for t in range(0, 8, 2):
        z.append((k[t] << 8) | k[t + 1])
    return z


def dec_keys(z):
    d = [0] * 53
    tbl = [(49, 50, 51, 52, 47, 48), (43, 45, 44, 46, 41, 42),
           (37, 39, 38, 40, 35, 36), (31, 33, 32, 34, 29, 30),
           (25, 27, 26, 28, 23, 24), (19, 21, 20, 22, 17, 18),
           (13, 15, 14, 16, 11, 12), (7, 9, 8, 10, 5, 6)]
    for r, t in enumerate(tbl):
        b = 6 * r + 1
        d[b + 0] = inv(z[t[0]])
        d[b + 1] = (-z[t[1]]) & 0xFFFF
        d[b + 2] = (-z[t[2]]) & 0xFFFF
        d[b + 3] = inv(z[t[3]])
        d[b + 4] = z[t[4]]
        d[b + 5] = z[t[5]]
    d[49] = inv(z[1]); d[50] = (-z[2]) & 0xFFFF
    d[51] = (-z[3]) & 0xFFFF; d[52] = inv(z[4])
    return d


def _rounds(x1, x2, x3, x4, z):
    for r in range(8):
        b = 6 * r + 1
        x1 = mul(x1, z[b]); x2 = add(x2, z[b + 1])
        x3 = add(x3, z[b + 2]); x4 = mul(x4, z[b + 3])
        t1 = x1 ^ x3; t2 = x2 ^ x4
        t1 = mul(t1, z[b + 4]); t2 = add(t2, t1)
        t2 = mul(t2, z[b + 5]); t1 = add(t1, t2)
        x1 ^= t2; x3 ^= t2; x2 ^= t1; x4 ^= t1
        if r < 7:              # 第 8 轮不交换（等价于参考实现的"撤销+换位"）
            x2, x3 = x3, x2
    y1 = mul(x1, z[49]); y2 = add(x2, z[50])
    y3 = add(x3, z[51]); y4 = mul(x4, z[52])
    return y1, y2, y3, y4


def idea_decrypt(block8, key16, little=False, sub=None):
    if sub is None:
        sub = dec_keys(expand(key16))
    fmt = '<HHHH' if little else '>HHHH'
    x = struct.unpack(fmt, block8)
    y = _rounds(*x, sub)
    return struct.pack(fmt, *y)


def idea_encrypt(block8, key16, little=False):
    return idea_decrypt(block8, key16, little, sub=expand(key16))


if __name__ == '__main__':
    # 权威向量 (bozhu/IDEA-Python): key/pt -> ct
    k = (0x2BD6459F82C5B300952C49104881FF48).to_bytes(16, 'big')
    pt = (0xF129A6601EF62A47).to_bytes(8, 'big')
    want = (0xEA024714AD5C4D84).to_bytes(8, 'big')
    c = idea_encrypt(pt, k)
    print("加密:", c.hex().upper(), " 期望", want.hex().upper(),
          "  ", "OK" if c == want else "失败")
    print("解密:", idea_decrypt(c, k).hex().upper(), " 期望", pt.hex().upper(),
          "  ", "OK" if idea_decrypt(c, k) == pt else "失败")
