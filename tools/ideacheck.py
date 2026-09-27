# -*- coding: utf-8 -*-
"""穷举 IDEA 实现变体，找出与标准测试向量一致的那一种"""
import struct, itertools

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


def rotl128(k, n):
    v = int.from_bytes(k, 'big')
    v = ((v << n) | (v >> (128 - n))) & ((1 << 128) - 1)
    return v.to_bytes(16, 'big')


def expand(key16, kwe, rot):
    z = [0]
    k = bytes(key16)
    for g in range(6):
        for t in range(0, 16, 2):
            z.append((k[t] << 8 | k[t + 1]) if kwe == '>' else (k[t + 1] << 8 | k[t]))
        k = rotl128(k, rot)
    for t in range(0, 8, 2):
        z.append((k[t] << 8 | k[t + 1]) if kwe == '>' else (k[t + 1] << 8 | k[t]))
    return z


def crypt(block8, z, bwe, swap_last):
    x = list(struct.unpack(bwe + 'HHHH', block8))
    for r in range(8):
        b = 6 * r + 1
        x[0] = mul(x[0], z[b]); x[1] = add(x[1], z[b + 1])
        x[2] = add(x[2], z[b + 2]); x[3] = mul(x[3], z[b + 3])
        t1 = x[0] ^ x[2]; t2 = x[1] ^ x[3]
        t1 = mul(t1, z[b + 4]); t2 = add(t2, t1)
        t2 = mul(t2, z[b + 5]); t1 = add(t1, t2)
        x[0] ^= t2; x[2] ^= t2; x[1] ^= t1; x[3] ^= t1
        if r < 7 or swap_last:
            x[1], x[2] = x[2], x[1]
    y = [mul(x[0], z[49]), add(x[1], z[50]), add(x[2], z[51]), mul(x[3], z[52])]
    return struct.pack(bwe + 'HHHH', *y)


KEY = b''.join(struct.pack('>H', w) for w in range(1, 9))
PT = struct.pack('>HHHH', 0, 0, 0, 1)
# 期望值候选（两种记忆）
WANT = {'11FBED2B01986DE5', '1FBED3F68E4B8C1A', 'DAB36ACFD7BEE342'}

for kwe, bwe, swap_last, rot in itertools.product('><', '><', (False, True), (25,)):
    z = expand(KEY, kwe, rot)
    c = crypt(PT, z, bwe, swap_last).hex().upper()
    tag = ' <<< 命中' if c in WANT else ''
    print("key字序%s 块字序%s 末轮交换=%-5s 旋转%d -> %s%s" %
          (kwe, bwe, swap_last, rot, c, tag))
