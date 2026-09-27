import struct, zlib, os, re

PATH = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
OUT = r"e:\迅雷下载\Demonophobia\_unpack"
data = open(PATH, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3c)[0]
opt = pe + 24
optsize = struct.unpack_from('<H', data, pe + 20)[0]
nsec = struct.unpack_from('<H', data, pe + 6)[0]
imagebase = struct.unpack_from('<I', data, opt + 28)[0]
secs = []
for i in range(nsec):
    o = opt + optsize + 40 * i
    name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
    name = ''.join(c for c in name if 32 <= ord(c) < 127) or 's%d' % i
    vs, va, rs, ra = struct.unpack_from('<IIII', data, o + 8)
    secs.append(dict(name=name, va=va, vs=vs, rs=rs, ra=ra))

# 建立内存映像
SIZE = imagebase + 0x48000
mem = bytearray(SIZE)
for s in secs:
    n = min(s['rs'], s['vs'])
    mem[imagebase + s['va']:imagebase + s['va'] + n] = data[s['ra']:s['ra'] + n]


def lcg_xor(seed, start, end):
    """key0=seed, 先更新再 XOR, 逐 dword"""
    key = seed & 0xFFFFFFFF
    p = start
    while p + 4 <= end:
        key = (key * 0x19660D + 0x3C6EF375) & 0xFFFFFFFF
        k = struct.pack('<I', key)
        for j in range(4):
            mem[p + j] ^= k[j]
        p += 4


def lz_decode(src, expected):
    window = bytearray([0x20] * 0xFEE + [0] * (0x1000 - 0xFEE))
    pos = 0xFEE
    flag = 0
    i = 0
    out = bytearray()

    def gb():
        nonlocal i
        if i >= len(src):
            return -1
        b = src[i]
        i += 1
        return b

    while len(out) < expected:
        flag >>= 1
        if not (flag & 0x100):
            c = gb()
            if c < 0:
                break
            flag = c | 0xFF00
        if flag & 1:
            c = gb()
            if c < 0:
                break
            out.append(c)
            window[pos] = c
            pos = (pos + 1) & 0xFFF
        else:
            b0 = gb()
            b1 = gb()
            if b0 < 0 or b1 < 0:
                break
            off = b0 | ((b1 & 0xF0) << 4)
            n = (b1 & 0x0F) + 3
            for k in range(n):
                c = window[(off + k) & 0xFFF]
                out.append(c)
                window[pos] = c
                pos = (pos + 1) & 0xFFF
    return bytes(out), i


def unpack_block(block_va, label):
    d0, d1, d2 = struct.unpack_from('<III', mem, block_va)
    print("[%s] 块@0x%08X  解压后=0x%X(%d) 压缩=0x%X(%d) 校验=0x%08X" %
          (label, block_va, d0, d0, d1, d1, d2))
    src = bytes(mem[block_va + 12: block_va + 12 + d1])
    res, used = lz_decode(src, d0)
    print("    -> 解压 %d 字节 (期望 %d)  用掉输入 %d/%d  crc32=0x%08X adler=0x%08X" %
          (len(res), d0, used, len(src), zlib.crc32(res) & 0xFFFFFFFF, zlib.adler32(res) & 0xFFFFFFFF))
    if len(res) == d0:
        mem[block_va:block_va + len(res)] = res
    return res


# ---- 阶段1: 解密第7节并解压 boot code ----
s7 = secs[6]
lcg_xor(imagebase + s7['va'], imagebase + s7['va'], imagebase + s7['va'] + s7['vs'])
boot = unpack_block(imagebase + s7['va'], "阶段1 boot")
open(os.path.join(OUT, "boot.bin"), 'wb').write(boot)

# ---- 阶段2: 解密 4ext 尾段并解压 ----
BLK2 = 0x42EB92
s5 = secs[4]                      # 4ext
sec_end = imagebase + s5['va'] + s5['vs']
start2 = (BLK2 + 0xC) & ~3
lcg_xor(BLK2, start2, sec_end)
code2 = unpack_block(BLK2, "阶段2 主体")
open(os.path.join(OUT, "stage2.bin"), 'wb').write(code2)

open(os.path.join(OUT, "memory.bin"), 'wb').write(bytes(mem[imagebase:imagebase + 0x48000]))
print("\n内存映像已保存 memory.bin")
