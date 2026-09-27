import struct, zlib, re, os

OUT = r"e:\迅雷下载\Demonophobia\_unpack"
sec = open(os.path.join(OUT, "sec", "7_6ata.bin"), 'rb').read()
d0, d1, d2 = struct.unpack_from('<III', sec, 0)
src = sec[12:12 + d1]


def decode(src, expected, delta):
    window = bytearray([0x20] * 0xFEE + [0] * (W - 0xFEE)) if False else bytearray([0x20] * 0xFEE + [0] * (0x1000 - 0xFEE))
    pos = 0xFEE
    flag = 0
    i = 0
    out = bytearray()

    def getbyte():
        nonlocal i
        if i >= len(src):
            return -1
        b = src[i]
        i += 1
        return b

    while True:
        flag >>= 1
        if not (flag & 0x100):
            c = getbyte()
            if c < 0:
                break
            flag = c | 0xFF00
        if flag & 1:
            c = getbyte()
            if c < 0:
                break
            out.append(c)
            window[pos] = c
            pos = (pos + 1) & 0xFFF
        else:
            b0 = getbyte()
            b1 = getbyte()
            if b0 < 0 or b1 < 0:
                break
            off = b0 | ((b1 & 0xF0) << 4)
            n = (b1 & 0x0F) + delta
            for k in range(n):
                c = window[(off + k) & 0xFFF]
                out.append(c)
                window[pos] = c
                pos = (pos + 1) & 0xFFF
        if len(out) >= expected:
            break
    return bytes(out), i


for delta in (2, 3, 1, 4):
    res, used = decode(src, d0, delta)
    ok = len(res) == d0
    print("delta=+%-2d  输出 %6d (期望 %d) %s  用掉输入 %d/%d  crc32=0x%08X adler=0x%08X" %
          (delta, len(res), d0, "OK" if ok else "", used, len(src),
           zlib.crc32(res) & 0xFFFFFFFF, zlib.adler32(res) & 0xFFFFFFFF))
    if ok:
        open(os.path.join(OUT, "boot.bin"), 'wb').write(res)
        for m in re.finditer(rb'[ -~]{10,}', res):
            print("   %04X: %s" % (m.start(), m.group().decode('latin1')))
        break
