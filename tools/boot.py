import struct, zlib, re, os

OUT = r"e:\迅雷下载\Demonophobia\_unpack"
sec = open(os.path.join(OUT, "sec", "7_6ata.bin"), 'rb').read()

d0, d1, d2 = struct.unpack_from('<III', sec, 0)
print("字段0(解压后大小) = 0x%X (%d)" % (d0, d0))
print("字段1(压缩数据大小) = 0x%X (%d)" % (d1, d1))
print("字段2(校验) = 0x%08X" % d2)

blob = sec[12:12 + d1]
print("压缩数据前 8 字节:", blob[:8].hex())

for name, fn in (("raw", None), ("zlib", "z"), ("gzip", "g"), ("deflate", "-")):
    try:
        if fn is None:
            out = zlib.decompress(blob)
        elif fn == "z":
            out = zlib.decompress(blob)
        elif fn == "g":
            out = zlib.decompress(blob, 16 + zlib.MAX_WBITS)
        else:
            out = zlib.decompress(blob, -zlib.MAX_WBITS)
        print("[%s] 解压成功 -> %d 字节 (期望 %d) %s" % (name, len(out), d0, "OK" if len(out) == d0 else "!大小不符"))
        open(os.path.join(OUT, "boot_%s.bin" % name), 'wb').write(out)
        print("   crc32   = 0x%08X %s" % (zlib.crc32(out) & 0xFFFFFFFF, "匹配" if (zlib.crc32(out) & 0xFFFFFFFF) == d2 else ""))
        print("   adler32 = 0x%08X %s" % (zlib.adler32(out) & 0xFFFFFFFF, "匹配" if (zlib.adler32(out) & 0xFFFFFFFF) == d2 else ""))
    except Exception as e:
        print("[%s] 失败: %s" % (name, e))
