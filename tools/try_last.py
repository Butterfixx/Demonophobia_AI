import zlib, struct

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
SEC = 9779609
print("段前 16 字节(含可能的块表):", d[SEC - 16:SEC].hex())
for i in range(4):
    print("  块表候选 -%d: 0x%08X" % (16 - 4 * i, struct.unpack_from('<I', d, SEC - 16 + 4 * i)[0]))

data = d[SEC:SEC + 7872]
print("\n段起始 32 字节:", data[:32].hex())

for name, wbits in (("raw deflate", -15), ("zlib", 15), ("gzip", 31), ("auto", 47)):
    try:
        o = zlib.decompressobj(wbits)
        r = o.decompress(data)
        pr = sum(1 for c in r if 32 <= c < 127) / max(1, len(r))
        print("\n[%s] 成功! 输出 %d 字节, 可打印率 %.2f" % (name, len(r), pr))
        print(r[:400])
    except Exception as e:
        print("\n[%s] 失败: %s" % (name, e))
