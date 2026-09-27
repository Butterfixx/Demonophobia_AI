import zlib, struct

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
BOX = 0x29000
box = d[BOX:]
print("box 大小", len(box))
hdr_hash = box[0x10:0x20]
print("头部16字节:", hdr_hash.hex())

# 1) 试 XOR 16字节哈希
data0 = box[0x60:0x60 + 64]
x = bytes(b ^ hdr_hash[i % 16] for i, b in enumerate(data0))
print("XOR哈希后:", x.hex())
x2 = bytes(b ^ hdr_hash[i % 16] for i, b in enumerate(box[0x20:0x20 + 64]))
print("头部参数区 XOR 哈希:", x2.hex())

# 2) 在 box 前 0x10000 内按 4 字节对齐尝试 raw deflate / zlib
hits = []
for off in range(0x20, 0x10000, 4):
    chunk = box[off:off + 8192]
    for wbits in (-15, 15, 31):
        try:
            o = zlib.decompressobj(wbits)
            r = o.decompress(chunk, 4096)
            if len(r) >= 200:
                pr = sum(1 for c in r if 32 <= c < 127) / len(r)
                hits.append((off, wbits, len(r), pr, r[:48]))
        except Exception:
            pass
print("\n候选可解压偏移 (前 12):")
for h in hits[:12]:
    print("  off=0x%X wbits=%d -> %d 字节 可打印率%.2f  %r" % (h[0], h[1], h[2], h[3], h[4]))
if not hits:
    print("  未找到")

# 3) 统计 zlib 头 0x78 0x9C / 0x78 0xDA 出现次数
c1 = box.count(b'\x78\x9c')
c2 = box.count(b'\x78\xda')
print("\n0x789C 次数=%d  0x78DA 次数=%d  (9.6MB 随机数据期望约 %d 次)" % (c1, c2, len(box) // 65536))
