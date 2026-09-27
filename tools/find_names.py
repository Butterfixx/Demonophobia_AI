import glob, re, os, collections

hits = collections.Counter()
files = []
for f in glob.glob(r"e:\迅雷下载\Demonophobia\_unpack\out2\s_*.bin"):
    b = open(f, 'rb').read()
    n = re.findall(rb'[ -~]{4,}\.(?:bmp|wav|mid|dat|txt)', b)
    if n:
        files.append((os.path.basename(f), len(b), len(n), [x.decode('latin1') for x in n[:8]]))
print("== 提取段中含文件名的段 ==")
for f, l, c, s in files[:20]:
    print("  %-20s %8d 字节  命中%d  %s" % (f, l, c, s))
if not files:
    print("  （无：文件名表不在已提取的段中）")

# 箱尾 7872 区域各种可能性
d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
print("\n== 箱尾区域单字节 XOR 扫描（找 ASCII 名字）==")
for off, sz in ((9779609, 7872), (9779609, 3338)):
    blk = d[off:off + sz]
    best = max(range(256), key=lambda b: sum(1 for c in blk if 32 <= (c ^ b) < 127))
    pr = sum(1 for c in blk if 32 <= (c ^ best) < 127) / sz
    print("  0x%X 最佳XOR=0x%02X 可打印%.2f  %r" % (off, best, pr, bytes(c ^ best for c in blk[:60])))
