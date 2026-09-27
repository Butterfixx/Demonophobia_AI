import zlib, re

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
for off in (9779609, 9782947, 9779605):
    for cs in (3338, 7872, 4534):
        blk = d[off:off + cs]
        if len(blk) < 32:
            continue
        for b in range(256):
            x = bytes(c ^ b for c in blk)
            for w in (15, -15):
                try:
                    o = zlib.decompressobj(w)
                    r = o.decompress(x, 100000)
                    if o.eof and len(r) > 200:
                        pr = sum(1 for c in r if 32 <= c < 127) / len(r)
                        print("0x%X 大小%d XOR=0x%02X wbits%d -> %d 字节 可打印%.2f" %
                              (off, cs, b, w, len(r), pr))
                        print("   ", r[:120])
                except Exception:
                    pass
print("\n== 直接在整个箱里找 'bmp' 明文/单字节XOR ==")
names = [b'setA.bmp', b'room1A.bmp', b'.bmp']
tail = d[9779609:]
for nm in names:
    for b in range(256):
        pat = bytes(c ^ b for c in nm)
        p = tail.find(pat)
        if p >= 0:
            print("  命中 %r XOR=0x%02X @0x%X" % (nm, b, 9779609 + p))
            break
