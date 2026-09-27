import struct, re

mem = open(r"e:\迅雷下载\Demonophobia\_unpack\memory.bin", 'rb').read()
BASE = 0x400000
print("memory.bin 大小 = 0x%X" % len(mem))

pats = {
    'MAMA_myla_RAE': b'MAMA_myla_RAE',
    'CAFEBABE(LE)': b'\xbe\xba\xfe\xca',
    'BOXFILE': b'BOXFILE',
    '_splashscreen': b'_splashscreen',
    '.mbx': b'.mbx',
    'MoleBox': b'MoleBox',
}
for name, p in pats.items():
    hits = []
    i = 0
    while True:
        i = mem.find(p, i)
        if i < 0:
            break
        hits.append(BASE + i)
        i += 1
        if len(hits) > 20:
            break
    print("%-16s -> %s" % (name, ['0x%X' % h for h in hits[:20]]))

print("\n== 全映像中的可读字符串（含路径/扩展名/文件名）==")
seen = set()
for m in re.finditer(rb'[ -~]{7,}', mem):
    s = m.group().decode('latin1')
    if re.search(r'\.(bmp|wav|mid|avi|txt|dat|ini|dll|exe|ax|jpg|png|ogg)\b', s, re.I) or '\\\\' in s or 'Mole' in s or 'box' in s.lower():
        if s not in seen:
            seen.add(s)
            print("  0x%06X: %s" % (BASE + m.start(), s))
    if len(seen) > 80:
        break
