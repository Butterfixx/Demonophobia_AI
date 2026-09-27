# -*- coding: utf-8 -*-
import struct, zlib, json

d = open(r"e:\迅雷下载\Demonophobia\Demonophobia.exe", 'rb').read()
chain = json.load(open(r"e:\迅雷下载\Demonophobia\_unpack\align.json"))
print("段间填充字节（前 12 处）:")
for i in range(1, 12):
    prev_end = chain[i - 1][2]
    # 段数据结束 = 表起点 + 4*块数 + 各块压缩大小之和
    p = chain[i - 1][2]
    c = None
    nxt = chain[i][2]
    # 重新算 prev 段的数据结束
    def data_end(p):
        q = p
        tot = 0
        cnt = 0
        while q + 4 <= len(d):
            v = struct.unpack_from('<I', d, q)[0]
            if 0 < (v & 0x7FFFFFFF) <= 65600:
                tot += v & 0x7FFFFFFF
                cnt += 1
                q += 4
            else:
                break
        return p + 4 * cnt + tot, cnt
    de, cnt = data_end(prev_end)
    gap = d[de:nxt]
    print("  段%d 表@0x%X 块%d 数据止0x%X → 段%d 表@0x%X  填充%d字节: %s | %s" %
          (i - 1, prev_end, cnt, de, i, nxt, len(gap),
           ' '.join('%02X' % b for b in gap),
           ''.join(chr(b) if 32 <= b < 127 else '.' for b in gap)))
