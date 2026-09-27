import re, collections, os

b = open(r"e:\迅雷下载\Demonophobia\_unpack\out2\s_00047DE7.bin", 'rb').read()
for enc in ('shift_jis', 'gbk', 'latin1'):
    try:
        txt = b.decode(enc)
        break
    except Exception:
        continue
open(r"e:\迅雷下载\Demonophobia\_unpack\Demonophobia_script.txt", 'w', encoding='utf-8').write(txt)
print("脚本 %d 字符, 编码 %s" % (len(txt), enc))

names = collections.Counter(re.findall(r'"([^"]+\.[A-Za-z0-9]{2,4})"', txt))
print("引用文件名(去重): %d" % len(names))
ext = collections.Counter(n.rsplit('.', 1)[-1].lower() for n in names)
print("扩展名分布:", dict(ext))
print("\n出现最多的 40 个:")
for n, c in names.most_common(40):
    print("   %-30s x%d" % (n, c))
print("\n== 脚本前 1200 字符 ==")
print(txt[:1200])
