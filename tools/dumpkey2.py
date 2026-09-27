# -*- coding: utf-8 -*-
"""枚举进程内存，搜索 ".BOX" 箱体结构，取出 +0x20 的 16 字节密钥并即时验证"""
import ctypes, struct, subprocess, time, os, sys
from ctypes import wintypes

sys.path.insert(0, r"e:\迅雷下载\Demonophobia\_unpack")
from idea import idea_decrypt

k32 = ctypes.windll.kernel32
EXE = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01

# 已知的密文测试块（段75 的前 8 字节）
dbox = open(EXE, 'rb').read()
import csv
rows = list(csv.DictReader(open(r"e:\迅雷下载\Demonophobia\extracted_files\_manifest.csv")))
TEST = []
for r in rows:
    if int(r['idx']) in (75, 76, 77, 80):
        t = int(r['box_offset'], 16)
        ds = t + 4 * int(r['blocks'])
        TEST.append(dbox[ds:ds + 8])


def ok(key):
    for b in TEST:
        for little in (False, True):
            o = idea_decrypt(b, key, little)
            if o[:2] == b'BM' or o[0] == 0x78:
                return True
    return False


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wintypes.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', wintypes.DWORD), ('Protect', wintypes.DWORD),
                ('Type', wintypes.DWORD)]


si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
si.wShowWindow = 0
p = subprocess.Popen([EXE], cwd=os.path.dirname(EXE), startupinfo=si)
print("pid=%d" % p.pid)
time.sleep(5)

h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | 0x0001, False, p.pid)
if not h:
    print("打开进程失败")
    sys.exit(1)


def read(addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return buf.raw[:got.value]
    return None


mbi = MBI()
addr = 0x10000
found = []
regions = 0
while addr < 0x7FFF0000:
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                              ctypes.sizeof(mbi)):
        break
    base = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS) and size:
        if size <= 0x2000000:
            data = read(base, size)
            regions += 1
            if data:
                i = 0
                while True:
                    i = data.find(b'.BOX', i)
                    if i < 0:
                        break
                    found.append(base + i)
                    i += 1
    addr = base + max(size, 0x1000)

print("扫描区域 %d 处, .BOX 命中 %d 处" % (regions, len(found)))
seen = set()
for a in found:
    st = a - 0x30 + 0x20      # 结构体 +0x20 = 名字 -0x10
    key = read(st, 16)
    if not key or key in seen:
        continue
    seen.add(key)
    nm = read(a - 0x30, 0x40)
    print("\n名字@0x%X  密钥@0x%X = %s" % (a - 0x30, st, key.hex().upper()))
    if nm:
        for i in range(0, 0x40, 16):
            r = nm[i:i + 16]
            print("   +%02X %s  %s" % (i, r.hex(),
                  ''.join(chr(c) if 32 <= c < 127 else '.' for c in r)))
    if ok(key):
        print("   >>> 密钥可用！")
        open(r"e:\迅雷下载\Demonophobia\_unpack\key.bin", 'wb').write(key)
        break
    else:
        print("   验证未通过")

try:
    p.kill()
except Exception:
    pass
