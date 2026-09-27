# -*- coding: utf-8 -*-
"""启动游戏进程（隐藏窗口），读取 IDEA 密钥指针链 [0x442718]->+0x2C->+0x20 (16字节)"""
import ctypes, struct, subprocess, time, os
from ctypes import wintypes

k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
EXE = r"e:\迅雷下载\Demonophobia\Demonophobia.exe"
RVA_GLOB = 0x42718          # 0x442718 - 0x400000

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_TERMINATE = 0x0001

si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
si.wShowWindow = 0
p = subprocess.Popen([EXE], cwd=os.path.dirname(EXE), startupinfo=si)
print("已启动 pid=%d" % p.pid)


def read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return buf.raw[:got.value]
    return None


def dword(h, addr):
    b = read(h, addr, 4)
    return struct.unpack('<I', b)[0] if b else None


result = None
for attempt in range(60):
    time.sleep(0.5)
    if p.poll() is not None:
        print("进程已退出 (code=%s)" % p.poll())
        break
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
                        PROCESS_TERMINATE, False, p.pid)
    if not h:
        continue
    try:
        mods = (wintypes.HMODULE * 1024)()
        need = wintypes.DWORD(0)
        psapi.EnumProcessModules(h, ctypes.byref(mods), ctypes.sizeof(mods),
                                 ctypes.byref(need))
        base = mods[0]
        g = dword(h, base + RVA_GLOB)
        if not g:
            continue
        p2 = dword(h, g + 0x2C)
        if not p2:
            continue
        key = read(h, p2 + 0x20, 16)
        if key and any(key):
            print("\n基址    0x%08X" % base)
            print("[0x442718] = 0x%08X" % g)
            print("+0x2C     = 0x%08X" % p2)
            print("结构体前 64 字节:")
            blob = read(h, p2, 64) or b''
            for i in range(0, 64, 16):
                row = blob[i:i + 16]
                print("   +%02X %s  %s" % (i, row.hex(),
                      ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)))
            print("\n>>> IDEA 密钥 = %s" % key.hex().upper())
            result = key
            break
    finally:
        k32.CloseHandle(h)

if result:
    open(r"e:\迅雷下载\Demonophobia\_unpack\key.bin", 'wb').write(result)
    print("已保存 key.bin")
try:
    p.kill()
except Exception:
    pass
print("进程已结束" if result is None else "完成")
