<<<<<<< HEAD
# Demonophobia（デモノフォビア / 3DM 汉化版）完整解包工程

从加壳程序 `Demonophobia.exe` 中 **100% 还原** 的游戏源码与资源。

- 外壳：**MoleBox 2.6（evaluation copy）**
- 引擎：**HSP3（Hot Soup Processor 3）**
- 原始打包目录（箱内记录）：`C:\Program Files\hsp31\bmpfile\`
- 还原结果：**283 / 283 个文件，全部校验通过**（279 张 BMP + 主源码 + 编译脚本 + 图标 + 打包清单）
- 文件名：来自箱内 **IDEA 加密的文件名索引表**，顺序即打包顺序，**100% 准确**

---

## 目录结构

```
Demonophobia_source/
├─ demono.hsp            ← 游戏主源码（749,566 字节，HSP 源码文本，含全部汉化文案）
├─ start.ax              ← HSP3 编译产物（653,251 字节）
├─ packfile_list.txt     ← 打包清单
├─ icon7.ico             ← 图标
├─ abura.bmp …           ← 279 张 BMP 图像资源（真实文件名）
├─ _meta/
│   ├─ _mapping.csv      ← 箱内序号 ↔ 文件名 ↔ 大小 ↔ 类型
│   ├─ _idea_key.txt     ← IDEA 主密钥及取法
│   └─ key.bin           ← 16 字节 IDEA 密钥
├─ tools/                ← 全部逆向/解包 Python 脚本
└─ README.md
```

关键索引（已从文件名表确认）：`#8 demono.hsp`、`#34 icon7.ico`、`#73 packfile_list.txt`、`#266 start.ax`。

---

## 使用方法 / 重新编译

1. 安装 **HSP3**（作者原环境 `hsp31`）。
2. 本目录即作者原始目录内容，脚本用相对路径 `picload "setA.bmp"`，保持同目录即可。
3. HSP3 打开 `demono.hsp` 编译 → 生成 `start.ax`；改文本/改图后重新编译即可。

```hsp
	title "Demonophobia"
	screen 0,800,600,0
	width ,,100,50
	pos 0,0 : color 0,0 : mes "now loading"
	redraw 0
	buffer 2 : picload "setA.bmp" ;(185,256)
```

---

## 逆向全过程（完整技术记录）

| 层 | 位置 | 算法 | 密钥 / 参数 |
|---|---|---|---|
| ① PE 节加密 | 7 个节 | LCG 流密钥 XOR，逐 4 字节 | `k = k*0x19660D + 0x3C6EF375` |
| ② 块压缩 | boot code + 引擎 | 12 字节块头 + **LZSS** | 4KB 窗口、填充 `0x20`、初始 pos `0xFEE`；`off = b0 \| ((b1&0xF0)<<4)`，`len = (b1&0xF)+3` |
| ③ 自解密代码 | `0x431C44` 等 11 处 | SMC：运行时解密、用完再加密回去 | 逐字节 XOR，`k = p*0x19660D + 0x3C6EF35F`（`p` = 地址）；区域由 `push A; call 0x42EB7E` 给出，`[ret-(A&0xFFFF), ret+(A>>16))` |
| ④ 箱格式 | overlay `0x29000`，9,619,601 字节 | 32 字节箱头 + 每文件切成 ≤64KB 的块；块表为 n 个 dword | `size = v & 0x7FFFFFFF`；最高位 = 该块未压缩 |
| ⑤ 块解密（主流） | 块数据 | **逐字节 XOR 0xA3** → zlib `inflate` | XOR 常量藏在 SMC 代码里（`byte [0x441C00]`） |
| ⑥ 块解密（支流） | 部分数据 | **IDEA**（ECB、in-place、52 子密钥、模 `0x10001`） | 运行时 `[0x442718] → +0x2C → +0x20` |

### 关键代码位置

| 地址 | 作用 |
|---|---|
| `0x431AFE` | 块读取（8 字节对齐 → 分组密码） |
| `0x431C2C` | 分支：`flags&1` → `flags&0x30==0x10` 走 XOR，否则走 IDEA |
| `0x431CC9` | IDEA 路径：`[0x442718] → +0x2C → +0x20` 取 16 字节密钥 |
| `0x4332B6` | IDEA 初始化：密钥展开 + 求逆子密钥 |
| `0x4332E1` | IDEA 密钥展开（52 子密钥，每组 8 个后循环左移 25 位） |
| `0x433389` | 求 IDEA 解密子密钥（写入 `ctx+0x68`，104 字节） |
| `0x43368A` | IDEA 模 `0x10001` 乘逆 |
| `0x433DF0` | IDEA ECB 解密循环（`ctx+0x68` 为子密钥，原地加解密） |
| `0x42EB7E` | SMC 自解密/再加密函数 |

### 箱头结构（文件偏移 `0x29000`）

```
+0x00  4  箱大小 0x0092C891 = 9,619,601
+0x04  12 ASCII "MAMA_myla_RA"
+0x10  16 未知/校验
+0x20      第 0 段的块表开始
```

箱尾（`-48` 字节）为索引区：`0x1EC0`(7872)、`0x953999`(文件名表绝对偏移)、`0xD0A`(3338)、`0x11B`(283)、`0x955891`(箱尾)，末 4 字节 `CAFEBABE`。

### IDEA 密钥怎么拿到的

密钥**不在文件里**，由运行时生成，静态不可得。取法（无需调试器、不触发 anti-debug）：

```
tools/dumpkey.py  — 启动进程（隐藏窗口），读指针链
    [0x442718] → +0x2C → +0x20 = 16 字节密钥
    （结构体 +0x30 处为箱名 "Demonophobia.BOX"）
tools/dumpkey2.py — 枚举进程内存搜 ".BOX" 定位结构体并验证
```

本机取到的密钥：`01 08 82 CC 17 6F 18 5C 25 4C FE 20 7A BB 78 75`

用它可以解开箱尾 `0x953999` 处 3338 字节的**文件名索引表**（IDEA-ECB，解出即明文，无需解压），
从而得到 283 个真实文件名与打包顺序 —— 这也是本次能把文件名做到 100% 准确的原因。

### 坑：IDEA 实现校验

自己写的 IDEA 必须与权威向量对齐（否则密钥对了也解不开）：

```
key   = 2BD6459F82C5B300952C49104881FF48
plain = F129A6601EF62A47
cipher= EA024714AD5C4D84      ← tools/idea.py 已通过
```

要点：**8 轮中第 8 轮不交换中间两字**（等价于参考实现 bozhu/IDEA-Python 的"撤销 + 换位"）；
子密钥为 52 个 16 位字，每 8 个后 128 位密钥循环左移 25 位。

---

## tools/ 脚本

| 脚本 | 作用 |
|---|---|
| `smc.py` / `smc_all.py` | 解密 SMC 自修改代码（11 处区域） |
| `find_key.py` | 提取块 XOR 常量 0xA3 |
| `dumpkey.py` / `dumpkey2.py` | 从运行进程取出 IDEA 密钥 |
| `idea.py` | IDEA 实现（含权威测试向量自检） |
| `nametable.py` | 解密文件名索引表 |
| `extract_all.py` | **统一提取器**：顺序走箱，自动识别 XOR/IDEA/裸/原样，输出 283 段 |
| `build_final.py` | 用真实文件名生成本工程目录 |
| `walk.py` / `align2.py` / `anchors.py` | 段顺序与对齐分析（早期探索用） |
| `dumpfn.py` / `dis2.py` | 反汇编辅助 |

## 校验结果

- BMP 文件头自校验（`bfSize` 与实测长度一致）：**279 / 279 通过，0 损坏**
- 段数与文件名表条目数：**283 = 283 完全一致**
=======
# Demonophobia_AI-
这是用AI反编译得来的源代码，编程工具用的是HSP
>>>>>>> 0d45ec883f94ebeddf9ede8240bde2e1c86cba07
