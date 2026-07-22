# Smart Card Door Lock System

基于 MIFARE Classic 1K + ACR122U 的 Crypto-1 加密门锁系统，跨平台 (macOS / Linux / Windows)。

## 硬件需求

| 设备 | 说明 |
|------|------|
| ACR122U (或兼容) NFC 读卡器 | USB CCID, 13.56 MHz |
| MIFARE Classic 1K 卡片 | S50 空白卡 / 校园卡 / 门禁卡均可 |
| 主机 | macOS (自带 PCSC) / Linux (`apt install libpcsclite-dev`) / Windows (MinGW) |

## 编译

```bash
cd lock
make
```

生成两个可执行文件：`lock`（门锁守护进程）、`lock_admin`（制卡工具）。

## 架构

```
刷卡检测 → 读 UID(明文) → Load Key A → Three-Pass Auth (Crypto-1)
    │
    ├─ 加密读 Block 4 → 验证 magic "LOCK"
    ├─ 加密读 Block 5 → 比对 credKey（白名单）
    ├─ 加密读 Block 6 → 检查过期日期
    │
    ├─ 全部通过 → 绿灯 + 蜂鸣 (ACCESS GRANTED)
    └─ 任一失败 → 红灯三闪 (ACCESS DENIED)
```

## 凭证存储位置

卡上 **Sector 1**（Block 4–7）：

```
Block 4: "LOCK" | 卡序列号(4B) | 权限等级(2B) | 预留(6B)
Block 5: 凭证密钥(8B 随机数) | 预留(8B)
Block 6: 签发日期(4B) | 过期日期(4B) | 预留(8B)
Block 7: Key A(6B) | Access Bits(4B) | Key B(6B)
```

---

## 快速开始

### 1. 制卡（将一张空白卡编程为钥匙）

```bash
# 基础制卡：access level=1, 永不过期, 默认 Key A
./lock_admin

# 指定参数
./lock_admin --level 3 --expiry 20261231

# 如果卡的 Sector 1 使用的是自定义 Key A（非全 F），必须指定
./lock_admin --keya A1B2C3D4E5F6 --level 3
```

放上卡片 → 按回车 → 程序写入凭证并打印 credKey：

```
[+] Wrote credential header  (block 4)
[+] Wrote credential key      (block 5)
[+] Wrote metadata             (block 6)
[+] Card programmed successfully.
```

**记下输出的 `cred key` 前 8 字节，这就是这把钥匙的 ID。**

### 2. 创建白名单

复制上一步输出的 credKey（如 `A1 B2 C3 D4 E5 F6 A7 B8`），去掉空格写入 `keys.txt`：

```txt
# 门锁授权密钥
A1B2C3D4E5F6A7B8
```

### 3. 运行门锁

```bash
./lock --keyfile keys.txt
```

刷刚才制的卡 → `ACCESS GRANTED`。

---

## 日常钥匙管理

### 添加新钥匙

```bash
./lock_admin --level 2 --expiry 20270630
# 记下输出的 credKey，追加到 keys.txt:
echo "新钥匙的16进制credKey" >> keys.txt
```

### 撤销一把钥匙

从 `keys.txt` 中删除对应行，重启 `lock` 即可。该卡的物理卡还在，但刷门锁会被 `AUTH_FAIL_NOT_IN_LIST` 拒绝。

### 钥匙过期

制卡时指定 `--expiry`，到期后自动拒绝。无需修改白名单。

### 钥匙分级

`--level` 参数 0–255 写入卡内 Block 4，日志中可见 `Access level: N`。可用于区分管理员/访客等，当前版本仅记录不做分级控制，预留扩展。

### 换 Key A（安全加固）

默认 Key A = `FF FF FF FF FF FF` 是全行业公开的。如果环境有安全需求：

```bash
# 1) 制卡时指定新 Key A 并格式化尾扇区
./lock_admin --keya A1B2C3D4E5F6 --level 3 --format-trailer

# 2) 门锁用相同 Key A 读取
./lock --keya A1B2C3D4E5F6 --keyfile keys.txt
```

**警告**：`--format-trailer` 会改写 Sector 1 的尾扇区！如果已经用默认 Key A 制过卡，先用默认 Key A 把卡读取出来备份数据，再重新用新 Key A 写入。否则旧 Key A 的卡将无法被再次写入。

---

## 关于"只读 UID 卡"

通常说的"只读卡"指 Block 0（厂商区/UUID）不可写，这是**所有标准 MIFARE Classic 的正常属性**——不需要中国魔术卡。

Sector 1 的数据块（Block 4–6）对标准卡完全可读写，只需知道 Key A。空卡出厂时 Key A 默认全 F。所以你的校园卡/普通 S50 白卡都可以直接当门锁钥匙用：

```bash
# 如果 Key A 还是默认值
./lock_admin
# 放卡 → 回车 → 完成
```

唯一的问题是：如果卡已被其他系统写过，**Sector 1 的 Key A 可能已被修改**。此时你需要知道那个 Key A，用 `--keya` 传入：

```bash
./lock_admin --keya <当前有效KeyA> --level 3
```

---

## 命令行参考

### `lock_admin`（制卡）

```
Usage: lock_admin [--level N] [--expiry YYYYMMDD] [--keya HEX] [--format-trailer]

  --level N          权限级别 0-255 (默认 1)
  --expiry YYYYMMDD  过期日期 (默认 29991231 = 永不过期)
  --keya HEX         6 字节 Key A, 12 个 hex 字符 (默认: FFFFFFFFFFFF)
  --format-trailer   写入尾扇区 (包括 Key A + access bits)
```

### `lock`（门锁）

```
Usage: lock [--keyfile PATH] [--keya HEX]

  --keyfile PATH  白名单文件路径 (每行一个 16 进制 credKey)
  --keya HEX      6 字节 Key A, 12 个 hex 字符 (默认: FFFFFFFFFFFF)
```

---

## 平台相关

### macOS

系统自带 PCSC.framework，无需额外安装依赖。确保 ACR122U 插入后系统识别为 CCID 设备。

```bash
# 验证读卡器可见
pcsctest   # 或者用 pcsc_scan
```

### Linux

```bash
sudo apt install libpcsclite-dev pcscd
sudo systemctl start pcscd
make
```

### Windows

需要 MinGW-w64 或 MSVC + Windows SDK (WinSCard.dll 系统自带)。

---

## 文件结构

```
lock/
├── include/
│   ├── pcsc_common.h      # 跨平台 PCSC 抽象 + MIFARE 常量
│   ├── crypto_engine.h    # Crypto-1 加密会话 API
│   ├── hardware_ctrl.h    # LED/蜂鸣器控制
│   └── readin.h           # PCSC 读卡器封装
├── src/
│   ├── main.c             # 门锁守护进程入口
│   ├── admin.c            # 制卡工具入口
│   ├── crypto_engine.c    # MIFARE Classic 全部操作实现
│   ├── hardware_ctrl.c    # ACR122U APDU LED 控制
│   └── readin.c           # PCSC 读卡器实现
├── keys.txt               # 白名单示例
└── Makefile
```
