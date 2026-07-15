# Proxmark3 刷机问题总结 (2026-07-14)

## 设备信息
- **型号**: PM3 GENERIC (非 RDV4)
- **芯片**: AT91SAM7S512 Rev B
- **闪存**: 512KB (74% 已使用)
- **固件**: Iceman/master/v4.21611-556-gd0e8cf186 (PM3GENERIC, 全功能)

---

## 遇到的问题及其解决方案

### 1. 设备完全不被 macOS 识别（充电线问题）

**现象**: 插入 USB 后蓝灯+绿灯常亮（有供电），但 `system_profiler SPUSBDataType` 完全看不到设备，`/dev/` 下无任何串口设备。

**原因**: 使用的 Micro-USB 线是"仅充电"线，内部只有电源线芯 (VCC/GND)，没有数据线芯 (D+/D-)。

**解决**: 更换为确认可传输数据的 Micro-USB 线。

---

### 2. 按按钮插入后设备消失，且无法恢复

**现象**: 被其他助手建议"按住按钮插入 USB"后，设备从 USB 设备列表中消失，之后正常插入也无法识别。LED 状态变为 CHR 红闪烁 + STD 绿常亮 + 侧面蓝常亮。

**原因**: 
- 按住按钮插入 USB 触发了 AT91SAM7S 的 ROM bootloader (SAM-BA) 模式
- 旧版 bootloader 在 macOS 上可能枚举异常，或设备进入了固件损坏后的恢复状态
- 红色 CHR 闪烁 = 设备无有效固件，处于等待刷写状态

**解决**: 需要刷写固件才能恢复正常。

---

### 3. system_profiler 看不到设备，但 pm3 脚本能找到

**现象**: `system_profiler SPUSBDataType` 不显示 Proxmark3，但 `./pm3 --list` 能找到 `/dev/tty.usbmodem88881`。

**原因**: macOS 的 USB 设备枚举和 CDC 串口设备注册是两个不同层面，某些状态下设备可能不在 USB 设备树中完整注册但串口驱动仍能识别。

**教训**: 始终使用 `./pm3 --list` 或直接检查 `/dev/tty.*` 来检测设备，不要只依赖 `system_profiler`。

---

### 4. 旧 bootloader 不兼容新命令 / 报告错误闪存大小

**现象**: 刷写时提示：
- `Your bootloader does not understand the new CMD_BL_VERSION command`
- `Your bootloader does not understand the new CHIP_INFO command`
- `Available memory on this board: UNKNOWN`
- `Permitted flash range: 0x00100000-0x00140000` (仅 256KB)

**原因**: 设备上的旧版 bootloader 太老，不支持新版刷写工具的命令协议，且错误地将 512KB 闪存报告为 256KB。

**解决**: 需要先单独刷写新 bootrom (`./pm3-flash-bootrom`)，再刷 fullimage。新 bootloader 正确报告了 512KB 闪存。

---

### 5. 固件过大不兼容

**现象**: 使用 RDV4 平台编译的 fullimage 约 423KB，旧 bootloader 报告闪存范围仅 256KB，刷写失败：
```
ERROR: Firmware image too large for your platform!
PHDR is not contained in Flash
```

**原因**: 旧 bootloader 错误报告闪存大小。实际硬件有 512KB 但 bootloader 说只有 256KB。

**解决**: 更新 bootrom 后，新 bootloader 正确报告 512KB，问题消失。此设备实际为 PM3GENERIC 512KB 版本。

---

### 6. 软件重启进入 bootloader 失败

**现象**: `./pm3-flash-fullimage` 尝试通过软件命令重启设备进入 bootloader 模式，设备消失后不再回来：
```
[+] Entering bootloader...
[+] Trigger restart...
[+] Waiting for Proxmark3 to appear... [countdown to 0, then fails]
```

**原因**: 软件重启命令在某些 bootloader 版本或设备状态下不可靠。

**解决**: 物理操作 — 拔掉 USB，按住按钮不放，插入 USB，等 LED 显示 A + C 红灯常亮（bootloader 模式标志），然后执行刷写命令。

---

### 7. RDV4 固件刷入 PM3GENERIC 设备导致无法启动

**现象**: 将 PM3RDV4 平台固件刷入 PM3GENERIC 设备后，设备完成刷写重启，但 USB 完全不枚举，`/dev/` 下无任何串口设备。

**原因**: RDV4 固件包含 RDV4 特定的硬件初始化代码 (`-DRDV4`, `-DWITH_SMARTCARD`, `-DWITH_FLASH`)，在非 RDV4 硬件（如 PM3 Easy / 通用克隆版）上不兼容，固件可能在启动时崩溃。

**解决**: 重新编译为 PM3GENERIC 平台，编译配置：
```makefile
PLATFORM=PM3GENERIC
PLATFORM_SIZE=512
```
去掉所有 `SKIP_*=1`，保留全部功能。fullimage 约 370KB，在 512KB 设备上占 74%。

---

### 8. 端口名称变化

**现象**: 设备在不同状态下使用不同的串口名称：
- Normal bootloader 模式: `/dev/tty.usbmodem88881`
- Manual bootloader 模式 (按按钮): `/dev/tty.usbmodemiceman1`
- 正常固件运行: `/dev/tty.usbmodemiceman1`

**原因**: macOS 根据 USB 描述符和设备状态分配不同的端口名称。

**注意**: 刷写脚本会记住首次检测到的端口名，如果设备重启后换端口会失败，需要重新运行脚本或手动进入 bootloader 模式。

---

### 9. 首次 hf 命令偶发协议错误

**现象**: 刷写完固件后第一次执行 `hf search` 报错：
```
Received packet OLD frame with payload too short? 37/534
ERROR: cannot communicate with the Proxmark3
```

**原因**: 设备刚启动，内部初始化可能尚未完全完成，或 USB CDC 缓冲区有残留数据。

**解决**: 重试即可。第二次执行正常工作。

---

## 最佳实践总结

1. **检测设备**: 始终用 `./pm3 --list` 或 `ls /dev/tty.usb*`，不要依赖 `system_profiler`
2. **USB 线**: 务必使用确认能传输数据的 Micro-USB 线
3. **识别硬件**: 不要假设设备是 RDV4，先用 `hw version` 确认平台类型
4. **bootloader LED 标志**: A + C 红灯常亮 = 手动 bootloader 模式
5. **刷写顺序**: 旧 bootloader 需先 `./pm3-flash-bootrom` 再 `./pm3-flash-fullimage`
6. **软件重启不可靠时**: 使用物理按钮进入 bootloader 模式
7. **编译前确认平台**: 确认 `Makefile.platform` 使用正确的 PLATFORM 和 PLATFORM_SIZE

## 刷写命令速查

```bash
# 编译 (完整功能, 512KB)
# Makefile.platform:  PLATFORM=PM3GENERIC  /  PLATFORM_SIZE=512
make -j$(sysctl -n hw.ncpu)

# 手动 bootloader 模式:
#   1. 拔掉 USB
#   2. 按住按钮不放
#   3. 插入 USB
#   4. LED A+C 红灯常亮即为 bootloader 模式

# 刷写 bootrom
./pm3-flash-bootrom

# 刷写 fullimage
./pm3-flash-fullimage

# 连接客户端
./pm3

# 进入客户端后可用命令:
#   hw version      - 查看固件版本
#   hw status       - 查看设备状态
#   hf search       - 搜索 HF 标签
#   hf 14a reader   - 读取 ISO14443-A 卡片
#   hf mf           - Mifare 经典卡操作
#   lf search       - 搜索 LF 标签
```
