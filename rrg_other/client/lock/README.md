# ACR122T MIFARE Classic 1K 门锁模拟器

这是一个面向 Windows 的只读控制台程序。ACR122T 作为门锁读卡器，实体
MIFARE Classic 1K 卡作为门卡。程序按配置加载每个扇区的 Key A/Key B，执行
原生 Crypto1 三次认证，读取用户选定的数据块，与一个或多个预期值精确比较，并
给出“允许开门”或“拒绝开门”的结果。

程序不会向卡片写入任何数据。

## 认证与判定规则

- `auth: "A"`：只验证 Key A。
- `auth: "B"`：只验证 Key B。
- `auth: "both"`：Key A 和 Key B 必须分别认证成功。
- `key_a`/`key_b` 可用 `/` 分隔多个候选密钥，程序按从左到右的顺序尝试。
- `block0`、`block1`、`block2` 控制是否读取对应数据块；扇区尾块不读取。
- 每个启用块的 `blockN_data` 可用 `/` 分隔多个 16 字节预期值。实际数据与任意
  一个候选值完整、逐字节相同才算通过。
- `required: true`：密钥认证、块读取或数据匹配任一失败都会拒绝开门。
- `required: false`：仍执行全部检验并记录结果，但失败不影响开门判定。
- 未写入配置文件的扇区不会被访问。
- 待机时关闭 13.56 MHz 射频场。按空格键才开启一次读卡，处理结束立即关闭射频并
  重新取得 Direct handle；按 Q 或 Esc 退出。

程序对命中的密钥在每个扇区只执行一次必要认证，然后连续读取该扇区的选定块；
只有当前密钥无法读取某些块时，才切换另一把已验证密钥并重新认证一次。同一次刷卡
中，相邻扇区使用相同 Key A/Key B 时还会复用读卡器密钥槽位，不重复发送加载密钥
命令。ACR122T 在读卡器和卡片内部完成认证；PC/SC 只返回成功或失败状态，程序无法
输出
`Nt/Nr/Ar/At` 原始认证报文。如果需要原始挑战报文，应同时使用 Proxmark3 被动
嗅探。

待机时程序通过 Windows PC/SC Escape Command 同时完成两项设置：

1. 读取并保存当前 PICC Operating Parameter，把 bit 7 清零以关闭 Auto PICC
   Polling。
2. 向 PN532 发送 RFConfiguration OFF。

程序使用底层 WinSCard 的 `SCARD_SHARE_DIRECT` 和
`SCARD_PROTOCOL_UNDEFINED`，因此场内没有卡时也能连接读卡器。按空格时只恢复保存的
PICC Operating Parameter；自动轮询会自行开启射频，不能再重复发送 RF ON，否则
ACR122T 可能返回 `6300`。ACS 驱动必须允许 Escape Command，否则程序会明确报错。

关闭射频后，程序会在整个待机阶段持续持有 Direct handle。这是为了阻止 Windows
智能卡服务或驱动在 1–2 秒后重新接管读卡器并恢复射频轮询。待机期间其他 PC/SC
程序不能同时使用这台 ACR122T；按空格后程序会恢复 Auto PICC Polling 并释放
Direct handle，完成一次读卡后再重新进入待机。退出程序时会恢复启动前保存的 PICC
参数，然后释放 handle。

## 文件说明

- `door_lock_sim.py`：主程序。
- `config.example.json`：配置示例。
- `requirements.txt`：运行依赖。
- `build_exe.ps1`：可选的单文件 EXE 打包脚本。
- `tests/`：无需读卡器即可运行的模拟测试。

## Windows 安装

1. 安装 64 位 Python 3.9 或更高版本，并确保 `py` 命令可用。
2. 连接 ACR122T。Windows 通常通过 PC/SC/CCID 驱动识别设备；若设备管理器中未
   正常显示，请安装 ACS 官方 ACR122T 驱动。
3. 在本目录打开 PowerShell，执行：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .\config.example.json .\config.json
```

如果 PowerShell 阻止当前会话运行激活脚本，可先执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## 配置

编辑 `config.json`：

```json
{
  "reader": {
    "name_contains": "ACR122",
    "poll_interval_ms": 300
  },
  "sectors": [
    {
      "sector": 0,
      "required": true,
      "auth": "A",
      "key_a": "FFFFFFFFFFFF/A0A1A2A3A4A5",
      "key_b": null,
      "block0": true,
      "block0_data": "00112233445566778899AABBCCDDEEFF/112233445566778899AABBCCDDEEFF00",
      "block1": false,
      "block1_data": null,
      "block2": false,
      "block2_data": null
    },
    {
      "sector": 1,
      "required": true,
      "auth": "both",
      "key_a": "A0A1A2A3A4A5",
      "key_b": "B0B1B2B3B4B5/FFFFFFFFFFFF",
      "block0": false,
      "block0_data": null,
      "block1": true,
      "block1_data": "FFEEDDCCBBAA99887766554433221100",
      "block2": true,
      "block2_data": "00000000000000000000000000000000"
    },
    {
      "sector": 2,
      "required": false,
      "auth": "B",
      "key_a": null,
      "key_b": "FFFFFFFFFFFF",
      "block0": false,
      "block0_data": null,
      "block1": false,
      "block1_data": null,
      "block2": false,
      "block2_data": null
    }
  ]
}
```

配置约束：

- `sector` 必须是 `0` 到 `15`，且不能重复。
- 每个密钥必须是 6 字节十六进制字符串；多把候选密钥用 `/` 分隔。允许写成
  `FFFFFFFFFFFF/A0A1A2A3A4A5`。
- `auth` 选择 `A` 时必须提供 `key_a`；选择 `B` 时必须提供 `key_b`；选择
  `both` 时必须同时提供两者。
- `blockN: true` 时必须提供对应的 `blockN_data`；每个候选值必须恰好为 16 字节，
  多个预期值用 `/` 分隔。
- `blockN: false` 时，对应的 `blockN_data` 必须为 `null` 或省略。
- 至少配置一个 `required: true` 的扇区。

`config.json` 已加入 `.gitignore`。它包含明文密钥，请限制文件访问权限，不要提交
到版本库或发送给无关人员。示例密钥仅用于测试。

## 运行

先确认读卡器名称：

```powershell
python .\door_lock_sim.py --list-readers
```

启动后射频保持关闭。每次按空格开启一次读卡，只输出到控制台：

```powershell
python .\door_lock_sim.py --config .\config.json
```

同时把每次刷卡追加为一行 JSON（JSONL）：

```powershell
python .\door_lock_sim.py --config .\config.json --json-log .\logs\captures.jsonl
```

只读取一张卡后退出：

```powershell
python .\door_lock_sim.py --config .\config.json --json-log .\logs\captures.jsonl --once
```

JSONL 包含时间、采集编号、读卡器、ATR、UID、候选密钥命中序号、实际块数据、
预期数据命中序号、每扇区耗时、APDU 数量和最终门锁判定。日志不会写入候选密钥或
预期数据列表。每行都是独立 JSON，可直接流式导入后续数据处理程序。

## 打包 EXE

在已激活的虚拟环境中运行：

```powershell
.\build_exe.ps1
```

生成文件位于 `dist\door-lock-sim.exe`。配置文件仍应放在 EXE 外部：

```powershell
.\dist\door-lock-sim.exe --config .\config.json --json-log .\logs\captures.jsonl
```

## 测试

模拟测试不需要 pyscard 或真实硬件：

```powershell
python -m unittest discover -s tests -v
```

真实 ACR122T 的最终验证应至少覆盖：第二候选密钥命中、第二候选数据命中、完整数据
不匹配、必需/可选扇区失败、待机射频关闭、按空格开启、处理后再次关闭射频。

## 常见问题

- **找不到读卡器**：运行 `--list-readers`，再把 `reader.name_contains` 改成唯一的
  名称片段。
- **认证状态为 `6300`**：通常是密钥错误、卡片并非 MIFARE Classic，或扇区/块号
  不正确。
- **认证成功但某块读取失败**：检查该扇区尾块中的访问控制位；认证成功不代表这把
  密钥对所有块都有读权限。
- **无法关闭/开启射频场**：确认使用 ACS PC/SC 驱动，并允许 PC/SC Escape
  Command。程序不会在射频控制失败时继续进入伪待机状态。若错误仍为
  `0x80100069`，请确认运行的是最新版 `door_lock_sim.py`；最新版不会通过需要卡片
  的高层连接发送射频命令。
- **按空格后返回 `6300`**：旧版在恢复 Auto PICC Polling 后又重复发送 RF ON。
  最新版只恢复 PICC 参数，由自动轮询负责开启射频。
- **熄灯后约 1–2 秒又亮起**：这表示运行的仍是只发送一次关闭命令、随后释放
  Direct handle 的版本。最新版待机提示应显示“射频已关闭并保持 Direct 占用”。
- **只能看到认证成功/失败，看不到随机数**：这是 ACR122T PC/SC 接口的能力边界，
  不是程序遗漏。

底层命令依据 ACS《ACR122T 应用程序编程接口 V2.03》：`FF 82` 加载密钥、
`FF 86` 认证、`FF B0` 读块、`FF CA` 获取 UID。

参考资料：

- [ACS ACR122T 产品与 Windows 驱动](https://www.acs.com.hk/cn/products/109/acr122t-usb-tokens-nfc-reader/)
- [ACS ACR122T 应用程序编程接口 V2.03](https://www.acs.com.hk/download-manual/1848/API-ACR122T-CN-2.03.pdf)
- [pyscard 用户指南](https://pyscard.sourceforge.io/user-guide.html)
