# ACR122T MIFARE Classic 1K 门锁模拟器

这是一个面向 Windows 的只读控制台程序。ACR122T 作为门锁读卡器，实体
MIFARE Classic 1K 卡作为门卡。程序按配置加载每个扇区的 Key A/Key B，执行
原生 Crypto1 三次认证，读取四个块，并给出“允许开门”或“拒绝开门”的结果。

程序不会向卡片写入任何数据。

## 认证与判定规则

- `auth: "A"`：只验证 Key A。
- `auth: "B"`：只验证 Key B。
- `auth: "both"`：Key A 和 Key B 必须分别认证成功。
- `required: true`：认证失败会拒绝开门。
- `required: false`：仍然认证和读取，但失败不影响开门判定。
- 每个已配置扇区都会尝试读取全部四个块。块读取失败会被标注和记录，但不改变
  开门判定。
- 未写入配置文件的扇区不会被访问。
- 每次处理完成后立即断开卡片、冷复位射频状态并释放 PC/SC 上下文；持续模式通过
  插卡/移卡事件等待下一张卡，不会长期占用 ACR122T。

每个块在读取前会重新认证，因此一次刷卡可能包含多次独立的 Crypto1 随机挑战。
ACR122T 在读卡器和卡片内部完成认证；PC/SC 只返回成功或失败状态，程序无法输出
`Nt/Nr/Ar/At` 原始认证报文。如果需要原始挑战报文，应同时使用 Proxmark3 被动
嗅探。

扇区尾块也会尝试读取。受 MIFARE Classic 访问条件限制，Key A 通常不会作为
可读数据返回，Key B 是否可读取取决于访问控制位；这不代表程序从配置文件泄露密钥。

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
      "key_a": "FFFFFFFFFFFF",
      "key_b": null
    },
    {
      "sector": 1,
      "required": true,
      "auth": "both",
      "key_a": "A0A1A2A3A4A5",
      "key_b": "B0B1B2B3B4B5"
    },
    {
      "sector": 2,
      "required": false,
      "auth": "B",
      "key_a": null,
      "key_b": "FFFFFFFFFFFF"
    }
  ]
}
```

配置约束：

- `sector` 必须是 `0` 到 `15`，且不能重复。
- 密钥必须是 6 字节十六进制字符串；允许省略空格，也允许写成
  `FF FF FF FF FF FF`。
- `auth` 选择 `A` 时必须提供 `key_a`；选择 `B` 时必须提供 `key_b`；选择
  `both` 时必须同时提供两者。
- 至少配置一个 `required: true` 的扇区。

`config.json` 已加入 `.gitignore`。它包含明文密钥，请限制文件访问权限，不要提交
到版本库或发送给无关人员。示例密钥仅用于测试。

## 运行

先确认读卡器名称：

```powershell
python .\door_lock_sim.py --list-readers
```

持续等待刷卡，只输出到控制台：

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

JSONL 包含时间、采集编号、读卡器、ATR、UID、每把密钥的认证状态、每块读取结果、
使用的密钥类型和最终门锁判定。日志不会写入密钥值。每行都是独立 JSON，可直接
流式导入后续数据处理程序。

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

真实 ACR122T 的最终验证应至少覆盖：正确 Key A、正确 Key B、`both` 中任一错误、
可选扇区错误、尾块不可读、刷卡后移卡和连续刷两张不同卡。

## 常见问题

- **找不到读卡器**：运行 `--list-readers`，再把 `reader.name_contains` 改成唯一的
  名称片段。
- **认证状态为 `6300`**：通常是密钥错误、卡片并非 MIFARE Classic，或扇区/块号
  不正确。
- **认证成功但某块读取失败**：检查该扇区尾块中的访问控制位；认证成功不代表这把
  密钥对所有块都有读权限。
- **只能看到认证成功/失败，看不到随机数**：这是 ACR122T PC/SC 接口的能力边界，
  不是程序遗漏。

底层命令依据 ACS《ACR122T 应用程序编程接口 V2.03》：`FF 82` 加载密钥、
`FF 86` 认证、`FF B0` 读块、`FF CA` 获取 UID。

参考资料：

- [ACS ACR122T 产品与 Windows 驱动](https://www.acs.com.hk/cn/products/109/acr122t-usb-tokens-nfc-reader/)
- [ACS ACR122T 应用程序编程接口 V2.03](https://www.acs.com.hk/download-manual/1848/API-ACR122T-CN-2.03.pdf)
- [pyscard 用户指南](https://pyscard.sourceforge.io/user-guide.html)
