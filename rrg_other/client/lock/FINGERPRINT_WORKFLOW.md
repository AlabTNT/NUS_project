# ACR122T + Proxmark3 三阶段硬件指纹门锁

统一入口为 `fingerprint_door.py`，固定使用 Proxmark3 `COM5`。程序复用发行包
`setup.bat` 的环境，因此与上一级 `pm3.bat` 的启动方式一致。

程序控制 PM3 时会在 `setup.bat` 环境中直接启动 `proxmark3.exe -p COM5`。
这是 `pm3.bat` 中 `bash pm3 -p COM5` 最终执行的本机客户端命令。程序不直接调用
Bash 包装器，因为该包装器在 Python 重定向输入输出且工程路径包含中文时，可能找
不到自带的 `dirname`/`basename`，从而在连接 COM5 之前退出。

卡片操作是只读的，不会写入 MIFARE Classic 数据。

## 三阶段采集

由于 `sratio 4` 的单个 BigBuf 无法覆盖完整扇区 0，程序将一次刷卡拆成三个高采样
窗口：

1. 扇区 0 `AUTH A`；
2. 扇区 0 `AUTH B`；
3. 扇区 0 `READ Block 0`。

三段共享同一个 `capture_id`。PM3 客户端在程序启动时建立一次持久 COM5 连接，
每段执行：

```text
data clear → hf sniff → 对应ACR122T APDU → data save → data clear
```

默认在提交 `hf sniff` 后等待 200 ms 再发送 APDU。这是当前
RDV2 + ACR122T 叠放环境的实测同步值，可用
`--pm3-operation-delay-ms` 调整。审计记录会保存实际使用的延迟。

每段质控不仅检查样本数、标准差和非平坦程度，还检查 32 点活动块相对于波形后半段
噪声底的比例，以及活动块数量。AUTH 与 READ 使用各自的强度门槛，因为读数据的
响应长度和能量本来就不同。这样可以拒绝只录到 PM3 启动瞬态、却错过 AUTH/READ
的文件。若改变设备摆位、采样比例或客户端版本，应重新校准延迟并检查
`audit.jsonl` 中的 `operation_activity`。

## 安装

建议为本目录建立新的虚拟环境，不要继续使用从其他工程复制、路径已经失效的旧
`.venv`：

```powershell
py -3 -m venv .\lock\.venv-fingerprint
.\lock\.venv-fingerprint\Scripts\python.exe -m pip install `
  -r .\lock\requirements.txt
```

## 采样模式

每张物理正式卡使用独立输出目录。例如采集 lyl 正式卡：

```powershell
.\lock\.venv-fingerprint\Scripts\python.exe `
  .\lock\fingerprint_door.py sample `
  --config .\lock\config\lyl.json `
  --label formal `
  --output-dir .\fingerprint_data\lyl
```

`--label` 是必选参数：

- `--label formal`：通过验证后保存为 `formal-<capture_id>.pm3`；
- `--label magic`：通过验证后保存为 `magic-<capture_id>.pm3`。

一次程序运行中的所有采样使用同一个标签。若需要切换标签，应退出并以另一个
`--label` 重新启动，避免同一批次误标。

程序启动后保持 ACR122T RF 关闭：

- 按空格：采集一次完整的三阶段样本；
- 按 `Q` 或 `Esc`：退出。

只采一次可增加 `--once`，但仍需按一次空格。

每次通过质控的输出结构如下：

```text
fingerprint_data/
  lyl/
    audit.jsonl
    stages/
      auth_a/formal-<capture_id>.pm3
      auth_b/formal-<capture_id>.pm3
      read_block0/formal-<capture_id>.pm3
```

只有三段全部保存、通过交互活动波形质控，并且卡片密钥和数据验证成功，该次采样状态
才是 `VALID`，三段文件才会从 `pending-` 原子改名为指定的 `formal-` 或
`magic-`。失败或不完整
样本保留为 `pending-` 供审计，训练模式不会读取。

## 训练模式

数据根目录下应包含多张物理正式卡的独立目录：

```text
fingerprint_data/
  card_001/...
  card_002/...
  card_003/...
```

训练三个 one-class 模型：

```powershell
.\lock\.venv-fingerprint\Scripts\python.exe `
  .\lock\fingerprint_door.py train `
  --data-root .\fingerprint_data `
  --model-dir .\fingerprint_models\sector0
```

训练使用 `formal-*.pm3` 拟合 one-class 模型；`magic-*.pm3` 只参与评估，
绝不参与中心、尺度或阈值拟合。程序取三个阶段均存在的 `capture_id` 交集，分别拟合：

- `auth_a/oneclass_model.json`
- `auth_b/oneclass_model.json`
- `read_block0/oneclass_model.json`

统一入口模型为：

```text
fingerprint_models/sector0/fingerprint_bundle.json
```

同时生成：

- `three_stage_evaluation.json`：三阶段全部通过规则的总体结果及按卡组留一验证；
- `three_stage_predictions.csv`：每个样本的三个相对分数和最终判定；
- 每个阶段目录下的 `oneclass_training_report.json` 和 `features.csv`。

默认 `--target-frr 0.05` 是偏安全的阈值设置。三阶段采用 AND 规则后，正式卡总拒绝率
会高于单阶段的 5%；应优先参考 `three_stage_evaluation.json` 中的
`leave_one_card_group_out.aggregate`，而不是训练数据上的回代结果。

## 使用模式

```powershell
.\lock\.venv-fingerprint\Scripts\python.exe `
  .\lock\fingerprint_door.py use `
  --config .\lock\config\lyl.json `
  --output-dir .\access_audit `
  --model .\fingerprint_models\sector0\fingerprint_bundle.json
```

使用模式保存的文件以 `use-` 开头，因此不会被训练模式误当成正式卡训练数据。

最终允许开门必须同时满足：

```text
密钥认证成功
AND 块数据完全匹配
AND AUTH A 波形保存及质控成功
AND AUTH B 波形保存及质控成功
AND READ Block 0 波形保存及质控成功
AND 三个 one-class 模型全部判定可信
```

PM3 连接、保存、波形质控、模型加载或模型推理任一步失败，最终结果均为
`DENY`，但程序仍尽可能记录卡片验证结果和已取得的波形。

## 审计

`audit.jsonl` 每行对应一次空格触发，包含：

- `capture_id` 与模式；
- 门锁配置、UID、ATR、认证和读块结果；
- 三阶段 PM3 文件、字节数和质控统计；
- APDU 开始/结束、波形保存和 RF 开关时间戳；
- 每阶段模型分数、阈值和可信判定；
- 最终 `OPEN`/`DENY` 原因。

日志不会写入配置中的密钥值或预期数据候选列表。

## 已验证环境

- Proxmark3 RDV2：`COM5`，Iceman `v4.21611`；
- ACR122T：`ACS ACR122 0`；
- lyl 正式卡：扇区 0 Key A/Key B、Block 0 数据和扇区 1 Key B 均验证成功；
- 三阶段 `sratio 4` 波形均保存为 36,243 点并通过质控；
- 在当前叠放位置，10 ms 延迟仅录到启动瞬态；180–220 ms 均捕获到认证活动，
  因而采用 200 ms 默认值；
- 临时两样本模型测试中，卡片验证通过但模型拒绝时，最终结果正确保持 `DENY`。

临时两样本模型只用于验证程序链路，不能作为实际门锁模型。
