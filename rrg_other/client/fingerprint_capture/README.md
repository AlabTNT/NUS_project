# MIFARE Classic 1K 硬件指纹采集

本方案让 ACR122T 自定义读卡器（或实际门禁）执行真实的 ISO14443-A、Crypto1 认证和读块交易，Proxmark3 RDV2 只被动采集。正式卡与 Magic Card 的密钥、UID 和块数据可以完全一致；采集脚本不会把卡内数据当作“真实性”依据。

## 采集能力与限制

- `hf sniff` 采集的是 RDV2 HF 峰值检波路径上的 **8 位包络 ADC**，基础采样率约为 **13.56 MS/s**，不是复数 IQ。
- 命令检测到外部读卡器 RF 场超过固件阈值后开始填充 BigBuf。RDV2 不产生载波，因此 ACR122T/门禁必须负责给卡供能和发起交易。
- RDV2 只有 64 KiB SRAM，固件可用 BigBuf 通常约 40 KiB。全速采样约覆盖 3 ms；`sratio=4` 的 `drop` 模式每 8 点保留 1 点，约覆盖 20–25 ms，输出采样率 1.695 MS/s。
- 原始 ADC 与 ISO14443-A 协议 trace 使用不同 FPGA 模式，单台 PM3 无法同时采集。因此脚本将二者分成两轮重复实验。
- `.pm3` 是 `data save` 生成的一行一个整数的 GraphBuffer 文件。它保留采样值，但不自带采样率；采样率记录在 `manifest.csv`。

## 推荐物理布置

把 ACR122T、卡片和 RDV2 固定在不可移动的非金属夹具中。RDV2 天线应靠近卡片，但不能明显降低 ACR122T 的交易成功率。先固定一个位置完成一个 session，再改变距离或角度，并使用新的 `fixture_id`，不要在同一 session 中无记录地改变几何关系。

每次采集应遵循：

1. ACR122T RF 场关闭，卡片移出场区。
2. PM3 控制台出现 `[ARMED]`。
3. 按正常人的方式把卡移入固定读卡区域。
4. ACR122T 开场，执行一次完整的认证和若干读块，然后关场。
5. 移开卡片，等待脚本的随机间隔，再进行下一次。

如果自定义读卡器会持续开场，下一轮会被立即触发，产生无效样本。应让它在每次交易后真正关闭 RF 场。

## 1. 原始波形批量采集

在已连接 RDV2 的 Proxmark3 客户端中运行：

```text
script run hf_mf_fingerprint_raw -c card_001 -u DE0E504F -l genuine -n 200 -r 4 -e acr122t_custom -f fixture_01
```

默认 profile 为 `-r 4`：实际抽取倍数为 8，采样率 1.695 MS/s。建议正式数据每张物理卡采集 200 次，分散到至少 4 个 session/时段，每个 session 50 次。`card_id` 必须表示物理卡，不能只用 UID，因为 UID 可以复制。

可额外采集不同窗口，但应作为不同输入 profile 单独训练或分别建模：

| 参数 | 实际抽取 | 输出采样率 | 典型覆盖范围 | 用途 |
|---|---:|---:|---:|---|
| `-r 0` | 1 | 13.56 MS/s | 约 3 ms | 上电、REQA/ATQA、抗冲突早期细节 |
| `-r 2` | 4 | 3.39 MS/s | 约 10–12 ms | 选卡及认证开始 |
| `-r 4` | 8 | 1.695 MS/s | 约 20–25 ms | 默认，认证与少量读块 |
| `-r 8` | 16 | 847.5 kS/s | 约 40–50 ms | 较长的多块读取，时域细节较少 |

不要把不同采样率的数组直接放进同一个模型而不提供 profile 或重采样；模型很容易把采集设置当成类别特征。

## 2. 协议 trace 与认证挑战

另开一轮采集：

```text
script run hf_mf_fingerprint_trace -c card_001 -u DE0E504F -l genuine -t 20 -e acr122t_custom
```

完成计划交易后按 **RDV2 实体按钮** 停止。脚本保存 `.trace` 和相邻的 JSON 元数据。查看或提取认证信息：

```text
trace load -f fingerprint_data/<session>/card_001/protocol/<capture_id>
trace list -1 -t 14a
trace extract -1
```

协议 trace 用于核对 REQA、抗冲突、认证、读块顺序、失败/重试和挑战分布；它不等同于 ADC 波形。

## 3. 转换和质量检查

退出 PM3 客户端后，在普通 PowerShell 中运行（需要 Python 与 NumPy）：

```powershell
python .\fingerprint_capture\convert_pm3.py .\fingerprint_data\<session>\manifest.csv
```

转换器把每个 `.pm3` 精确保留为 `int16` 的 `.npy`，并生成 `manifest_enriched.csv`，其中包含长度、均值、标准差、削顶比例和简单 QC 状态。不要先对整个数据集做全局归一化；建议按单条波形去直流，并保留幅度/RMS/包络上升时间等独立特征。

## 数据集设计与放行模型

只采正式卡时，这不是普通二分类问题。模型应按 **one-class / anomaly detection / OOD rejection** 设计，置信度阈值必须由独立验证集标定。不能把“softmax 低分”直接解释成 Magic Card。

建议最低规模：

- 至少 20–30 张不同批次/厂商日期的正式物理卡；每张 200 次。
- 训练、验证、测试按 `card_id` 分组切分，绝不能把同一物理卡的不同波形随机分到三组。
- 留出不同日期、温度、夹具位置和至少一台不同 ACR122T/门禁作为域外测试。
- UID、明文块内容、固定密钥、文件名和采集顺序不要直接输入波形模型，避免模型记住身份或 session。
- 最终阈值必须同时满足“正式卡误拒率”和实测仿制卡/异常卡拒绝率。即使不把 Magic Card 用于训练，也应把若干已知 Magic Card 仅作为最终盲测集，否则无法证明系统能排除目标类别。

认证随机数会改变每次交易的比特内容。建议使用协议 trace 标注各帧边界，再从 ADC 中裁出相同类型的卡响应（ATQA、UID/BCC、认证响应、读块响应），或让模型使用分段输入，减少“交易内容差异”掩盖硬件指纹。

## 固件依据

- Iceman `client/src/cmdhf.c`：`hf sniff` 参数、BigBuf 下载和 `data save` 工作流。
- Iceman `armsrc/hfsnoop.c`：场强阈值触发、BigBuf 填充、`drop/min/max/avg` 抽取实现。
- Iceman `fpga/hi_sniffer.v`：被动模式关闭发射功放，以 13.56 MHz ADC 时钟输出 8 位样本。
- Iceman `client/src/cmdhf14a.c` 与 `client/src/cmdtrace.c`：ISO14443-A sniff 和 `.trace` 保存。

对应在线源码：

- <https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/cmdhf.c>
- <https://github.com/RfidResearchGroup/proxmark3/blob/master/armsrc/hfsnoop.c>
- <https://github.com/RfidResearchGroup/proxmark3/blob/master/fpga/hi_sniffer.v>
- <https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/commands.md>
