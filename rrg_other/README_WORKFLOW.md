# Proxmark3 卡片硬件指纹：采集、训练、评估与预测流程

本目录现在提供一个可运行的最小闭环：

```text
ACR122T 执行固定的 MIFARE Classic 认证和读块
                    ↓
Proxmark3 RDV2 被动采集 8-bit HF 包络
                    ↓
manifest.csv + .pm3 波形
                    ↓
QC、粗对齐、时域/频域/物理特征
                    ↓
只用正式卡训练 PCA one-class 模型
                    ↓
标定阈值、评估 Magic/模拟卡、预测新波形
```

这套代码能够完成工程流程，但模型是否真的能区分正式卡和 Magic/模拟卡，必须由足量、无数据泄漏的真实实验验证。当前仓库只有一条零散的 `client/sniff.pm3` 测试波形，不能直接训练可靠模型。

只在获得授权的实验卡、测试读卡器和门锁环境中使用。真实校园卡的 UID、密钥、dump 和原始波形不应提交到 Git。

## 1. 文件说明

- `client/luascripts/hf_mf_fingerprint_raw.lua`：批量采集 ADC 包络并写 `manifest.csv`。
- `client/luascripts/hf_mf_fingerprint_trace.lua`：另开一轮采集 ISO 14443-A 协议 trace。
- `fingerprint_capture/reader_transaction.py`：用 ACR122T 生成固定的“一次认证＋一次读块”交易。
- `fingerprint_capture/convert_pm3.py`：把 `.pm3` 转为 `.npy`，生成基础 QC 统计；模型不强制要求预先转换。
- `fingerprint_pipeline.py`：数据检查、训练、评估和单波形预测。
- `requirements.txt`：Python 依赖。
- `tests/test_fingerprint_pipeline.py`：不需要硬件的合成数据闭环测试。

`fingerprint_pipeline.py` 使用纯 NumPy 实现 PCA one-class 基线，不依赖 sklearn、PyTorch 或 TensorFlow。只有实际控制 ACR122T 时才需要 `pyscard`。

## 2. 硬件与物理摆放

需要：

1. Proxmark3 RDV2/PM3GENERIC，客户端与固件版本匹配；
2. ACR122T 或能执行固定交易的外部门锁读卡器；
3. 至少三张不同的正式测试卡；
4. 用于最终评估的 Magic Card；
5. 非金属固定夹具。

物理关系：

```text
ACR122T 天线
    │
    │ 固定距离和角度
    ▼
待测卡片
    │
    │ Proxmark3 靠近但不能让 ACR122T 交易失败
    ▼
Proxmark3 HF 天线
```

Proxmark3 在 raw 采集模式中只监听，不负责给卡片供电或发起认证。ACR122T 必须负责实际交易。不能让同一台 Proxmark3 一边模拟卡、一边监听自己的波形；采集 Proxmark3 模拟卡时需要第二台 Proxmark3 或 HackRF。

正式卡和 Magic Card 必须使用相同的读卡器、夹具、位置、方向、采样率和交易配置。建议在同一个 session 内交替采不同类别，避免模型把日期或位置当成类别。

## 3. Python 环境

建议 Python 3.11 或 3.12。在项目根目录执行：

```bash
cd /Users/liucanyu/NUS_project
python3 -m venv .venv-fingerprint
source .venv-fingerprint/bin/activate
python -m pip install --upgrade pip
python -m pip install -r rrg_other/requirements.txt
```

macOS 已通过 USB-CDC 识别 Proxmark3 时，不需要额外 Proxmark3 驱动。ACR122T 是否需要厂商驱动取决于系统的 PC/SC/CCID 支持。

确认 ACR122T：

```bash
python rrg_other/fingerprint_capture/reader_transaction.py --list-readers
```

确认 Proxmark3 和 HF 天线；测量 `hw tune` 时先取下所有卡片：

```bash
proxmark3 -p /dev/tty.usbmodemiceman1 -c "hw version; hw tune"
```

必须满足：

- 不再提示 client/ARM firmware mismatch；
- 不再提示 RDV4 firmware on generic device；
- HF antenna 不是 `unusable`。

## 4. 卡片和标签命名

`card_id` 必须代表一张物理卡，不能只使用 UID：

```text
genuine_001
genuine_002
magic_gen1_001
magic_gen2_001
pm3_sim_001
```

推荐标签：

```text
正式卡：genuine
Gen1 Magic：magic_gen1
Gen2 Magic：magic_gen2
Proxmark3 模拟：pm3_sim
其他模拟器：emulator_<name>
```

训练程序只把 `genuine` 当作正式卡。UID 不是训练输入；不需要记录时使用 `-u unknown`。

每次改变日期、夹具位置、卡片方向、读卡器或环境，应使用新的 `session_id` 或 `fixture_id`。

## 5. 采集 raw 波形

一次采集需要两个终端。先确定一个所有实验卡都能正常认证的实验扇区和数据块。下面以数据块 4、Key A 为例；不要使用扇区尾块 3、7、11 等。

### 终端 A：Proxmark3

进入客户端：

```bash
cd /Users/liucanyu/NUS_project/rrg_other/client
proxmark3 -p /dev/tty.usbmodemiceman1
```

采一张正式卡的一个 50 次 session：

```text
script run hf_mf_fingerprint_raw -c genuine_001 -u unknown -l genuine -n 50 -r 4 -e acr122t -f fixture_01
```

采 Magic Card 时只改变物理卡 ID 和标签，不改变任何采样或交易参数：

```text
script run hf_mf_fingerprint_raw -c magic_gen1_001 -u unknown -l magic_gen1 -n 50 -r 4 -e acr122t -f fixture_01
```

开发集建议显式使用 `-o fingerprint_development`，避免与最终盲测混在一起：

```text
script run hf_mf_fingerprint_raw -c genuine_001 -u unknown -l genuine -n 50 -r 4 -o fingerprint_development -e acr122t -f fixture_01
```

默认不写 `-o` 时，数据写到当前工作目录下的：

```text
rrg_other/client/fingerprint_data/<session_id>/
```

最终盲测卡应写入另一个根目录，例如 `-o fingerprint_blind_test`。训练前不要查看或使用盲测分数调参。

### 终端 B：ACR122T 固定交易

```bash
cd /Users/liucanyu/NUS_project
source .venv-fingerprint/bin/activate
python rrg_other/fingerprint_capture/reader_transaction.py \
  --reader ACR122 \
  --block 4 \
  --key-type A \
  --count 50
```

程序会无回显地询问 12 位十六进制 MIFARE Classic 密钥，不会把密钥或读取到的块内容写入日志。

每一轮严格按照：

1. 从两副天线之间移开卡片；
2. 等终端 A 出现 `[ARMED]`；
3. 在终端 B 按 Enter；
4. 把卡放回固定夹具，让 ACR122T 完成一次认证和读块；
5. 看到 `transaction OK` 后移开卡片；
6. 等待下一次 `[ARMED]`。

如果 ACR122T 的 RF 场持续开启，PM3 下一轮可能立即触发并保存无效波形。此时应检查读卡器是否在断开后真正冷复位，或使用能够显式控制 RF 场的实验读卡器。

## 6. 可选：采协议 trace

raw 包络和协议 trace 使用不同 FPGA 模式，单台 Proxmark3 不能同时采集。保持相同卡片、读卡器和交易配置，另开一轮：

```text
script run hf_mf_fingerprint_trace -c genuine_001 -u unknown -l genuine -t 20 -e acr122t
```

执行计划数量的交易后，按 Proxmark3 实体按钮停止。该 trace 用于核对 REQA、选卡、认证、读取、失败和重试，不直接进入第一版模型。

## 7. 第一批数据规模

先做 pilot，不要立即采几万条：

```text
3–5 张正式卡
2–3 张不同 Magic Card
每张卡 2 个 session
每个 session 50 次
总计约 500–800 条
```

若 pilot 显示在未见过的正式卡上仍有分离能力，再扩展为：

```text
20–30 张正式卡，每张至少 200 次，至少 4 个 session
5–10 张不同厂商/代次的 Magic Card
若干模拟器样本作为完全独立的盲测集
```

训练至少需要三张不同的正式 `card_id`。程序会拒绝用一两张卡训练并虚假标定。

## 8. 检查数据

```bash
python rrg_other/fingerprint_pipeline.py inspect \
  --data-root rrg_other/client/fingerprint_development
```

输出包括：

- manifest 总行数；
- 通过和拒绝的波形数量；
- 每个标签的采集数量；
- 每个标签的物理卡数量；
- 前 20 个 QC 失败原因。

默认 QC 拒绝：

- 少于 1000 个样本；
- 标准差小于 1；
- 波形变化比例过低；
- 削顶比例超过 5%；
- 文件不存在或格式错误。

需要 NumPy `.npy` 副本和更详细 CSV 时，可额外运行已有转换器：

```bash
python rrg_other/client/fingerprint_capture/convert_pm3.py \
  rrg_other/client/fingerprint_development/<session_id>/manifest.csv
```

## 9. 训练正式卡 one-class 模型

```bash
mkdir -p rrg_other/models
python rrg_other/fingerprint_pipeline.py train \
  --data-root rrg_other/client/fingerprint_development \
  --model-out rrg_other/models/mfc_oneclass.npz \
  --genuine-label genuine
```

训练过程：

1. 只选取 `label=genuine`；
2. 按物理 `card_id` 划分，而不是随机拆波形；
3. 部分正式卡用于训练 PCA；
4. 至少一张训练中未见过的正式卡用于标定；
5. 默认取标定正式卡异常分数第 99 百分位作为阈值；
6. 保存模型 `.npz` 和相邻的训练摘要 `.json`。

模型组合两种异常指标：

```text
PCA 重构误差
+
PCA 潜在空间中到正式卡分布的稳健距离
```

第一版特征包括振幅统计、波形活动程度、粗对齐位置、128 段时域包络统计和 24 段对数频谱统计。

## 10. 评估 Magic/模拟卡

```bash
mkdir -p rrg_other/reports
python rrg_other/fingerprint_pipeline.py evaluate \
  --data-root rrg_other/client/fingerprint_blind_test \
  --model rrg_other/models/mfc_oneclass.npz \
  --output rrg_other/reports/evaluation.json
```

重点查看：

- `false_reject_rate`：正式卡被误拒比例，越低越好；
- `false_accept_rate`：Magic/模拟卡被误认为正式卡的比例，越低越好；
- `auroc`；
- `average_precision`；
- `breakdown` 中每种卡和每张物理卡的分数。

不要用同一个评估集反复调整阈值。用于最终报告的 Magic/模拟卡和正式卡测试 session 必须在所有参数确定后才解封测试。

评估默认排除模型训练或阈值标定阶段已经见过的 `card_id`，并在输出中列出 `overlapping_card_ids`。如果盲测目录没有“未见过的正式卡”和“异常卡”两者，评估会拒绝运行。`--include-seen-genuine` 只用于调试采集链路，不能用于报告最终性能。

## 11. 预测一条新波形

采集一条与训练时相同 profile 的 `.pm3` 后：

```bash
python rrg_other/fingerprint_pipeline.py predict \
  --model rrg_other/models/mfc_oneclass.npz \
  --waveform path/to/new_capture.pm3
```

输出示例结构：

```json
{
  "score": 1.23,
  "threshold": 2.10,
  "decision": "genuine",
  "quality": {"ok": true}
}
```

可能的决定：

- `genuine`：异常分数未超过阈值；
- `anomalous`：超过阈值；
- `invalid_capture`：波形没有通过 QC，此时应拒绝或重新采集，不能当成正式卡。

实际门锁建议连续采三次并做多数判定，同时报告增加的开门延迟。

## 12. 运行代码测试

测试不需要读卡器，也不会访问真实卡：

```bash
python -m unittest discover -s rrg_other/tests -v
```

测试会生成临时的正式卡和异常卡合成波形，跑通发现、QC、训练、标定和预测后自动删除。

## 13. 结果有效性的最低要求

满足以下条件之前，只能说“流程跑通”，不能声称防御有效：

1. 测试卡 `card_id` 从未出现在训练中；
2. 正式卡与异常卡在同一采集条件下交替采集；
3. UID、文件名、标签、session 和采集顺序未作为模型特征；
4. 至少跨日期或跨夹具重新摆放测试；
5. 阈值在正式卡验证集上冻结；
6. 最终 Magic/模拟卡盲测只运行一次；
7. 报告 FRR 和 FAR，而不是只报告 accuracy；
8. 更换读卡器或 Proxmark3 后重新验证或重新训练。

ACR122T 不会通过 PC/SC 把模拟 ADC 波形交给 Python，因此目前是“ACR122T 发起交易＋Proxmark3 旁路传感＋本地主机推理”的研究原型。要做成独立实时门锁，最终需要专用模拟前端或能输出原始包络的读卡硬件。
