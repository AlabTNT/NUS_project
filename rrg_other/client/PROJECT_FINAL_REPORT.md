# MIFARE Classic 1K 卡片硬件指纹识别实验结项报告

## 1. 项目目标

本项目研究在协议数据、UID、密钥和卡内数据均可被复制的情况下，能否利用
13.56 MHz 交互波形中的模拟硬件差异，辅助区分正式 MIFARE Classic 1K 卡与
Magic Card。

最终系统采用双重判定：

1. ACR122T 按正常门禁流程验证扇区 0 的 Key A、Key B，并读取 Block 0；
2. Proxmark3 RDV2 被动采集上述三个操作的原始包络波形；
3. 监督二分类模型计算该次交易属于 Magic Card 的概率；
4. 密钥、Block 0 数据、三段波形质量和模型判定必须全部通过才允许开门。

模型不是 MIFARE Classic 密码学认证的替代品，而是在复制卡拥有相同密钥与
数据时增加一层物理硬件指纹判断。

---

## 2. 实验对象与设备

### 2.1 卡片

- 协议：ISO/IEC 14443-A
- 卡型：MIFARE Classic 1K
- 工作频率：13.56 MHz
- 正式卡与对应 Magic Card：
  - 使用相同的已知 Key A、Key B；
  - Block 0 数据按组完全对应；
  - 正常读卡时都能完成 Crypto1 认证和数据读取。

六组数据及 Magic Card 代际如下：

| 组别 | Magic Card 代际 | Formal 交易数 | Magic 交易数 |
|---|---|---:|---:|
| lxj | Gen 1a | 43 | 28 |
| lyl | Gen 1a | 45 | 23 |
| pcfe | Gen 2/CUID | 58 | 29 |
| szc | Gen 1a | 47 | 25 |
| ypz | Gen 1a | 47 | 20 |
| zxh | Gen 2/CUID | 54 | 30 |
| **合计** | Gen 1a 4 组，Gen 2/CUID 2 组 | **294** | **155** |

每组 Formal 与 Magic 相邻采集。采集中多次重新移卡、重新摆放并调整位置，
以降低固定耦合位置对结果的影响。

### 2.2 读卡与采样设备

- 正常交互读卡器：ACS ACR122T
- 被动采样设备：Proxmark3 RDV2
- PM3 客户端：Iceman/master/v4.21611 系列
- PM3 端口：COM5
- 采样命令：

```text
hf sniff --sp 0 --st 0 --smode drop --sratio 4
```

`hf sniff` 采集的是高频包络 ADC 波形，不是 IQ 数据。`--sratio 4` 对原始
13.56 MHz 采样流每 8 个采样保留 1 个，有效采样率为：

```text
13.56 MHz / 8 = 1.695 MHz
```

每个 `.pm3` 波形包含 36,243 个采样点，对应约 21.38 ms 的采样窗口。

---

## 3. 门锁交互范围

最终配置文件为 `lock/config/Mix.txt`。系统只处理扇区 0：

1. 使用 Key A 认证扇区 0；
2. 使用 Key B 认证扇区 0；
3. 读取 Block 0；
4. Block 0 必须精确匹配六个候选值之一；
5. 不认证、不读取其他扇区。

配置中的 Key 为：

```text
Key A: A0A1A2A3A4A5
Key B: B0B1B2B3B4B5
```

Block 0 候选值：

```text
6A569CC161880400C838002000000022
FA9B36C592880400C838002000000022
9AAF3EC5CE880400C838002000000022
64C85AC83E880400C805002000000021
AAD435C58E880400C838002000000022
6A534DC5B1880400C838002000000022
```

三个硬件操作分别生成独立波形：

| 阶段 | 操作 | 输出目录 |
|---|---|---|
| `auth_a` | 扇区 0 Key A 认证 | `stages/auth_a` |
| `auth_b` | 扇区 0 Key B 认证 | `stages/auth_b` |
| `read_block0` | 读取扇区 0 Block 0 | `stages/read_block0` |

每次完整交易必须同时存在三段同名波形。只有标签明确、三段完整且通过波形
质量检查的交易才进入训练。

---

## 4. 样本陈述

### 4.1 有效样本

最终训练数据位于 `fingerprint_data_mix`：

- 完整交易：449 次；
- Formal：294 次；
- Magic：155 次；
- 每次交易三段波形；
- 有效带标签波形总数：449 × 3 = 1,347 份。

数据目录中另有 303 份 `pending-*.pm3`。这些文件没有完成标签提升，不进入
训练、阈值校准或测试。

### 4.2 标签与分组

文件名标签：

- `formal-*`：正式卡；
- `magic-*`：Magic Card；
- `pending-*`：未纳入数据集。

物理分组使用顶层目录名 `lxj`、`lyl`、`pcfe`、`szc`、`ypz`、`zxh`。
所有评估均按完整组拆分，不会把同一组的重复波形同时放入训练集和测试集。

Magic Card 代际记录在：

```text
fingerprint_data_mix/group_metadata.json
```

### 4.3 数据隔离原则

对任意测试折：

- 测试组的 Formal 不参与特征标准化、模型拟合或阈值选择；
- 测试组的 Magic 不参与模型拟合或阈值选择；
- 阈值只依据训练组；
- 测试结果生成后不反向修改该折模型或阈值。

---

## 5. 硬件指纹原理

MIFARE Classic 卡片通过负载调制响应读卡器。即使数字协议内容完全相同，
不同芯片和模拟前端仍可能在以下方面产生差异：

- 负载调制深度；
- 上升沿、下降沿和瞬态响应；
- 整流、稳压和内部电容造成的包络形状；
- 调制开关时序和抖动；
- 高频与低频能量分布；
- 波形削顶、偏度、峰度和幅值占用率；
- 局部能量出现位置与持续时间。

Proxmark3 在 ACR122T 与卡片正常交互时被动观察这些差异。实验不依赖 Magic
Card 后门命令，而只观察普通 Crypto1 认证和 Block 0 读取过程，因此检测路径
与真实门禁使用路径一致。

---

## 6. 波形质量控制

采样程序在保存波形后执行质量检查，包括：

- 样本数量；
- 最小值、最大值、均值和标准差；
- 变化采样比例；
- 削顶比例；
- 分块平均绝对差分；
- 活动块数量；
- 活动与静默噪声比。

`auth_a`、`auth_b` 至少要求活动噪声比 3.5，`read_block0` 至少要求 6.0；
每段至少需要 20 个活动块。采样失败、波形无操作活动、文件保存失败或三段不
完整时，系统采用 fail-closed 策略，不允许开门，也不提升为训练样本。

---

## 7. 特征工程

每段波形提取 78 个特征，三段拼接为 234 维交易特征。

| 特征族 | 数量 | 内容 |
|---|---:|---|
| 幅值统计 | 15 | 均值、标准差、RMS、平均绝对幅值、中位数、MAD、分位数、IQR、偏度、峰度、熵 |
| 幅值占用 | 10 | 正负削顶、总削顶、近零比例、不同幅值阈值占用、活动比例 |
| 跳变特征 | 19 | 一阶/二阶差分、归一化差分、差分分位数、大跳变比例、过零率、斜率变化、滞后差分 |
| 自相关 | 8 | lag 1、2、4、8、16、32、64、128 |
| 时间结构 | 7 | 局部 RMS/绝对幅值变异、能量中心、能量扩散、前半能量、活动段数量和长度 |
| 频谱 | 19 | Welch 频谱中心、带宽、熵、平坦度、滚降、峰值、9 个频带能量及频带比 |
| **每阶段合计** | **78** |  |
| **三阶段合计** | **234** |  |

Welch 频谱使用 4,096 点 Hann 窗和 50% 重叠。

最终全数据模型中绝对系数最大的特征包括：

| 排名 | 特征 | 标准化系数 |
|---:|---|---:|
| 1 | `read_block0:clip_neg_frac` | -0.885 |
| 2 | `read_block0:skewness` | 0.588 |
| 3 | `read_block0:d1_gt_16_frac` | 0.468 |
| 4 | `read_block0:clip_total_frac` | -0.464 |
| 5 | `auth_a:clip_total_frac` | -0.419 |
| 6 | `auth_b:clip_total_frac` | -0.406 |
| 7 | `auth_b:mad_median` | -0.406 |
| 8 | `auth_b:band_090_130k_frac` | -0.344 |
| 9 | `auth_b:clip_neg_frac` | -0.327 |
| 10 | `read_block0:band_030_060k_frac` | -0.322 |

结果表明主要判别信息来自 Block 0 读取阶段的削顶、波形形状和跳变特征，
同时认证阶段也提供补充信息。

---

## 8. 最终监督二分类模型

### 8.1 模型

最终模型使用带 L2 正则的逻辑回归：

```text
P(Magic | x) = sigmoid(w · z + b)
```

其中：

- `x` 为 234 维三阶段特征；
- `z` 为训练集加权均值和标准差归一化后的特征；
- `w`、`b` 为模型参数；
- L2 系数 `ridge = 1.0`；
- 输出为 Magic 概率。

### 8.2 组别与类别平衡

训练权重按“组别 × 类别”分配。每个训练组中的 Formal 和 Magic 单元获得相同
总权重，避免样本较多的组或类别主导模型：

```text
每个 (group, label) 单元总权重相同
```

### 8.3 阈值选择

阈值只使用训练组选择，目标顺序为：

1. 每个训练 Formal 组的 FRR 不超过 5%；
2. 最小化训练 Magic 的错误放行率；
3. 在 Magic 错误放行相同时，最小化 Formal 误拒率；
4. 分类结果相同时，选择 Formal/Magic 分数间隔较大的中点。

最终全六组模型阈值：

```text
Magic probability threshold = 0.5563979393
```

推理规则：

```text
probability <= threshold  => waveform accepted as Formal
probability >  threshold  => rejected as Magic
```

---

## 9. 5|1 留一组评估

六折中每次使用五组 Formal+Magic 训练和选择阈值，余下一整组只用于盲测。

| 留出组 | Formal 放行 | Magic 拦截 | 准确率 | 平衡准确率 | AUC |
|---|---:|---:|---:|---:|---:|
| lxj | 43/43，100.00% | 28/28，100.00% | 100.00% | 100.00% | 100.00% |
| lyl | 45/45，100.00% | 23/23，100.00% | 100.00% | 100.00% | 100.00% |
| pcfe | 53/58，91.38% | 29/29，100.00% | 94.25% | 95.69% | 99.70% |
| szc | 47/47，100.00% | 25/25，100.00% | 100.00% | 100.00% | 100.00% |
| ypz | 46/47，97.87% | 20/20，100.00% | 98.51% | 98.94% | 99.26% |
| zxh | 54/54，100.00% | 30/30，100.00% | 100.00% | 100.00% | 100.00% |
| **总体** | **288/294，97.96%** | **155/155，100.00%** | **98.66%** | **98.98%** | **宏平均 99.83%** |

5|1 结果说明：当训练数据包含至少一个相同 Magic 代际的组时，模型对未见实体
组具有很强的泛化能力。六折中没有 Magic 漏放，Formal 共误拒 6 次。

---

## 10. 4|2 全组合评估

六组中任取两组作为完整盲测集，共有：

```text
C(6, 2) = 15
```

每折使用剩余四组 Formal+Magic 训练和选阈值。

| 留出两组 | Formal 放行 | Magic 拦截 | 准确率 | 平衡准确率 | AUC |
|---|---:|---:|---:|---:|---:|
| lxj + lyl | 88/88，100.00% | 51/51，100.00% | 100.00% | 100.00% | 100.00% |
| lxj + pcfe | 96/101，95.05% | 57/57，100.00% | 96.84% | 97.52% | 99.90% |
| lxj + szc | 90/90，100.00% | 53/53，100.00% | 100.00% | 100.00% | 100.00% |
| lxj + ypz | 87/90，96.67% | 48/48，100.00% | 97.83% | 98.33% | 99.38% |
| lxj + zxh | 97/97，100.00% | 58/58，100.00% | 100.00% | 100.00% | 100.00% |
| lyl + pcfe | 99/103，96.12% | 52/52，100.00% | 97.42% | 98.06% | 99.91% |
| lyl + szc | 92/92，100.00% | 48/48，100.00% | 100.00% | 100.00% | 100.00% |
| lyl + ypz | 91/92，98.91% | 43/43，100.00% | 99.26% | 99.46% | 99.52% |
| lyl + zxh | 99/99，100.00% | 53/53，100.00% | 100.00% | 100.00% | 100.00% |
| pcfe + szc | 96/105，91.43% | 54/54，100.00% | 94.34% | 95.71% | 99.88% |
| pcfe + ypz | 101/105，96.19% | 49/49，100.00% | 97.40% | 98.10% | 99.69% |
| pcfe + zxh | 99/112，88.39% | 49/59，83.05% | 86.55% | 85.72% | 93.55% |
| szc + ypz | 93/94，98.94% | 45/45，100.00% | 99.28% | 99.47% | 99.50% |
| szc + zxh | 101/101，100.00% | 55/55，100.00% | 100.00% | 100.00% | 100.00% |
| ypz + zxh | 100/101，99.01% | 50/50，100.00% | 99.34% | 99.50% | 99.29% |

15 折宏平均：

| 指标 | 结果 |
|---|---:|
| Formal 放行率 | 97.38% |
| Magic 拦截率 | 98.87% |
| 平衡准确率 | 98.13% |
| AUC | 99.37% |

将所有 15 折预测合并时，每条交易会在五个不同测试组合中重复出现，因此合并
计数不是独立样本数。重复预测合计：

- Formal：1,429/1,470 放行，97.21%；
- Magic：765/775 拦截，98.71%；
- 平衡准确率：97.96%。

唯一明显下降的组合是同时留出 `pcfe` 与 `zxh`。这两组是全部
Gen 2/CUID，训练集此时只包含 Gen 1a，因此该折同时也是严格的留一代际测试。

---

## 11. Magic Card 代际分析

### 11.1 常规 5|1 代际结果

| 代际 | 组别 | Magic 拦截 |
|---|---|---:|
| Gen 1a | lxj、lyl、szc、ypz | 96/96，100.00% |
| Gen 2/CUID | pcfe、zxh | 59/59，100.00% |

Gen 1a 的 Magic 概率最低值为 0.9906，中位数为 0.9998；Gen 2/CUID 最低值
为 0.7523，中位数为 0.9935。Gen 2/CUID 的分布更宽，是更难识别的代际。

### 11.2 严格留一代际结果

| 训练代际 | 完全未见测试代际 | Formal 放行 | Magic 拦截 | 平衡准确率 | AUC |
|---|---|---:|---:|---:|---:|
| 仅 Gen 2/CUID | Gen 1a | 179/182，98.35% | 96/96，100.00% | 99.18% | 99.54% |
| 仅 Gen 1a | Gen 2/CUID | 99/112，88.39% | 49/59，83.05% | 85.72% | 93.55% |

只使用 Gen 1a 训练时：

- `pcfe` Magic 拦截 26/29，漏放 3 次；
- `zxh` Magic 拦截 23/30，漏放 7 次。

结论：两种 Magic Card 之间存在共同硬件特征，但仅见过 Gen 1a 的模型不能
完全覆盖 Gen 2/CUID。最终部署模型同时包含两种代际，因此适用于当前已覆盖
类型；面对未见第三种 Magic 实现时仍需重新验证。

---

## 12. 最终全数据模型

最终模型使用全部六组数据：

- Formal 294 次；
- Magic 155 次；
- 234 个三阶段特征；
- L2 逻辑回归；
- 组别×类别平衡；
- 阈值 0.5563979393。

全数据拟合/校准结果：

| 类别 | 结果 |
|---|---:|
| Formal | 294/294 放行 |
| Magic | 155/155 拦截 |

该结果用于生成部署模型，不属于独立盲测证据。模型泛化能力应以 5|1、4|2 和
留一代际结果为准。

最终模型文件：

```text
fingerprint_models/mix_supervised_binary/final_all_groups/supervised_binary_model.json
```

---

## 13. 复现实验

### 13.1 采样

Formal：

```powershell
py -3 .\lock\fingerprint_door.py sample `
  --config .\lock\config\Mix.txt `
  --output-dir .\fingerprint_data_mix\<group_id> `
  --label formal
```

Magic：

```powershell
py -3 .\lock\fingerprint_door.py sample `
  --config .\lock\config\Mix.txt `
  --output-dir .\fingerprint_data_mix\<group_id> `
  --label magic
```

每次按空格执行一轮：

```text
PM3 开始嗅探
→ ACR122T Key A 认证
→ 保存 auth_a
→ Key B 认证
→ 保存 auth_b
→ 读取 Block 0
→ 保存 read_block0
→ 卡片密钥/数据验证
→ 波形质量检查
→ 写入 audit.jsonl
→ data clear
```

### 13.2 训练与全部评估

```powershell
py -3 .\lock\fingerprint_door.py train `
  --data-root .\fingerprint_data_mix `
  --model-dir .\fingerprint_models\mix_supervised_binary `
  --group-metadata .\fingerprint_data_mix\group_metadata.json
```

该命令会生成：

- 6 折 5|1；
- 15 折 4|2；
- 2 折留一代际；
- 全六组最终部署模型；
- CSV 预测明细和 JSON 汇总报告。

也可以直接运行：

```powershell
py -3 .\fingerprint_capture\evaluate_mix_supervised_binary.py
```

### 13.3 门锁使用模式

```powershell
py -3 .\lock\fingerprint_door.py use `
  --config .\lock\config\Mix.txt `
  --model .\fingerprint_models\mix_supervised_binary\final_all_groups\supervised_binary_model.json `
  --output-dir .\fingerprint_use_mix
```

最终放行必须同时满足：

```text
Key A 认证通过
AND Key B 认证通过
AND Block 0 完整数据匹配
AND 三段波形保存成功
AND 三段波形质量检查通过
AND 监督模型判定为 Formal
```

任何异常均拒绝开门。

---

## 14. 输出文件

| 文件 | 内容 |
|---|---|
| `fingerprint_models/mix_supervised_binary/supervised_binary_report.json` | 完整训练和评估报告 |
| `fingerprint_models/mix_supervised_binary/fold_results.csv` | 5|1 六折结果 |
| `fingerprint_models/mix_supervised_binary/blind_predictions.csv` | 5|1 逐交易预测 |
| `fingerprint_models/mix_supervised_binary/four_train_two_test_results.csv` | 4|2 十五折结果 |
| `fingerprint_models/mix_supervised_binary/four_train_two_test_predictions.csv` | 4|2 逐交易预测 |
| `fingerprint_models/mix_supervised_binary/generation_holdout_predictions.csv` | 留一代际预测 |
| `fingerprint_models/mix_supervised_binary/feature_cache.npz` | 1,347 份波形的冻结特征缓存 |
| `fingerprint_models/mix_supervised_binary/final_all_groups/supervised_binary_model.json` | 最终部署模型 |

---

## 15. 结果解释与限制

### 15.1 已得到的证据

1. 在六组完整留组测试中，监督模型对 Magic 的拦截率为 100%；
2. 5|1 平衡准确率为 98.98%；
3. 4|2 十五折宏平均平衡准确率为 98.13%；
4. Gen 1a 与 Gen 2/CUID 都能被识别；
5. 多次重新摆放后仍保持可分，固定位置不是唯一解释；
6. Block 0 读取阶段贡献了最强的一批特征。

### 15.2 仍然存在的限制

1. 物理分组只有六组，样本数主要来自同卡重复采样；
2. Magic Card 只覆盖 Gen 1a 和 Gen 2/CUID；
3. 同时留出全部 Gen 2/CUID 时，拦截率下降到 83.05%；
4. 削顶比例是重要特征，可能同时受到天线距离、耦合强度和 ADC 饱和影响；
5. 当前结论只适用于相同 ACR122T、PM3、天线叠放方式和采样参数；
6. 对新的读卡器、PM3、天线位置或 Magic 代际，需要重新校准或验证；
7. 全数据 100% 是拟合/校准结果，不能代替留组测试。

### 15.3 推荐部署策略

- 保留密钥和 Block 0 数据校验，不允许模型单独开门；
- 固定 PM3、ACR122T 和天线结构；
- 使用当前监督模型检测已覆盖的 Gen 1a、Gen 2/CUID；
- 收集新 Magic 代际时，先冻结模型做盲测，再决定是否加入训练；
- 定期记录概率分布，监测设备漂移；
- 对接近阈值的样本可要求重新刷卡；
- 任何采样、质量检查或模型异常均 fail closed。

---

## 16. 结项结论

本实验在协议数据、密钥和 Block 0 内容相同的条件下，通过 ACR122T 正常执行
扇区 0 Key A/Key B 认证与 Block 0 读取，并由 Proxmark3 RDV2 被动采集三段
原始包络波形。基于 78×3 个统计、时域和频域特征训练监督逻辑回归模型。

最终结果为：

```text
5|1：Formal 97.96%，Magic 100.00%，平衡准确率 98.98%
4|2：宏平均 Formal 97.38%，Magic 98.87%，平衡准确率 98.13%
严格 Gen 1a → Gen 2/CUID：Magic 83.05%
```

实验支持以下结论：

> 在当前设备、卡片代际和采样条件下，正常 MIFARE Classic 1K 与 Gen 1a、
> Gen 2/CUID Magic Card 在扇区 0 认证和 Block 0 读取波形中存在稳定、可用于
> 监督分类的硬件差异。模型能够对未参与训练的实体组保持较高识别率，但对完全
> 未见 Magic 代际的能力取决于该代际与训练代际的硬件相似性。

