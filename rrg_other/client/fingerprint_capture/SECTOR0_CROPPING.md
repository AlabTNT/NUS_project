# 扇区 0 波形截断

`crop_sector0.py` 根据 `lock/config/<组名>.json` 和
`lock/door_lock_sim.py` 的实际执行顺序，从 PM3 原始 GraphBuffer 中提取：

1. 扇区 0 Key A 认证；
2. 扇区 0 Key B 认证；
3. 读取扇区 0 的绝对块 0。

UID 获取、选卡前导、扇区 1 认证以及交易后的再次寻卡活动均不包含在输出中。脚本
不会修改 `capture` 中的原文件。

## 使用方法

先仅生成判断清单：

```powershell
python .\fingerprint_capture\crop_sector0.py `
  --dry-run `
  --output-root .\tmp\sector0_dryrun
```

确认 `crop_manifest.csv` 后生成截断波形：

```powershell
python .\fingerprint_capture\crop_sector0.py `
  --output-root .\capture_sector0
```

训练截断数据：

```powershell
python .\fingerprint_capture\train_fingerprint_model.py train `
  --data-root .\capture_sector0 `
  --mode binary `
  --output-dir .\fingerprint_capture\binary_output_sector0
```

## 判定原理

当前门锁配置的扇区 0 流程固定为 `AUTH A → AUTH B → READ block 0`。
一次成功的 MIFARE Classic Crypto1 认证包含四个空中帧，一次成功读块包含命令和
响应两个空中帧，因此目标流程应包含十个帧候选。脚本在初始选卡活动之后寻找该
序列，并检查每一阶段的时间间隔和结束后的留白。

这仍然是包络波形的启发式分段，并非 ISO14443-A 协议解码。以下情况会被拒绝：

- 没有捕获到完整交易；
- 活动段合并或缺失，无法唯一确定十帧边界；
- 最后一个响应到达采样缓冲区边缘；
- 认证失败或重试导致序列与成功流程不一致。

拒绝样本不得强行加入训练，应扩大采样窗口后重新采集，或用配对协议 trace/读卡器
时间戳提供精确边界。

## 当前数据结果

当前 120 条原始采样中有 100 条通过保守截断，20 条被拒绝。`zxh` 的十条 magic
采样均无法可靠确定扇区 0 终点，因此当前截断数据中没有 `zxh` magic 测试样本。
完整原因见：

```text
capture_sector0/crop_manifest.csv
```

在这 100 条截断样本上进行按物理卡组留一验证，聚合准确率为 99%，正式卡接受率
为 98.08%，magic 拒绝率为 100%，AUC 为 0.9996。该结果仍属于小样本探索，
不能作为门禁上线指标，特别是需要重新采集完整的 `zxh` magic 样本后再做严格的
跨卡、跨日期和跨摆放位置测试。
