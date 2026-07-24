# zxh 卡扇区尾恢复清单

本清单只修复扇区尾，不写 Block 0，也不改普通数据块。

必须在 `client` 目录启动的 PM3 客户端内逐组执行。每个 `wrbl` 后紧接一个
`rdbl` 验证；只有两条都显示成功才进入下一组。出现 `fail`、`Auth error`、
`Can't select card` 时立即停止。

## 扇区 3

```text
hf mf wrbl --blk 15 -b -k 324233423442 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 12 -b -k B0B1B2B3B4B5
```

## 扇区 4

```text
hf mf wrbl --blk 19 -b -k 35222C0D0A20 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 16 -b -k B0B1B2B3B4B5
```

## 扇区 5

```text
hf mf wrbl --blk 23 -b -k 202020202022 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 20 -b -k B0B1B2B3B4B5
```

## 扇区 6

```text
hf mf wrbl --blk 27 -b -k 416363657373 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 24 -b -k B0B1B2B3B4B5
```

## 扇区 7

```text
hf mf wrbl --blk 31 -b -k 436F6E646974 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 28 -b -k B0B1B2B3B4B5
```

## 扇区 8

```text
hf mf wrbl --blk 35 -b -k 696F6E73223A -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 32 -b -k B0B1B2B3B4B5
```

## 扇区 9

```text
hf mf wrbl --blk 39 -b -k 202237463037 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 36 -b -k B0B1B2B3B4B5
```

## 扇区 10

```text
hf mf wrbl --blk 43 -b -k 38383639222C -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 40 -b -k B0B1B2B3B4B5
```

## 扇区 11

```text
hf mf wrbl --blk 47 -b -k 0D0A20202020 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 44 -b -k B0B1B2B3B4B5
```

## 扇区 12

```text
hf mf wrbl --blk 51 -b -k 202022416363 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 48 -b -k B0B1B2B3B4B5
```

## 扇区 13

```text
hf mf wrbl --blk 55 -b -k 657373436F6E -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 52 -b -k B0B1B2B3B4B5
```

## 扇区 14

```text
hf mf wrbl --blk 59 -b -k 646974696F6E -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 56 -b -k B0B1B2B3B4B5
```

## 扇区 15

```text
hf mf wrbl --blk 63 -b -k 735465787422 -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 60 -b -k B0B1B2B3B4B5
```

## 扇区 1（源文件缺失，恢复为默认传输配置）

当前访问条件 `FF078069` 要求用当前 Key A 写扇区尾。

```text
hf mf wrbl --blk 7 -a -k 437265617465 -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF
hf mf rdbl --blk 4 -a -k FFFFFFFFFFFF
```

## 扇区 2（源文件缺失，恢复为默认传输配置）

```text
hf mf wrbl --blk 11 -a -k 64223A202270 -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF
hf mf rdbl --blk 8 -a -k FFFFFFFFFFFF
```

## 扇区 0（最后执行）

```text
hf mf wrbl --blk 3 -b -k 20202020224B -d A0A1A2A3A4A57F078869B0B1B2B3B4B5
hf mf rdbl --blk 0 -b -k B0B1B2B3B4B5
```

## 全部成功后的验证

```text
hf mf chk --dump -k FFFFFFFFFFFF -k A0A1A2A3A4A5 -k B0B1B2B3B4B5
hf 14a info
hf mf info
```

`chk --dump` 会生成一个新的 `hf-mf-6A534DC5-key-*.bin`。最后使用它明确
指定密钥文件进行完整读取，不要让 `dump` 自动选中之前的旧 key 文件：

```text
hf mf dump --1k --ns -k <chk刚生成的key文件名>
```

预期：扇区 0、3–15 为 A0/B0；扇区 1、2 为 FF/FF。UID 仍为
`6A534DC5`。
