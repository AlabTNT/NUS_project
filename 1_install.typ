#set page(
  paper: "a4",
  margin: (x: 2.5cm, y: 2cm),
)
#set text(
  font: ("Songti SC", "Heiti SC"),
  size: 11pt,
  lang: "zh",
)

#set heading(numbering: "1.")

#show raw.where(block: true): it => {
  box(
    fill: luma(97%),
    stroke: luma(60%),
    inset: 12pt,
    radius: 8pt,
    width: 100%,
    it
  )
}

= 环境配置指南

== macOS 环境配置

=== 安装 Homebrew 包管理器（可跳）

Homebrew 是 macOS 下的标准包管理工具，所有后续安装依赖它。

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

安装完成后，根据终端提示将 Homebrew 加入 PATH（Apple Silicon 机型需要额外操作）。

=== 安装编译工具链

```bash
brew install git gcc make cmake pkg-config
```

=== 安装 Proxmark3 客户端

```bash
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
# 仅编译客户端，不编译固件
make client
```

编译成功后，`pm3` 可执行文件位于 `client/` 目录下。为了方便全局使用，可以将其加入 PATH：

```bash
sudo ln -s $(pwd)/client/pm3 /usr/local/bin/pm3
```

=== 安装 HackRF One 驱动及 GNU Radio

```bash
brew install hackrf gnuradio
```

验证 HackRF 连接：

```bash
hackrf_info
```

=== 安装 Python 分析工具

```bash
brew install python@3.12
pip3 install numpy scipy matplotlib pyserial
```

== Windows 环境配置

=== 安装 MSYS2 编译环境（可选，推荐）

Proxmark3 客户端在 Windows 上的编译依赖 MSYS2 提供的 POSIX 工具链。如果之前已经在 Shell 环境中安装过 pacman、git、make，可以跳过安装 MSYS2 直接使用 Shell 。

1. 从 #link("https://www.msys2.org/")[msys2.org] 下载并安装 MSYS2。
2. 启动 MSYS2 UCRT64 终端，更新系统并安装依赖：

```bash
pacman -Syu
pacman -S git make gcc pkg-config readline-devel
```

=== 安装 Proxmark3 客户端

在 MSYS2 UCRT64 终端中执行：

```bash
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
make client
```

编译完成后的 `pm3.exe` 位于 `client/` 目录下。

=== 安装 HackRF 及 GNU Radio（二进制安装）

推荐使用 PothosSDR 一键安装包，免除手动编译 SDR 工具链的繁琐过程。

1. 从 #link("https://github.com/pothosware/PothosSDR/wiki")[PothosSDR Releases] 下载最新安装包。
2. 运行安装程序，勾选所需组件：
   - GNU Radio
   - HackRF Support
   - osmocom SDR
3. 安装完成后，使用 Zadig 驱动工具（安装包自带）为 HackRF One 安装 WinUSB 驱动。

或者通过 MSYS2 安装仅 HackRF 工具：

```bash
pacman -S mingw-w64-ucrt-x86_64-hackrf
```

=== 安装 Python 环境

从 #link("https://www.python.org/downloads/")[python.org] 下载 Python 3.12 安装包。安装时务必勾选“Add Python to PATH”。

打开命令提示符，安装所需包（有需要的可以创建虚拟环境）：

```powershell
pip install numpy scipy matplotlib pyserial
```

=== Windows 特殊说明：驱动与串口

- Proxmark3 通过 USB-CDC 虚拟串口通信。插入 PM3 后，在设备管理器中确认端口号（如 `COM3`），后续连接时指定即可。
- 若串口未自动识别，需安装项目自带的 `.inf` 驱动文件（位于 `proxmark3/driver/`）。

== 环境验证清单

完成上述配置后，按以下清单逐一验证：

#table(
  columns: (1fr, auto, auto),
  [*检查项*], [*命令*], [*预期结果*],
  [Proxmark3 客户端], [`pm3 --help`], [显示帮助信息],
  [HackRF 连接], [`hackrf_info`], [显示设备序列号与固件版本],
  [GNU Radio], [`gnuradio-companion`], [启动图形化流图编辑器],
  [Python 版本], [`python3 --version`], [≥ 3.10],
  [numpy / scipy], [`python3 -c "import numpy"`], [无报错],
)

