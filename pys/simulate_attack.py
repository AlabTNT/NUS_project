"""
Proxmark3 嗅探行为模拟器 (ACR122U/ACR122T)
===========================================
通过 ACR122U 的 PN532 射频前端发射连续载波/轮询信号，
模拟 Proxmark3 嗅探时的 RF 特征，供防守方调试检测程序。

平台兼容：
  - Windows: SCARD_SHARE_DIRECT + SCardControl (无需卡片, 已测试)
  - Linux:   SCARD_SHARE_DIRECT + SCardControl (需 pcsc-lite + libacsccid)
  - macOS:   不支持 SCardControl, 请使用 simulate_attack_macos.py
"""

import time
import sys
from smartcard.scard import (
    SCARD_SHARE_DIRECT,
    SCARD_PROTOCOL_RAW,
    SCardConnect,
    SCardControl,
    SCardDisconnect,
    SCARD_LEAVE_CARD,
    SCardEstablishContext,
    SCardListReaders,
    SCARD_SCOPE_USER,
)

# ── 攻击模式配置 ──────────────────────────────────────────
SCAN_MODES = {
    "passive_scan": {
        "desc": "被动扫描 - 只发射载波 + 缓慢轮询(模拟低功耗嗅探)",
        "cmd":      [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00],  # InListPassiveTarget (TypeA, 106k)
        "interval": 0.15,
    },
    "aggressive_probe": {
        "desc": "主动嗅探 - 高频快速轮询(模拟 aggressive sniffing)",
        "cmd":      [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00],
        "interval": 0.02,
    },
    "multi_protocol": {
        "desc": "多协议扫描 - 交替 TypeA/TypeB/FeliCa(模拟协议分析)",
        "cmds": [
            [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00],  # ISO14443A
            [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x03],  # ISO14443B
            [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x01],  # Topaz
            [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x02],  # FeliCa 212k
        ],
        "interval": 0.08,
    },
    "burst": {
        "desc": "脉冲嗅探 - ON/OFF交替, 模拟掩蔽式嗅探行为",
        "burst_on":  [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00],
        "burst_off": [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x32, 0x01, 0x00],  # RFConfiguration RFOff
        "cycles":    5,
        "interval":  0.05,
    },
    "rf_carrier_only": {
        "desc": "裸载波 - 仅持续输出13.56MHz载波(模拟监听设备就位)",
        "cmd":      [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00],
        "interval": 0.003,  # 极短间隔 = 接近连续载波
    },
}

# ACR122U CCID Escape 控制码 (Windows/Linux)
# SCARD_CTL_CODE(3500) 的标准值, 兼容 pcsc-lite / winscard
CONTROL_CODES = [
    0x003136B0,   # SCARD_CTL_CODE(3500)
    0x42000000 + 3500 * 4,  # IOCTL_CCID_ESCAPE (Linux pcsc-lite)
]


def scard_error_name(hr: int) -> str:
    errors = {
        0x00000000: "SCARD_S_SUCCESS",
        0x80100004: "SCARD_E_INVALID_PARAMETER",
        0x8010000B: "SCARD_E_SHARING_VIOLATION",
        0x8010000C: "SCARD_E_NO_SMARTCARD",
        0x80100016: "SCARD_E_NOT_TRANSACTED",
        0x8010001A: "SCARD_E_NO_SERVICE",
        0x8010001C: "SCARD_E_UNSUPPORTED_FEATURE",
    }
    return errors.get(hr, f"0x{hr:08X}")


def find_control_code(hcard, cmd):
    """尝试多个控制码, 返回第一个成功的"""
    for code in CONTROL_CODES:
        try:
            hr, resp = SCardControl(hcard, code, cmd)
            if hr == 0:
                return code, resp
        except Exception:
            continue
    return None, None


def run_sniffer_simulator():
    hr, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
    if hr != 0:
        print(f"[-] SCardEstablishContext 失败: {scard_error_name(hr)}")
        sys.exit(1)

    hr, readers = SCardListReaders(hcontext, [])
    if hr != 0 or len(readers) == 0:
        print(f"[-] 未检测到读卡器: {scard_error_name(hr)}")
        sys.exit(1)

    reader = readers[0]
    print(f"[+] 读卡器: {reader}")

    hr, hcard, proto = SCardConnect(hcontext, reader, SCARD_SHARE_DIRECT, SCARD_PROTOCOL_RAW)
    if hr != 0:
        print(f"[-] SCardConnect(DIRECT) 失败: {scard_error_name(hr)}")
        print("[!] 当前平台可能不支持 SCARD_SHARE_DIRECT (macOS?).")
        print("[!] 请使用 simulate_attack_macos.py 或在 Windows/Linux 运行本脚本。")
        sys.exit(1)

    print(f"[+] 物理层直连连通! hcard={hcard}, proto={proto}")

    # 探测可用的控制码
    test_cmd = [0xFF, 0x00, 0x00, 0x00, 0x02, 0xD4, 0x02]  # PN532 GetFirmwareVersion
    code, _ = find_control_code(hcard, test_cmd)
    if code is None:
        print("[-] SCardControl 不可用, 当前平台不适合直接跑本脚本。")
        print("[!] 如果仍要强行尝试, 请在 macOS 改用模拟脚本。")
        SCardDisconnect(hcard, SCARD_LEAVE_CARD)
        sys.exit(1)
    print(f"[+] SCardControl 可用, 控制码: 0x{code:08X}")

    # ── 交互选模式 ──
    print("\n可选嗅探模式:")
    for i, (key, cfg) in enumerate(SCAN_MODES.items(), 1):
        print(f"  [{i}] {key}: {cfg['desc']}")
    print(f"  [0] 退出")

    try:
        choice = int(input("\n选择模式 [1-5]: "))
    except (EOFError, ValueError):
        choice = 1

    if choice == 0:
        SCardDisconnect(hcard, SCARD_LEAVE_CARD)
        return

    modes = list(SCAN_MODES.values())
    if 1 <= choice <= len(modes):
        mode = modes[choice - 1]
    else:
        print("[*] 默认 passive_scan")
        mode = modes[0]

    print(f"\n{'='*55}")
    print(f"[*] 嗅探模式: {mode.get('desc', '自定义')}")
    print(f"[*] 13.56MHz 射频场已就绪")
    print(f"[*] 防守方可以开始用 HackRF One / RTL-SDR 采样分析")
    print(f"[*] Ctrl+C 停止")
    print(f"{'='*55}\n")

    count = 0
    try:
        while True:
            if "cmds" in mode:
                cmd = mode["cmds"][count % len(mode["cmds"])]
                interval = mode["interval"]
            elif "burst_on" in mode:
                # 脉冲模式: ON cycles 次, 然后 OFF 一次
                if (count // mode["cycles"]) % 2 == 0:
                    cmd = mode["burst_on"]
                else:
                    cmd = mode["burst_off"]
                interval = mode["interval"]
            else:
                cmd = mode["cmd"]
                interval = mode["interval"]

            hr, response = SCardControl(hcard, code, cmd)
            
            if hr == 0 and response and len(response) > 6:
                tag_found = " [TAG DETECTED!]" if len(response) > 10 else ""
                print(f"[#{count:05d}] RF握手 {len(response)}B 回应{tag_found}")
            else:
                print(f"[#{count:05d}] 射频脉冲发射中 (载波持续)")

            count += 1
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] 共发射 {count} 次射频脉冲")
        print("[-] 正在关闭射频场...")
        SCardDisconnect(hcard, SCARD_LEAVE_CARD)
        print("[+] 射频场已安全关闭。")


if __name__ == "__main__":
    run_sniffer_simulator()