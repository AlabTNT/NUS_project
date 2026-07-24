"""
Proxmark3 嗅探行为模拟器 - macOS 适配版
=========================================
macOS 的 PCSC.framework 不支持 SCardControl / SCARD_SHARE_DIRECT。
本脚本使用 pyscard 高层 API + ACR122U escape 指令通路,
通过反复连接/断开卡片 + 发送 PN532 命令来模拟嗅探行为。

使用前提: 请放任意一张 NFC 卡片在 ACR122T 上 (UID 卡, MIFARE, NTAG 均可)
"""

import time
import sys
import random
from smartcard.System import readers
from smartcard.util import toHexString

# ── 嗅探模式配置 ──
SCAN_MODES = {
    "passive_scan": {
        "desc": "被动扫描 - 缓慢轮询(模拟低功耗嗅探)",
        "interval": 0.2,
        "burst": False,
    },
    "aggressive_probe": {
        "desc": "主动嗅探 - 高频快速轮询(模拟 aggressive sniffing)",
        "interval": 0.03,
        "burst": False,
    },
    "multi_protocol": {
        "desc": "多协议扫描 - 交替 TypeA/TypeB/FeliCa(模拟协议嗅探)",
        "interval": 0.1,
        "burst": False,
        "rotate_cmds": True,
    },
    "burst": {
        "desc": "脉冲嗅探 - ON/OFF交替, 模拟掩蔽式嗅探行为",
        "interval": 0.06,
        "burst": True,
        "burst_on_cycles": 5,
    },
    "rf_carrier_only": {
        "desc": "裸载波 - 仅持续输出13.56MHz载波(模拟监听设备就位)",
        "interval": 0.01,
        "burst": False,
    },
}

# PN532 命令 (通过 ACR122U escape 封装)
PN532_INLIST_A  = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00]  # ISO14443A
PN532_INLIST_B  = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x03]  # ISO14443B
PN532_INLIST_T  = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x01]  # Topaz
PN532_INLIST_F  = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x02]  # FeliCa 212k
PN532_RF_OFF    = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x32, 0x01, 0x00]  # RFConfiguration RFOff
PN532_GET_UID   = [0xFF, 0xCA, 0x00, 0x00, 0x00]  # ACR122U 直接UID读取

ROTATE_CMDS = [PN532_INLIST_A, PN532_INLIST_B, PN532_INLIST_T, PN532_INLIST_F]


def get_reader():
    r = readers()
    if not r:
        print("[-] 未检测到 ACR122T! 请检查 USB 连接。")
        sys.exit(1)
    return r[0]


def connect_and_send(reader, cmd, timeout=1.0):
    """连接卡片并发送 PN532 命令, 返回 (success, response_data, sw1, sw2)"""
    try:
        conn = reader.createConnection()
        conn.connect(mode=1, disposition=0)  # SHARED mode
        data, sw1, sw2 = conn.transmit(cmd)
        conn.disconnect()
        return True, data, sw1, sw2
    except Exception:
        return False, None, 0, 0


def run_macos_sniffer():
    reader = get_reader()
    print(f"[+] 读卡器: {reader.name}")

    # 预检: 放卡片了吗
    ok, uid_data, sw1, sw2 = connect_and_send(reader, PN532_GET_UID)
    if not ok:
        print("[-] 无法连接卡片! 请确认:")
        print("    1. ACR122T USB 已插好")
        print("    2. 有一张 NFC 卡片放在读卡器上")
        print("    3. 没有其他程序独占读卡器")
        sys.exit(1)

    raw_uid = toHexString(uid_data).replace(" ", "").upper() if uid_data else "N/A"
    print(f"[+] 检测到卡片 UID: {raw_uid}")
    print(f"[+] 卡片将作为嗅探目标, RF 信号将围绕此卡片模拟攻击行为\n")

    # ── 模式选择 ──
    print("可选嗅探模式:")
    for i, (key, cfg) in enumerate(SCAN_MODES.items(), 1):
        print(f"  [{i}] {key}: {cfg['desc']}")
    print(f"  [0] 退出")

    try:
        choice = int(input("\n选择模式 [1-5]: "))
    except (EOFError, ValueError):
        choice = 1

    if choice == 0:
        return

    modes = list(SCAN_MODES.values())
    mode = modes[choice - 1] if 1 <= choice <= len(modes) else modes[0]
    mode_name = list(SCAN_MODES.keys())[choice - 1] if 1 <= choice <= len(modes) else "passive_scan"

    print(f"\n{'='*55}")
    print(f"[*] 嗅探模式: {mode['desc']}")
    print(f"[*] 13.56MHz 射频场已就绪")
    print(f"[*] 防守方可以用 HackRF One / RTL-SDR 进行频谱分析")
    print(f"[*] Ctrl+C 停止")
    print(f"{'='*55}\n")

    count = 0
    card_lost_count = 0

    try:
        while True:
            if mode.get("burst"):
                if (count // mode["burst_on_cycles"]) % 2 == 0:
                    cmd = PN532_INLIST_A
                else:
                    cmd = PN532_RF_OFF
            elif mode.get("rotate_cmds"):
                cmd = ROTATE_CMDS[count % len(ROTATE_CMDS)]
            else:
                cmd = PN532_INLIST_A

            ok, data, sw1, sw2 = connect_and_send(reader, cmd)

            if ok:
                card_lost_count = 0
                if data and len(data) > 0:
                    resp_hex = toHexString(data[:8])
                    print(f"[#{count:05d}] RF脉冲 -> 回应 {len(data)}B: {resp_hex}...")
                else:
                    print(f"[#{count:05d}] 射频脉冲发射 (载波持续)")
            else:
                card_lost_count += 1
                print(f"[#{count:05d}] 射频脉冲 (no response)")
                if card_lost_count > 10:
                    print("\n[!] 卡片似乎已移开! 请重新放卡后继续。")
                    print("[!] 正在等待卡片...")
                    while True:
                        ok2, _, _, _ = connect_and_send(reader, PN532_GET_UID)
                        if ok2:
                            print("[+] 卡片已放回, 继续嗅探。")
                            card_lost_count = 0
                            break
                        time.sleep(0.5)

            count += 1
            time.sleep(mode["interval"])

    except KeyboardInterrupt:
        print(f"\n[*] 共发射 {count} 次射频脉冲")
        print("[-] 嗅探模拟器已退出。")


if __name__ == "__main__":
    run_macos_sniffer()