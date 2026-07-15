import sys
import time
from smartcard.System import readers

r = readers()
if len(r) == 0:
    print("[-] 未检测到 ACR122T 读卡器")
    sys.exit()

reader = r[0]
connection = reader.createConnection()
connection.connect()

# 严格根据 04b4f7624b2d80 计算出的官方标准物理区块数据
b0 = [0x04, 0xB4, 0xF7, 0x3F]  # UID0-2 + BCC0
b1 = [0x62, 0x4B, 0x2D, 0x80]  # UID3-6
b2 = [0xC6, 0x48, 0x00, 0x00]  # BCC1 + Internal

print("[*] 正在向 ACR122T 发送全量同步复写序列...")

# 一气呵成连续写入 0, 1, 2 块
cmds = [
    ("[+] 写入 Block 0", [0xFF, 0xD6, 0x00, 0x00, 0x04] + b0),
    ("[+] 写入 Block 1", [0xFF, 0xD6, 0x00, 0x01, 0x04] + b1),
    ("[+] 写入 Block 2", [0xFF, 0xD6, 0x00, 0x02, 0x04] + b2)
]

for label, cmd in cmds:
    response, sw1, sw2 = connection.transmit(cmd)
    print(f"{label}: {hex(sw1)} {hex(sw2)}")
    time.sleep(0.1)

print("[🎉] 强写序列执行完毕。请将卡片拿开，重新放上，然后去 Proxmark3 用 hf 14a info 验明正身！")