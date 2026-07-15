import sys
from smartcard.System import readers
from smartcard.util import toHexString

HASREADER=False

def get_current_card_uid():
    # 1. 获取电脑上连接的所有读卡器
    card_readers = readers()
    if len(card_readers) == 0:
        print("[-] 错误：没有检测到 ACR122T 读卡器，请检查 USB 连接！")
        return None
    
    reader = card_readers[0]
    HASREADER=True
    if HASREADER:
        print(f"[+] 正在使用读卡器: {reader.name}")
    
    try:
        # 2. 尝试连接读卡器上的卡片
        connection = reader.createConnection()
        connection.connect()
        
        # 3. 发送 PC/SC 标准指令 (APDU) 来获取卡片的 UID
        # FF CA 00 00 00 是国际通用的“读取高频卡UID”的盲指令
        GET_UID_APDU = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        data, sw1, sw2 = connection.transmit(GET_UID_APDU)
        
        # 4. 如果返回状态码是 90 00，说明读取成功
        if sw1 == 0x90 and sw2 == 0x00:
            uid = toHexString(data).replace(" ", "")
            return uid
        else:
            print(f"[-] 读取失败，错误码: {hex(sw1)} {hex(sw2)}")
            return None
    except Exception as e:
        # 如果没有放卡片，这里会抛出异常
        return None

if __name__ == "__main__":
    print("[*] 请将准备作为【真钥匙】的卡片贴在 ACR122T 上...")
    while True:
        uid = get_current_card_uid()
        if uid:
            print(f"\n[🎉 录入成功! ]")
            print(f"这张卡片的唯一 7-byte UID 为: {uid}")
            print(f"请复制这串十六进制字符串，下一步要填入门锁白名单。")
            break