import time
from smartcard.System import readers
from smartcard.util import toHexString
from colorama import init, Fore, Style

init(autoreset=True)

# 🔒 【安全防御核心：32位核心密钥】
# 对应 4 个字节的明文十六进制密码，你可以任意修改
AUTH_PASSWORD = [0x12, 0x34, 0x56, 0x78]

def run_secure_lock():
    all_readers = readers()
    if len(all_readers) == 0:
        print(Fore.RED + "[-] 错误：未检测到任何读卡器，请检查 USB 连接！")
        return
    
    # 锁定当前连接的这唯一一台 Microsoft 读卡器
    lock_reader = all_readers[0]
    
    print(Fore.CYAN + "==================================================")
    print(Fore.CYAN + "       NUS RC4 Secure Smart Lock System v2.1       ")
    print(Fore.CYAN + "==================================================")
    print(Fore.GREEN + f"[+] 当前门锁设备: {lock_reader.name}")
    print(Fore.YELLOW + "[*] 安全系统已全面上锁 🔒，动态密码校验已启用...")
    
    last_uid = None
    
    while True:
        try:
            connection = lock_reader.createConnection()
            connection.connect()
            
            # 1. 基础寻卡：获取卡片的 UID
            GET_UID_APDU = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            data, sw1, sw2 = connection.transmit(GET_UID_APDU)
            
            if sw1 == 0x90 and sw2 == 0x00:
                current_uid = toHexString(data).replace(" ", "").upper()
                
                if current_uid != last_uid:
                    print(f"\n[*] 侦测到钥匙靠近 [UID: {current_uid}]")
                    print(Fore.BLUE + "[*] 正在向 NTAG21X 芯片发起 32-bit 密码质询...")
                    time.sleep(0.2)
                    
                    # 🚨 2. 发送底层的 PWD_AUTH 密码校验指令 (NTAG21X 核心硬件防御)
                    # FF 00 00 00: 读卡器透传包头 | 06: 数据长度
                    # 1B: NTAG芯片标准的密码认证操作码 | 后面紧跟4字节密码
                    PWD_AUTH_APDU = [0xFF, 0x00, 0x00, 0x00, 0x06, 0x1B] + AUTH_PASSWORD
                    
                    auth_data, auth_sw1, auth_sw2 = connection.transmit(PWD_AUTH_APDU)
                    
                    # 3. 校验卡片硬件返回的应答
                    # NTAG 芯片如果密码验证成功，其硬件会返回特定的 2 字节 PACK (Password Acknowledge)
                    if auth_sw1 == 0x90 and auth_sw2 == 0x00:
                        print(Fore.GREEN + Style.BRIGHT + "==================================================")
                        print(Fore.GREEN + Style.BRIGHT + "[ 🔓 ACCESS GRANTED ] 动态密码验证通过！欢迎回家。")
                        print(Fore.GREEN + Style.BRIGHT + "==================================================")
                    else:
                        print(Fore.RED + Style.BRIGHT + "==================================================")
                        print(Fore.RED + Style.BRIGHT + "[ ❌ ACCESS DENIED ] 警告：密码错误或非正版钥匙标签！")
                        print(Fore.RED + Style.BRIGHT + "==================================================")
                        
                    last_uid = current_uid
            
            connection.disconnect()
            
        except Exception:
            if last_uid is not None:
                print(Fore.YELLOW + "\n[*] 钥匙已移开，系统重新注入动态防御防护 🔒 ...")
                last_uid = None
        
        time.sleep(0.3) 

if __name__ == "__main__":
    run_secure_lock()