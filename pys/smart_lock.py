import time
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from colorama import init, Fore, Style

init(autoreset=True)
KEY_WHITE_LIST = ["04B4F7624B2D80"]
BLACKLIST = ["04298B92AF5980"]

class SmartLockObserver(CardObserver):
    """
    驱动级异步观察者：由操作系统直接派发硬件事件，绝不阻塞物理天线
    """
    def __init__(self):
        self.last_uid = None

    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        
        # 🔓 1. 检测到有卡片靠近 (毫秒级硬件触发)
        for card in addedcards:
            try:
                # 使用最安全的共享模式连接
                connection = card.createConnection()
                connection.connect(mode=2, protocol=3)
                
                GET_UID_APDU = [0xFF, 0xCA, 0x00, 0x00, 0x00]
                data, sw1, sw2 = connection.transmit(GET_UID_APDU)
                
                if sw1 == 0x90 and sw2 == 0x00:
                    current_uid = toHexString(data).replace(" ", "").upper()
                    
                    if current_uid != self.last_uid:
                        print(f"\n[*] 🔑 侦测到卡片靠近... [UID: {current_uid}]")
                        
                        if current_uid in KEY_WHITE_LIST:
                            print(Fore.GREEN + Style.BRIGHT + "==========================================")
                            print(Fore.GREEN + Style.BRIGHT + "[ 🔓 ACCESS GRANTED ] 欢迎回家！门锁已开启。")
                            print(Fore.GREEN + Style.BRIGHT + "==========================================")
                        else:
                            print(Fore.RED + Style.BRIGHT + "==========================================")
                            print(Fore.RED + Style.BRIGHT + "[ ❌ ACCESS DENIED ] 警告：非法钥匙！身份验证失败。")
                            print(Fore.RED + Style.BRIGHT + "==========================================")
                        
                        self.last_uid = current_uid
                
                # 强行断电释放，确保下一次拿开事件能被立刻捕获
                connection.disconnect(disposition=2)
                
            except Exception as e:
                pass

        # 🔒 2. 检测到卡片被拿开 (由系统底层通知，彻底告别盲等死锁)
        for card in removedcards:
            if self.last_uid is not None:
                print(Fore.YELLOW + "\n[*] 🍃 用户离开，门锁已自动重新上锁 🔒 ...")
                self.last_uid = None

def run_async_gate_lock():
    print(Fore.CYAN + "==================================================")
    print(Fore.CYAN + "     NUS RC4 Async Smart Lock System v2.0         ")
    print(Fore.CYAN + "==================================================")
    print(Fore.YELLOW + "[*] 门锁防御驱动已加载，正在后台监听物理层事件...")

    # 启动异步硬件监控器
    monitor = CardMonitor()
    observer = SmartLockObserver()
    monitor.addObserver(observer)

    try:
        # 主线程彻底解放，只需要在这里静默挂起，没有任何死锁风险
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # 退出时优雅注销勾子
        monitor.deleteObserver(observer)
        print("\n[-] 门锁系统安全退出。")

if __name__ == "__main__":
    run_async_gate_lock()