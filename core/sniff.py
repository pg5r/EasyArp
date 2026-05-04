from scapy.all import *
from colorama import init, Fore
import threading

init(autoreset=True)

sniff_statictics = False

statictics = {
    
}

def ArpDetect(packet, mode=None):
    if packet.haslayer(ARP):
        psrc = str(packet[ARP].psrc)
        hwsrc = str(packet[ARP].hwsrc)
        pdst = str(packet[ARP].pdst)
        hwdst = str(packet[ARP].hwdst)
        op = str(packet[ARP].op)
        
        if not psrc == "" and not hwsrc == "" and not pdst == "" and not hwdst == "" and not op == "":
            if op == "1":
                if str(mode) != "--reply" and str(mode) != "-reply":
                    print("-------------------------------------------------------------")
                    print(Fore.LIGHTYELLOW_EX + "Detected ARP Request")
                    print(Fore.MAGENTA + f"{psrc} Asks for {pdst}")
                    print("-------------------------------------------------------------")
                    
                    if psrc in statictics:
                        statictics[psrc][2] += 1
                    else:
                        statictics[psrc] = [0 , 0 , 1]

                    return True
                
                return False
                
            elif op == "2":
                if str(mode) != "--request" and str(mode) != "-request":
                    print("-------------------------------------------------------------")
                    print(Fore.LIGHTCYAN_EX + "Detected ARP Reply")
                    print(Fore.MAGENTA + f"Sent to {pdst}=={hwdst} that {psrc}=={hwsrc}")


                    if psrc in statictics:
                        statictics[psrc][0] += 1
                        if statictics[psrc][1] <= 3:
                            print(Fore.RED + "[WARNING] May be an ARP Spoofing")
                        statictics[psrc][1] = 0
                    else:
                        statictics[psrc] = [1 , 0 , 0]
                    
                    print("-------------------------------------------------------------")
                    return True
                return False
            return False
        return False

def SniffOperation(cnt: int, mode=None , statictics=None):
    stats = {}
    counter = {"count": 0}

    def handler(pkt):
        result = ArpDetect(pkt, mode)
        if result:
            counter["count"] += 1

    sniff(
        prn=handler,
        filter="arp",
        store=0,
        stop_filter=lambda pkt: counter["count"] >= cnt
    )

    if sniff_statictics:
        Show_Statictics()

    return True

def Show_Statictics():
    print("")
    print(Fore.GREEN + "Statictics:")
    print("")
    print("----------------------------------------------------")
    if statictics:
        for ip in statictics:
            print(Fore.LIGHTCYAN_EX + f"{ip}: {statictics[ip][0]} Replies , {statictics[ip][2]} Requests , Last Time to send Reply: {statictics[ip][1]}s")
    print("----------------------------------------------------")

def TimeManagement():
    while True:
        time.sleep(0.5)
        if statictics:
            for i in statictics:
                statictics[i][1] += 0.5

tm = threading.Thread(target=TimeManagement)
tm.start()
