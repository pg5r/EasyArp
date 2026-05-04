from scapy.all import *
from colorama import init, Fore, Back, Style
import threading
import os
from core import heart, selfie, help
from core import sniff as core_sniff
import platform

os_name = platform.system()

aliases = {}
red_flag_aliases = ["arp" , "tell" , "that" , "sniff" , "every" , "for" , "ask" , "if" , "can" , "why" , "who" , "where" , "when" , "else" , "all" , "broadcast" , "-request" , "--request" , "-reply" , "--reply" , "request" , "reply" , "flag"]

init(autoreset=True)

logo = r"""
  ______                                  
 |  ____|                  /\               
 | |__   __ _ ___ _   _   /  \   _ __ _ __  
 |  __| / _` / __| | | | / /\ \ | '__| '_ \ 
 | |___| (_| \__ \ |_| |/ ____ \| |  | |_) |
 |______\__,_|___/\__, /_/    \_\_|  | .__/ 
                  |___/              |_|                                
"""


def Terminal():
    global aliases

    while True:
        inpt = input(Fore.LIGHTCYAN_EX + f"[ $ ").lower()
        wrds = inpt.strip().split()
        if len(wrds) == 1:

            if str(wrds[0]) == "clear" or str(wrds[0]) == "clr":
                if os_name == "Windows":
                    os.system("cls")
                elif os_name == "Linux":
                    os.system("clear")
                print(Fore.LIGHTBLACK_EX + logo)
                print(Fore.YELLOW + "Python Based" + Fore.RESET + " - " + Fore.CYAN + "Version 1.0")
            elif str(wrds[0]) == "copyself":
                selfie.CopySelf()
            elif str(wrds[0]) == "help" or str(wrds[0]) == "-help" or str(wrds[0]) == "--help":
                print(Fore.WHITE + help.Help())
            elif str(wrds[0]) == "scan":
                heart.ArpScan()
                print("")
                print(Fore.GREEN + "Operation Ended successfuly")
                print("")
            elif str(wrds[0]) == "sst":
                core_sniff.Show_Statictics()
            elif str(wrds[0]).lower() == "sniff_statictics==on":
                core_sniff.sniff_statictics = True
                print("")
                print(Fore.GREEN + "Statictics Turned On successfuly")
                print("")
            elif str(wrds[0]).lower() == "sniff_statictics==off":
                core_sniff.sniff_statictics = False
                print("")
                print(Fore.RED + "Statictics Turned Off successfuly")
                print("")
            else:
                if "sniff_statictics==" in wrds[0]:
                    print(Fore.RED + "Please use one of these: [ON , OFF]")
                elif "sniff_statictics=" in wrds[0]:
                    print(Fore.RED + "Please use '==' instead of '='")

            
        elif len(wrds) > 1:
            #Alias
            if str(wrds[0]) == "alias":
                if len(wrds) > 2:
                    if str(wrds[1]) == "add":
                        if "==" in wrds[2]:

                            alwrs = str(wrds[2]).strip().split("==")
                            alias = str(alwrs[0])
                            if heart.DataType(alias) != "mac" and heart.DataType(alias) != "ip":
                                if not alias in red_flag_aliases:
                                    if not alias in aliases:
                                        if "/" in alias or '"' in alias or "'" in alias or "." in alias or "," in alias or "(" in alias or ")" in alias or "-" in alias:
                                            print(Fore.RED , f"Please don't use " + "(/" + '"' + "'.,-)")
                                        else:
                                            aliases[alias] = str(alwrs[1])
                                            print("")
                                            print(Fore.GREEN + "Alias Added Successfuly")
                                            print("")
                                        continue
                                    print(Fore.RED + f""">> *
This Alias already Exists.
                            """)
                                    continue


                                print(Fore.RED + "This Alias Name is Forbidden, please use another name.")
    
                            else:
                                print(Fore.RED + f""">> 
                            
Invalid Alias Type:
(IP AND MAC ARE FORBIDDEN)
                            """)
                                continue
                        else:
                            print(Fore.RED + """
Wrong Syntax ! the True is:
alias add <name>==<value: (MAC / IP / Number...)>

                                  """)
                    elif str(wrds[1]) == "del" or str(wrds[1]) == "rm" or str(wrds[1]) == "remove":
                        alias = str(wrds[2])
                        if alias in aliases:
                            del aliases[alias]
                            print("")
                            print(Fore.RED + "Alias Deleted Successfuly")
                            print("")
                            continue
                        else:
                            if alias == "all":
                                aliases.clear()
                                print("")
                                print(Fore.GREEN + "Deleted all Aliases Successfuly.")
                                print("")
                            else:
                                print(Fore.RED + "alias not found.")
                    elif str(wrds[1]) == "edit":
                        wr2 = str(wrds[2])
                        if "==" in wr2:
                            wrr = wr2.split("==")
                            alias == wrr[0]
                            val = wrr[1]
                            if alias in aliases:
                                if aliases[alias] != val:
                                    aliases[alias] = val
                                    print("")
                                    print(Fore.YELLOW + "Alias Edited Successfuly")
                                    print("")
                                    continue
                                else:
                                    print(Fore.RED + "This value is already there")
                            else:
                                print(Fore.RED + "alias not found.")
                    elif str(wrds[1]) == "show":
                        if str(wrds[2]) == "all":
                            print("---------------------------------")
                            print(f"|| {str(aliases).removeprefix("{").removesuffix("}")} ||")
                            print("---------------------------------")
                            continue
                        else:
                            if str(wrds[2]) in aliases:
                                print("---------------------------------")
                                print(f"|| {str(wrds[2])}: {aliases[str(wrds[2])]}".removeprefix("{").removesuffix("}") + " ||")
                                print("---------------------------------")
                                continue
                            else:
                                print(Fore.RED + "alias not found.")
                                continue

            #AskForMac

            elif "ask" in wrds and "for" in wrds and len(wrds) == 4:
                ask = str(wrds[1])
                fr = str(wrds[3])

                if ask == "ask" or ask == "for" or fr == "for" or fr =="ask":
                    print(Fore.RED + f""">> 
Wrong Syntax, The True is:
ask <source:IP or MAC> for <target:IP>
                                """)
                    continue
                else:
                    if str(ask) == "broadcast":
                        ask = "ff:ff:ff:ff:ff:ff"
                    if (heart.DataType(fr)).lower() == "none":
                        if fr in aliases:
                            fr = aliases[fr]
                        else:
                            print(Fore.RED + f""">> 
Wrong Syntax, The True is:
ask <source:IP or MAC> for <target:IP>
                                """)
                            continue

                    if (heart.DataType(ask)).lower() == "none":
                        if ask in aliases:
                            ask = aliases[ask]
                        else:
                            print(Fore.RED + f""">> 
Wrong Syntax, The True is:
ask <source:IP or MAC> for <target:IP>
                                """)
                            continue
                
                ans = heart.AskForMac(target=fr , repsource=ask)
                if ans == None:
                    print(Fore.RED + f">> No Response")
                else:
                    if not "[ERROR]" in ans:
                        print(Fore.GREEN + f">> {ans}")
                    else:
                        print(Fore.RED + f">> {ans}")
            elif len(wrds) == 8 and "tell" in wrds and "that" in wrds and "every" in wrds and "for" in wrds:
                #ARP Packet Send
                tll = str(wrds[1])
                tht = str(wrds[3])

                thts = tht.split("==")

                tht1 = thts[0]
                tht2 = thts[1]

                tlls = []
                have = False
                if "==" in tll:
                    tlls = tll.split("==")
                    have = True
                
                if have:
                    tll1 = tlls[0]
                    tll2 = tlls[1]

                    if tll1 in aliases:
                        tll1 = aliases[tll1]
                    else:
                        if str(heart.DataType(tll1)).lower() == "none":
                            print(Fore.RED + f""">> 
Wrong Syntax, The True is:
tell <destination: MAC==IP> that <target: UnicastMAC==IP> every <ticks: seconds> for <duration: seconds 1>
                                """)
                            continue

                    if tll2 in aliases:
                        tll2 = aliases[tll2]
                    else:
                        if str(heart.DataType(tll2)).lower() == "none":
                            print(Fore.RED + f""">> 
Wrong Syntax, The True is:
tell <destination: MAC==IP> that <target: UnicastMAC==IP> every <ticks: seconds> for <duration: seconds 2>
                                """)
                            continue

               

                    tll = f"{tll1}=={tll2}"
                else:
                    if str(tll) == "broadcast":
                        tll = "ff:ff:ff:ff:ff:ff"
                    if str(heart.DataType(tll)).lower() == "none":
                        if tll in aliases:
                            tll = aliases[tll]
                        else:
                            print(Fore.RED + f""">> 
Wrong Syntax, The True is:
tell <destination: MAC==IP> that <target: UnicastMAC==IP> every <ticks: seconds> for <duration: seconds 3>
                                    """)
                            continue

                if (heart.DataType(tht1)).lower() == "none":
                    if tht1 in aliases:
                        tht1 = aliases[tht1]
                    else:
                        print(Fore.RED + f""">> 
Wrong Syntax, The True is:
tell <destination: MAC==IP> that <target: UnicastMAC==IP> every <ticks: seconds> for <duration: seconds 4>
                            """)
                        continue

                if (heart.DataType(tht2)).lower() == "none":
                    if tht2 in aliases:
                        tht2 = aliases[tht2]
                    else:
                        print(Fore.RED + f""">> 
Wrong Syntax, The True is:
tell <destination: MAC==IP or BroadCast> that <target: UnicastMAC==IP> every <ticks: seconds> for <duration: seconds 5>
                            """)
                        continue

                tht = f"{tht1}=={tht2}"

                evr = str(wrds[5])
                dur = str(wrds[7])
            
                if evr in aliases:
                    evr = (aliases[evr]).removesuffix("s")

                if dur in aliases:
                    dur = (aliases[dur]).removesuffix("s")

                evr = evr.removesuffix("s")
                dur = dur.removesuffix("s")

                print(evr)
                print(dur)
                
                def checkie(evr, dur):
                    try:
                        float(evr)
                        float(dur)
                        return True
                    except:
                        return False

                if not checkie(evr, dur):
                    print(Fore.RED + "Please enter True Times: (float)+s(optional)")
                    continue

                evr = float(evr)
                dur = float(dur)

                if wrds[0] != "tell" or wrds[2] != "that" or wrds[4] != "every" or wrds[6] != "for" or "ff:ff:ff:ff:ff:ff" in tht or "broadcast" in tht:
                    print(Fore.RED + f""">> 
Wrong Syntax, The True is:
tell <destination: MAC==IP or BroadCast> that <target: UnicastMAC==IP> every <ticks: seconds> for <duration: seconds>
                            """)
                    continue

                res = heart.ArpAttack(dest=tll , target=tht , ticks=evr , dur=dur)
                if "[ERROR] Invalid." in str(res):
                    print(Fore.RED + f""">> 
Wrong Syntax, The True is:
tell <destination: MAC==IP or BroadCast> that <target: UnicastMAC==IP> every <ticks: seconds> for <duration: seconds>
                            """)
                    continue
            elif "sniff" in wrds and len(wrds) > 1:
                if wrds[0] == "sniff":
                    def check(val):
                        try:
                            int(val)
                            return True
                        except:
                            return False
                    
                    if check(val=str(wrds[1])) == False:
                        if str(wrds[1]) in aliases:
                            wrds[1] = aliases[wrds[1]]
                            if check(val=str(wrds[1])) == False:
                                print(Fore.RED + "Please enter True count: Natural Number")
                        else:
                            print(Fore.RED + "Please enter True count: Natural Number")
                            continue

                if len(wrds) == 2:
                    count = int(str(wrds[1]))

                    res = core_sniff.SniffOperation(cnt=count , mode=None)
                    if res:
                        print("")
                        print(Fore.GREEN + "Operation Ended Successfuly.")
                        print("")
                        continue
                elif len(wrds) == 3:
                    def chakie(val):
                        try:
                            int(val)
                            return True
                        except:
                            return False
                        
                    if not chakie(str(wrds[1])):
                        print(Fore.RED + "Please enter True count: Natural Number")
                        continue

                    count = int(str(wrds[1]))

                    flag = str(wrds[2])
                    flags = ["--reply" , "-reply" , "--request" , "-request"]
                    if not flag in flags:
                        if flag in aliases:
                            if not aliases[flag] in flags:
                                print(Fore.RED + f"Invalid Flag, True Flags are: {flags}")
                                continue
                            else:
                                flag = aliases[flag]
                        else:
                            print(Fore.RED + f"Invalid Flag, True Flags are: {flags}")
                            continue
                    
                    res = core_sniff.SniffOperation(cnt=count , mode=flag)
                    if res:
                        print("")
                        print(Fore.GREEN + "Operation Ended Successfuly.")
                        print("")
                        continue
            

os.system("cls")
termth = threading.Thread(target=Terminal)
print(Fore.LIGHTBLACK_EX + logo)
print(Fore.YELLOW + "Python Based" + Fore.RESET + " - " + Fore.CYAN + "Version 1.0")
termth.start()
