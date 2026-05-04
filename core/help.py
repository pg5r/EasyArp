help = """## EasyArp 1.0  (by pg5r)

Beginner-friendly ARP toolkit for local networks

USAGE:
command [arguments]

---

COMMANDS (DETAILED)

scan
Perform ARP scan on your local network.
- Automatically detects your IP and subnet mask
- Sends ARP requests to all hosts in the subnet
- Prints: IP -> MAC for each discovered device

---

ask <source> for <target_ip>
Send a single ARP request.

```
PARAMETERS:
- source:
    MAC address OR alias OR "broadcast"
    If "broadcast" → ff:ff:ff:ff:ff:ff

- target_ip:
    IPv4 address (e.g. 192.168.1.1)

BEHAVIOR:
- Sends ARP request: "Who has target_ip?"
- Waits for response (timeout ~5s)
- Returns MAC address or error

EXAMPLE:
    ask broadcast for 192.168.1.1
```

---

tell <destination> that <target> every <ticks> for <duration>
Send repeated ARP reply packets (ARP injection / spoofing simulation).

```
PARAMETERS:
- destination:
    Format: MAC==IP OR "broadcast"

- target:
    Format: MAC==IP
    (This is the identity you are claiming)

- ticks:
    Time between packets (float allowed)
    Examples: 1 , 2.5 , 3s

- duration:
    Total time to send packets

BEHAVIOR:
- Sends ARP reply packets every <ticks>
- Continues until <duration> is finished
- Uses low-level packet crafting via scapy

IMPORTANT:
- Invalid formats will be rejected
- Broadcast destination auto-fills network broadcast IP

EXAMPLE:
    tell ff:ff:ff:ff:ff:ff that 192.168.1.1==aa:bb:cc:dd:ee:ff every 2s for 10s
```

---

sniff <count> [--request | --reply]
Capture ARP packets from the network.

```
PARAMETERS:
- count:
    Number of packets to capture (integer only)

- flags:
    --request → only ARP requests
    --reply   → only ARP replies
    (no flag → capture both)

BEHAVIOR:
- Listens for ARP traffic
- Prints detected packets in real time
- Stops automatically after <count>

EXAMPLES:
    sniff 10
    sniff 20 --request
    sniff 15 --reply
```

---

sst
Show collected ARP statistics.

```
OUTPUT:
- IP address
- Number of replies sent
- Number of requests seen
- Time since last reply
```

---

OPTIONS / FLAGS

sniff_statictics==on
Enable statistics tracking during sniffing

sniff_statictics==off
Disable statistics tracking

---

ALIASES SYSTEM

Aliases allow replacing complex values (IP / MAC / numbers).

COMMANDS:

alias add <name>==<value>
Create alias

alias del <name>
Delete alias

alias edit <name>==<value>
Modify alias value

alias show all
Print all aliases

RULES:

* Name must not be IP or MAC
* Special characters are restricted
* Cannot overwrite existing alias

EXAMPLE:
alias add router==192.168.1.1
ask broadcast for router

---

SPECIAL VALUES

broadcast
ff:ff:ff:ff:ff:ff

TIME FORMAT
Accepts:
- Integer: 1
- Float: 2.5
- With suffix: 3s , 5s

---

NOTES

* Requires administrator/root privileges
* Uses scapy for packet-level operations
* Works on local network only
* Aliases are stored in memory (not persistent)

---

WARNING

This tool can manipulate ARP traffic.
Use ONLY in controlled environments.
Unauthorized usage may be illegal.
"""

def Help():
    return help
