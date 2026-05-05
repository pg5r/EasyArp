# EasyArp

**EasyArp** is a beginner-friendly Python-based command-line tool designed to explore and understand ARP (Address Resolution Protocol) in local networks.

It provides simple, interactive commands to help users learn how ARP works in practice.

---

##  Project Goal

This tool is specifically built for:

* Beginners in networking
* Students learning ARP concepts
* Safe experimentation in local environments

It focuses on simplicity over complexity, making low-level networking easier to understand.

---

##  Features

*  ARP Network Scanner (discover devices in LAN)
*  ARP Request (resolve IP → MAC)
*  ARP packet crafting
*  ARP Sniffer with optional statistics
*  Alias system for simplified commands
*  Interactive terminal interface
*  Auto setup via `launcher.bat`

---

##  Project Structure

```id="k92hsd"
EasyArp/
│
├── launcher.bat
├── main.py
├── requirements.txt
│
└── core/
    ├── heart.py
    ├── selfie.py
    ├── sniff.py
```

---

##  Installation & Usage

### Run the launcher

```id="z81xpa"
launcher.bat
```

This will:

* Check Python installation
* Verify project files
* Install dependencies
* Launch the tool

---

## Requirements

* Python 3.9+
* Windows OS

Dependencies:

* scapy
* colorama
* psutil

---

## Commands Overview

### Basic

* `scan` → Scan local network
* `clear / clr` → Clear terminal
* `copyself` → Relaunch tool

### ARP

* `ask <src> for <target_ip>` → Resolve MAC
* `tell <dest> that <target> every <t> for <d>` → Send ARP packets

### Sniffing

* `sniff <count>`
* `sniff <count> --request`
* `sniff <count> --reply`

### Statistics

* `sniff_statictics==on`
* `sniff_statictics==off`
* `sst`

### Aliases

* `alias add name==value`
* `alias del name`
* `alias edit name==value`
* `alias show all`

---

## Future Development

This project is actively evolving. Planned improvements include:

* Better error handling
* Improved UI/UX in terminal
* More advanced sniffing filters
* Cross-platform support (Linux)
* Performance optimizations
* Possibly GUI version

---

## Disclaimer

This tool is intended strictly for:

* Educational use
* Local testing environments
* Authorized network analysis

Do NOT use it on networks without permission.

---

## 👤 Author

**pg5r**

---

## 📌 Version

```id="q7sd2p"
1.0
```

---

## 📄 License

Use at your own risk. No guarantees provided.
