# 🕵️‍♂️ Packet Sniffer in Python

A basic packet sniffer written in Python for educational purposes. It captures and analyzes raw network packets from your local machine and displays key information such as Ethernet frame data, IP headers, and TCP/UDP/ICMP protocol information.

---

## 📌 Features

- Captures **raw network packets** using a raw socket
- Parses and displays:
  - Ethernet frame headers
  - IPv4 packet details
  - TCP/UDP/ICMP protocols
  - Port, flags, TTL, sequence, acknowledgment numbers
- Formats and displays packet data in a readable structure

---

## 🚀 Getting Started

### ⚠️ Requirements

- Python 3.x
- **Administrator/root privileges** are required to create raw sockets
- Platform: **Tested on Windows** (Linux requires slight modifications)

### 🔧 Installation

git clone https://github.com/your-username/packet-sniffer.git
cd packet-sniffer
python main.py

### 🧠 How It Works
-Uses the socket library to open a raw socket bound to your IP.
-Reads raw packet data using recvfrom().
-Uses the struct module to unpack bytes into headers (Ethernet, IP, TCP, etc.).
-Displays data with formatted output using textwrap.


### 🛡 Legal & Ethical Disclaimer
This tool is for educational purposes only. Capturing network traffic without authorization may violate local laws or organizational policies.
🛑 Do not use this on a network you do not own or have permission to monitor.

### 📚 Learning Goals
-Networking fundamentals
-Packet structures (Ethernet, IP, TCP, etc.)
-Working with raw sockets in Python
-Ethical network monitoring

## 🙋‍♂️ Author
Tracey-Lee Swartz
Aspiring cybersecurity and data professional | Python | Networking | Ethical hacking
