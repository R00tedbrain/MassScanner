🌐 Autonomous Network Scanner
A Python-based autonomous network scanner that leverages the nmap library to perform various port scans on randomly generated public IP addresses. This tool is designed for network auditing and security analysis, featuring automated IP generation, dynamic scan rotation, and detailed logging of results.

🚀 Features
🔄 Autonomous IP Generation: Automatically generates public IPs, excluding private and reserved ranges.
⚡ Dynamic Scan Rotation: Switches between different scan methods if no results are found.
⏳ Timeout Handling: Ensures no long delays with per-host timeout configurations.
📜 Detailed Logging: Saves results in a human-readable format (scan_results.txt) and prints them to the console.
🛠️ Five Scan Types Supported:
Basic Scan: Detects open ports (1-1024) and their services/versions.
SYN Scan: Stealth scan using TCP SYN packets.
Full Scan: Scans all ports (1-65535).
UDP Scan: Detects UDP-based services.
Evasive Scan: Uses advanced techniques (fragmentation, MTU adjustments) to evade detection.

🧩 How It Works
Generates Public IPs: The script excludes private (10.0.0.0, 192.168.0.0) and reserved ranges.
Performs Scans: Scans each IP using nmap based on the selected scan type.
Logs Results: Outputs detected open ports and services to both the console and a text file.
Rotates Scan Types: Automatically switches between the supported scan types if a host is unresponsive.
⚙️ Requirements
Python 3.x
nmap installed on your system
python-nmap library:
pip3 install python-nmap

📂 File Structure
.
├── botscanv2.py         # Main script
├── scan_results.txt     # Logs results from the scans
└── README.md            # Documentation

🖥️ Usage
Run the Script
Use the following command:
sudo python3 botscanv2.py
Results
Results are displayed in the console and saved in scan_results.txt:

IP: 8.8.8.8
PUERTOS ABIERTOS:
  - 80: http (Apache)
  - 443: https (nginx)
 Supported Scan Types
Basic Scan:

Ports: 1-1024
Options: -sV
Example:
[INFO] Escaneo básico en 8.8.8.8

SYN Scan:

Stealth scan (less detectable by firewalls).
Options: -sS -T4
[INFO] Escaneo SYN en 8.8.8.8
Full Scan:

All ports (1-65535).
Options: -sV

[INFO] Escaneo completo en 8.8.8.8

UDP Scan:

Focuses on UDP-based services.
Options: -sU
[INFO] Escaneo UDP en 8.8.8.8

Evasive Scan:

Uses techniques like packet fragmentation and MTU adjustments.
Options: -sS -T4 -f --mtu 24

[INFO] Escaneo evasivo en 8.8.8.8


⚠️ Legal Disclaimer
This script is intended for authorized network auditing and security testing purposes only. Unauthorized use on networks where you lack explicit permission may violate laws and regulations, such as the Computer Fraud and Abuse Act (CFAA) in the United States.

🛠️ Contributing
Feel free to contribute to this project by submitting issues or pull requests. Make sure your contributions align with the purpose of ethical security analysis.

📜 License
This project is licensed under the MIT License.





