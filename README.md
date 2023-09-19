# File Intercept
The File Intercept Python Script is a network interception tool developed in Python that leverages the power of scapy and netfilterqueue modules to intercept and modify network packets. Specifically, it focuses on trapping HTTP requests and responses and allows for the replacement of specific file extensions in the traffic.

## Key Features
- **Packet Interception:** Utilizes netfilterqueue to intercept network packets, providing the ability to inspect and modify their content.
- **HTTP Request and Response Handling:** Differentiates between HTTP requests and responses, enabling customized actions based on the packet type.
- **File Extension Replacement:** Identifies specific file extensions within HTTP traffic and replaces them with predefined redirection URLs.

## How it Works
1. **Packet Trapping:** The script sets up iptables rules to redirect packets to a specified queue number.
2. **Packet Processing:** Using netfilterqueue, the script intercepts packets and processes them, identifying HTTP requests and responses.
3. **File Extension Detection:** The script identifies specific file extensions (e.g., .exe, .pdf) within HTTP traffic.
4. **Modification and Redirection:** When a target requests a file with a designated extension, the script modifies the packet to redirect the request to a predefined URL.

## Usage
- Install the necessary dependencies using pip:
  
  ```commandline
  pip install scapy netfilterqueue
  ```
- To use the File Intercept Python Script, run the provided Python script file_intercept.py with the appropriate queue number:
  
  ```commandline
  python3 file_intercept.py --queue-num <num>
  ```
- Replace <num> with the desired queue number.

## Dependencies
- Python 3.0 or later
- scapy
- netfilterqueue
