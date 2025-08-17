Reconnoise: The Stealthy Reconnaissance Framework
   ____                            _   _
  |  _ \ ___  ___ ___  _ __   ___ | \ | | _____      __
  | |_) / _ \/ __/ _ \| '_ \ / _ \|  \| |/ _ \ \ /\ / /
  |  _ <  __/ (_| (_) | | | | (_) | |\  |  __/\ V  V /
  |_| \_\___|\___\___/|_| |_|\___/|_| \_|\___| \_/\_/

A network scanner that hides in plain sight.

📖 Table of Contents
Overview

Key Features

How It Works: A Deep Dive

Project Structure

Installation & Setup

Usage & Commands

Example Scans

Extending Reconnoise

Future Work

Disclaimer

📜 Overview
Reconnoise is a Python-based network reconnaissance framework designed for a single, critical purpose: stealth. In an era where modern security tools like Intrusion Detection Systems (IDS), Intrusion Prevention Systems (IPS), and firewalls can instantly detect traditional port scans, this tool takes a fundamentally different approach.

Instead of sending obvious scanning packets, it leverages the concept of network steganography. It camouflages its scanning activity inside a stream of legitimate-looking "cover traffic" that mimics popular, high-volume applications. This allows it to slowly and methodically identify open ports and services on a target system without triggering the signature-based or anomaly-based alerts that would catch a tool like Nmap.

This tool is built for environments where discretion is paramount, such as long-term penetration tests, red team engagements, or any scenario where avoiding detection is the primary objective.

✨ Key Features
🎭 Profile-Based Mimicry: Disguises scan traffic to look statistically identical to legitimate applications like Netflix, Zoom, or online games.

🤫 Stealthy Probe Injection: Subtly weaves TCP/UDP probes into the decoy traffic stream, ensuring they are indistinguishable from normal application packets.

🛡️ Advanced IDS/IPS Evasion: Specifically designed to bypass both signature-based (e.g., "Nmap scan detected") and volume-based (e.g., "high connection rate") security alerts.

🧩 Modular & Extensible: The framework is built in Python, making it simple to create new traffic profiles to mimic any application, expanding the tool's versatility.

🐍 Pure Python: Has no external dependencies for its core functionality, ensuring it is lightweight, portable, and easy to set up in any environment with Python 3.

⚡ Threaded for Efficiency: Utilizes multithreading for efficient scanning of multiple ports, balancing speed with stealth.

⚙️ How It Works: A Deep Dive
The methodology is a multi-stage process designed to be deliberate and undetectable.

Phase 1: Profile Selection (The Disguise)
The user selects a "cover traffic" profile. This profile is more than just a name; it's a detailed blueprint of an application's network behavior, containing data on typical packet sizes, the precise time interval between packets, and the common source/destination ports.

Phase 2: Decoy Traffic Generation (The Cover Story)
Using the selected profile, the tool begins generating a continuous stream of decoy packets. If the "Netflix" profile is chosen, it sends packets to the target on port 443 at a rhythm that perfectly mimics an encrypted video stream. To a monitoring system, this activity is indistinguishable from a user watching a movie.

Phase 3: Probe Injection (The Hidden Message)
The Probe Injection Engine is the core of the operation. As the decoy traffic flows, the engine waits for the precise, pre-calculated moment to substitute a decoy packet with a real probe. For example, it might inject a TCP SYN packet destined for port 3389 (RDP). This probe is carefully timed to maintain the rhythm of the cover traffic.

Phase 4: Response Analysis (The Secret Listener)
The Response Analyzer listens for replies from the target. It's programmed to ignore all the "noise" and specifically watch for two subtle signals:

A SYN/ACK response, indicating a TCP port is OPEN.

An ICMP "Port Unreachable" message, indicating a UDP port is CLOSED.

Phase 5: Reporting (The Intelligence)
This process repeats slowly over time for each port in the target list. Once complete, the tool compiles a report of the open ports it discovered. The key success metric is not speed, but the complete absence of security alerts.

📂 Project Structure
reconnoise/
├── reconnoise.py             # Main application entry point and CLI handler
├── requirements.txt          # (Empty, no external dependencies needed)
├── scanner/                  # Core scanning engine
│   ├── __init__.py
│   ├── scheduler.py          # Manages and schedules all scan jobs using a thread pool
│   ├── injector.py           # Connects to the target and injects probes
│   ├── fingerprint.py        # Analyzes responses to identify service signatures
│   └── collector.py          # Collects, aggregates, and processes scan results
├── profiles/                 # Application traffic profiles (the "disguises")
│   ├── __init__.py
│   ├── base.py               # Abstract base class for all profiles
│   ├── netflix.py
│   ├── zoom.py
│   └── fortnite.py
|└── utils/                    # Helper utilities
|   ├── __init__.py
|   ├── parser.py             # Parses command-line arguments (ports, etc.)
|   ├── network.py            # Network helper functions (IP validation, etc.)
|   └── logger.py             # Logging configuration
|
|_____moduleas/
      |_exmaple_module.py

      
🚀 Installation & Setup
Prerequisites
Python 3.6+

Installation
Clone the repository:

git clone [https://github.com/your-username/reconnoise.git](https://github.com/your-username/reconnoise.git)
cd reconnoise

Make the script executable (Recommended):
This allows you to run the tool from within its directory using ./reconnoise.py.

chmod +x reconnoise.py

Creating a Global Command (Linux/macOS)
To run reconnoise from any directory without typing python3 or ./, you can create a system-wide command.

Step 1 – Create and open the wrapper file

sudo nano /usr/local/bin/reconnoise

Step 2 – Add the following content:

#!/usr/bin/env bash
PROJECT_DIR="/home/kali/reconnoise"
PYTHONPATH="$PROJECT_DIR" python3 "$PROJECT_DIR/reconnoise.py" "$@"

⚠️ Important: Make sure /home/kali/reconnoise is the correct, absolute path to your project folder. If your username is different, replace kali with your username.

Step 3 – Save & Exit
Press:

CTRL + O → Enter

CTRL + X → Exit

Step 4 – Make it executable

sudo chmod +x /usr/local/bin/reconnoise

Step 5 – Test
Now you can run the tool from anywhere in your terminal:

reconnoise --target 192.168.1.1 --profile netflix -p 443

✅ This wrapper automatically sets the PYTHONPATH so Python can find the scanner, utils, and profiles modules correctly.

📋 Usage & Commands
The script requires a target (-t or --target) and ports (-p or --ports) to run.

Argument

Long Version

Description

-t

--target

(Required) The target IP address or hostname to scan.

-p

--ports

(Required) The port(s) to scan. Can be a single port (80), a comma-separated list (80,443), a range (1-1024), or a combination.

--profile



Use a specific traffic profile for stealth. Choices: netflix, zoom, fortnite. If omitted, a standard, non-stealthy scan is performed.

--threads



Number of concurrent threads to use for scanning. (Default: 10).

--timeout



Connection timeout in seconds for each probe. (Default: 5).

--output



Save the final scan results to a specified JSON file.

-v

--verbose

Enable detailed, real-time logging. Extremely useful for debugging and seeing the scanner's actions step-by-step.

--version



Show the tool's current version and exit.

-h

--help

Display this help message with all commands and examples.

🎯 Example Scans
1. Basic Default Scan
A standard, non-stealthy scan for common web ports. Good for quick checks in a lab environment where stealth is not required.

reconnoise -t example.com -p 80,443

2. Stealth Scan with a Profile
A stealthy scan for RDP (3389) and SMB (445) on an internal server, hiding the traffic inside what looks like a Zoom call.

reconnoise -t 10.10.10.50 --profile zoom -p 3389,445

3. Advanced Scan with Verbose Output
Scan a wide range of ports on a target using 50 threads for speed, enabling verbose output to monitor progress, and saving the final report to a file.

reconnoise -t internal.server.lan -p 1-4000 --threads 50 --output report.json -v

🔧 Extending Reconnoise
The true power of this framework lies in its extensibility. Creating a new traffic profile is straightforward:

Capture Traffic: Use a tool like Wireshark to capture a sample of the application traffic you want to mimic. Analyze its patterns (average packet size, timing, ports).

Create Profile File: Create a new Python file in the profiles/ directory (e.g., spotify.py).

Implement the Class: Create a class that inherits from BaseProfile (from profiles/base.py).

Define Methods: Implement the required methods (get_probes, analyze_response, etc.) to generate probes and analyze responses that match the captured traffic patterns.

Register Profile: Import your new profile into reconnoise.py and add an instance of it to the self.profiles dictionary in the Reconnoise class __init__ method.

🗺️ Roadmap / Future Work
[ ] More Traffic Profiles: Add profiles for Spotify, Slack, Windows Update, and other common protocols.

[ ] Vulnerability Integration: Connect service version findings to a CVE database to report potential vulnerabilities.

[ ] GUI Development: Build a simple graphical user interface (GUI) for easier use.

[ ] Enhanced Reporting: Add options to export results as professional HTML or PDF reports.

[ ] IPv6 Support: Add the capability to scan IPv6 targets.

⚠️ Disclaimer
This tool is intended for educational purposes, security research, and authorized penetration testing only. The techniques implemented in this tool (network steganography, IDS evasion) are for academic and professional security assessment.

Using this tool to scan networks without explicit, written permission from the network owner is illegal and unethical. The developers are not responsible for any misuse or damage caused by this tool. Always respect the law and ethical guidelines.
