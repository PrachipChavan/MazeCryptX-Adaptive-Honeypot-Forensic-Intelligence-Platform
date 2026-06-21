# MazeCryptX-Adaptive-Honeypot-Forensic-Intelligence-Platform
🛡 MazeCryptX

Adaptive Honeypot & Forensic Intelligence System

MazeCryptX is an all-in-one cybersecurity honeypot platform that simulates real-world attack surfaces (SSH & Web), captures attacker behavior, enriches it with intelligence, runs malware in a sandbox, and applies ML-based attacker persona classification — all with a live Streamlit dashboard.

🚀 Features 🔐 SSH Honeypot (Port 2222)

Fake SSH server with dynamic Linux banners

Deception-based fake login success

Semi-interactive Linux shell (ls, pwd, cd, cat, etc.)

Captures:

Login attempts

Commands executed

Session timelines

🌐 Web Honeypot (Port 8080)

Fake Online Banking Login Page

Captures:

Username & password attempts

Attacker IPs

Designed to look realistic

📡 Event Collection & Enrichment

Central event pipeline

Enriches attacker IPs with:

Country

City

ASN

Organization

VPN / Cloud detection

Stored in JSONL format for analysis

🧪 Malware Sandbox (Docker)

Executes suspicious files inside isolated Docker containers

Captures:

Network indicators

Suspicious API calls

File write activity

Auto-extracts IoCs

🧠 Machine Learning – Attacker Personas

Clusters attackers into personas using behavior patterns:

Scanner

Brute Forcer

Interactive Intruder

Features used:

SSH command count

Login attempts

Unique commands

Session duration

📊 Streamlit Dashboard (Port 8501)

Live dashboard with tabs:

📡 Live Attacks

💻 SSH Session Replay

🧪 Sandbox Output

🧠 Persona Analysis

📄 Forensic PDF Reports

📄 Forensic PDF Reports

Auto-generated per attacker IP

Includes:

GeoIP details

Full attack timeline

Predicted persona

⚙️ Requirements

Python 3.10+

Docker Desktop (running)

Windows / Linux / macOS

Python Packages pip install streamlit docker geoip2 ipwhois scikit-learn reportlab numpy

▶️ How to Run (Correct Way) 1️⃣ Start Honeypots python app.py

Starts:

SSH Honeypot → 2222

Web Honeypot → 8080

Event Collector

2️⃣ Start Dashboard (New Terminal) streamlit run dashboard.py

Dashboard URL:

http://localhost:8501

⚠️ Do NOT run streamlit run app.py

🧪 Testing Guide 🔹 SSH Honeypot

Use telnet (recommended on Windows):

telnet localhost 2222

Login multiple times (6+ attempts) to trigger deception login.

🔹 Web Honeypot

Open browser:

http://localhost:8080

Try fake credentials — attempts appear in dashboard.

🔹 Simulated Attacks python simulate_attacks.py

Injects fake attacker IPs for ML testing.

🔹 Train ML Model

Dashboard → Persona Analysis → Train ML Model

🔹 Predict Persona

Select IP → Predict Persona

🔹 Generate PDF

Dashboard → Forensic PDF → Select IP → Generate

🧹 Reset / Cleanup (Windows) taskkill /IM python.exe /F taskkill /IM streamlit.exe /F

(Optional) Clear old data:

del storage\events.jsonl del storage\persona_model.pkl

⚠️ Important Notes

SSH is NOT real SSH — OpenSSH clients will fail (expected)

Use telnet or netcat for SSH testing

Dashboard and honeypots must run in separate terminals

GeoIP database must be downloaded manually (MaxMind)

🧠 Educational Purpose

MazeCryptX is built for:

Cybersecurity learning

Honeypot research

Blue team training

SOC & DFIR simulations
