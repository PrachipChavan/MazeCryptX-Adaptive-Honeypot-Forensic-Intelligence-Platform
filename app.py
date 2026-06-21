import os
import socket
import threading
import time
import json
import hashlib
import datetime
import subprocess
import re
import random
import traceback
import docker
import geoip2.database
import ipwhois
import streamlit as st
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sklearn.cluster import KMeans
import numpy as np
import sys
import pickle
import textwrap


# FIX STREAMLIT RECURSION (FINAL & WORKING)


# If script is being run by Streamlit, do NOT start honeypots
if any("streamlit" in arg.lower() for arg in sys.argv):
    # Only load the dashboard
    def run_dashboard_only():
        import streamlit as st
        # We must import inside this function to avoid early class crash
        from __main__ import StreamlitDashboard
        StreamlitDashboard().render()
    run_dashboard_only()
    sys.exit(0)

MODEL_FILE = "storage/persona_model.pkl"

def save_model(model):
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

def load_model():
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, "rb") as f:
            return pickle.load(f)
    return None


def safe_filename(ip: str):
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", ip)

# GLOBAL CONFIGURATION
 

CONFIG = {
    "SSH_PORT": 2222,
    "WEB_PORT": 9090,
    "DASHBOARD_PORT": 8501,
    "EVENTS_FILE": "storage/events.jsonl",
    "UPLOAD_DIR": "storage/uploads/",
    "SANDBOX_LOGS": "storage/sandbox_logs/",
    "GEOIP_DB": "GeoLite2-City.mmdb",  # You must download this
    "VERBOSE": True,

    "MAX_LOG_SIZE": 5 * 1024 * 1024,  # 5 MB
}

# Ensure folders exist
os.makedirs("storage", exist_ok=True)
os.makedirs(CONFIG["UPLOAD_DIR"], exist_ok=True)
os.makedirs(CONFIG["SANDBOX_LOGS"], exist_ok=True)

 
# UTILITY CLASSES
 

class Logger:
    """Handles verbose printing + JSONL logging."""
    
    @staticmethod
    def log(msg):
        if CONFIG["VERBOSE"]:
            print(f"[LOG] {msg}")

    @staticmethod
    def save_event(data: dict):
        try:
            file_path = CONFIG["EVENTS_FILE"]

            # ✅ Check file size
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)

                if size > CONFIG["MAX_LOG_SIZE"]:
                    timestamp = int(time.time())
                    new_name = f"storage/events_{timestamp}.jsonl"
                    os.rename(file_path, new_name)
                    print(f"[LOG] Rotated log file → {new_name}")

            # ✅ Write new event
            with open(file_path, "a") as f:
                f.write(json.dumps(data) + "\n")

        except Exception as e:
            print("[ERROR] Could not save event:", e)


class FileManager:
    """Handles file saving, SHA256 calculation."""
    
    @staticmethod
    def save_uploaded_file(ip: str, content: bytes, filename: str):
        safe_name = f"{ip}_{int(time.time())}_{filename}"
        path = os.path.join(CONFIG["UPLOAD_DIR"], safe_name)
        
        with open(path, "wb") as f:
            f.write(content)
        
        return path

    @staticmethod
    def sha256(path: str):
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()


class Enricher:
    """GeoIP + ASN + VPN/Cloud Detection."""

    def __init__(self):
        try:
            print("[DEBUG] Loading GeoIP DB from:", CONFIG["GEOIP_DB"])
            self.geo_reader = geoip2.database.Reader(CONFIG["GEOIP_DB"])
            print("[DEBUG] GeoIP DB LOADED ✅")
        except Exception as e:
            print("[ERROR] GeoIP load failed:", e)
            self.geo_reader = None

    def enrich_ip(self, ip: str):
        data = {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "asn": "Unknown",
            "org": "Unknown",
            #"is_vpn": False,
            #"is_cloud": False
        }

        # ---- GEOIP ----
        try:
            if self.geo_reader:
                print("[DEBUG] Looking up IP:", ip)
                response = self.geo_reader.city(ip)
                print("[DEBUG] RESPONSE:", response)

                data["country"] = response.country.name or "Unknown"
                data["city"] = response.city.name or "Unknown"
            else:
                print("[DEBUG] Geo reader is NONE ❌")
        except Exception as e:
                print("[ERROR GEOIP]:", e)

        # ---- ASN ----
        try:
            whois = ipwhois.IPWhois(ip).lookup_rdap()
            data["asn"] = whois.get("asn", "Unknown")
            data["org"] = whois.get("asn_description", "Unknown")
        except:
            pass

        # ---- Detect VPN/Cloud ----
        vpn_keywords = ["digitalocean", "aws", "google", "azure", "ovh", "linode"]
        org_lower = data["org"].lower() if data["org"] else ""

        #data["is_vpn"] = any(k in org_lower for k in vpn_keywords)
        #data["is_cloud"] = data["is_vpn"]  # same list for now

        return data

 
# PART 2/7 — SSH Honeypot + Web Honeypot + Deception Engine
 

class DeceptionEngine:
    """Dynamic deception logic based on attacker behavior."""
    
    def __init__(self):
        self.failed_logins = {}
        self.open_ports = set()

    def record_failed_login(self, ip):
        self.failed_logins[ip] = self.failed_logins.get(ip, 0) + 1

        # Fake successful login if brute-forced many times
        if self.failed_logins[ip] > 5:
            Logger.log(f"[DECEPTION] Triggering fake success for {ip}")
            return True
        return False

    def get_dynamic_banner(self):
        banners = [
            "Ubuntu 22.04 LTS",
            "Ubuntu 20.04 LTS",
            "Debian GNU/Linux 11",
            "OpenSSH_8.9"
        ]
        return random.choice(banners)


class SSHHoneypot:
    """Fake SSH server with semi-intelligent shell."""

    def __init__(self, port=2222, deception=None):
        self.port = port
        self.deception = deception or DeceptionEngine()
        self.shell_state = {}  # track "current directory" for fake shell

    def start(self):
        thread = threading.Thread(target=self.run_server, daemon=True)
        thread.start()
        Logger.log(f"[SSH] Honeypot started on port {self.port}")

    def run_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", self.port))
        sock.listen(100)

        while True:
            conn, addr = sock.accept()
            ip = addr[0]
            Logger.log(f"[SSH] Incoming connection from {ip}")
            threading.Thread(target=self.handle_client, args=(conn, ip), daemon=True).start()

    def handle_client(self, conn, ip):
        try:
            # Send fake SSH banner (protocol expects \r\n here)
            banner = self.deception.get_dynamic_banner()
            conn.sendall(f"SSH-2.0-{banner}\r\n".encode())

            # Fake username/password prompt
            conn.sendall(b"login: ")
            username = self.recv_line(conn)

            conn.sendall(b"password: ")
            password = self.recv_line(conn)

            Logger.log(f"[SSH] {ip} attempted login: {username}/{password}")

            # Save event
            collector_instance.add_event({
                "timestamp": self.now(),
                "type": "ssh_login",
                "ip": ip,
                "username": username,
                "password": password
            })

            # Check deception
            success = self.deception.record_failed_login(ip)

            if success:
                conn.sendall(b"Login successful.\n")
                self.fake_shell(conn, ip)
            else:
                conn.sendall(b"Login incorrect.\n")
                conn.close()
        except:
            conn.close()

    def clean_command(self, cmd):
        # Remove escape sequences like ^[[A, etc.
        cmd = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', cmd)

        # Remove [C, [D, [A, [B — arrow keys from Windows Telnet
        cmd = re.sub(r'\[[A-D]', '', cmd)

        # Remove unknown characters (the ■ character on Windows)
        cmd = cmd.replace("■", "")

        # Remove backspaces and characters before them
        while "\x08" in cmd:
            bs_index = cmd.find("\x08")
            if bs_index > 0:
                cmd = cmd[:bs_index-1] + cmd[bs_index+1:]
            else:
                cmd = cmd[bs_index+1:]

        # Strip leftover control characters
        cmd = re.sub(r'[\x00-\x1f\x7f]', '', cmd)

        return cmd.strip()

    def fake_shell(self, conn, ip):
        """Semi-intelligent fake Linux shell with clean prompt formatting."""
        cwd = "/home/root"
        self.shell_state[ip] = cwd

        conn.sendall(f"Last login: {self.now()} from {ip}\n".encode())

        while True:
            try:
                prompt = f"root@server:{cwd}# "
                # IMPORTANT: no '\r' here to avoid shifted prompt on Windows SSH
                conn.sendall(prompt.encode())

                raw_cmd = self.recv_line(conn)
                cmd = self.clean_command(raw_cmd)

                if not cmd:
                    break

                Logger.log(f"[SSH][CMD] {ip}: {cmd}")

                collector_instance.add_event({
                    "timestamp": self.now(),
                    "type": "ssh_command",
                    "ip": ip,
                    "cwd": cwd,
                    "command": cmd
                })

                # ---- Semi-Intelligent Shell Responses ----
                if cmd.startswith("cd"):
                    parts = cmd.split()
                    if len(parts) > 1:
                        cwd = parts[1]
                    conn.sendall(b"\n")

                elif cmd == "pwd":
                    conn.sendall(f"{cwd}\n".encode())

                elif cmd == "ls":
                    fake_files = ["syslog", "server.conf", "note.txt", "config.ini"]
                    conn.sendall(("\n".join(fake_files) + "\n").encode())

                elif cmd.startswith("cat"):
                    conn.sendall(b"root:x:0:0:root:/root:/bin/bash\n")

                # ✅ FIXED SANDBOX BLOCK
                elif "wget" in cmd or "curl" in cmd:
                    conn.sendall(b"Downloading file...\n")
                    time.sleep(1)

                    conn.sendall(b"\n100% [==================>] 1.2K --.-KB/s in 0s\n\n")
                    time.sleep(0.5)

                    conn.sendall(b"Download completed.\n")
                    time.sleep(1)

                    conn.sendall(b"Executing file...\n")

                    fake_path = f"storage/uploads/{ip}_malware.py"
                    

                    with open(fake_path, "w") as f:
                        f.write(textwrap.dedent("""
                            import os
                            import socket
                            import subprocess

                            print("Malware executed")

                            os.system("echo hacked from attacker")

                            print("Connection attempt created")

                            output = subprocess.check_output("whoami", shell=True).decode()
                            print(output.strip())
                        """))
                    
                    sandbox = SandboxRunner()
                    result = sandbox.run_in_sandbox(ip, fake_path)

                    conn.sendall(b"Execution finished.\n\n")

                    if result.get("output"):
                        preview = result["output"][:200]
                        # ✅ CLEAN OUTPUT
                        clean_output = preview.replace("\r", "")
                        clean_output = "\n".join(line.strip() for line in clean_output.splitlines())
                        conn.sendall(preview.encode())
                    else:
                        conn.sendall(b"No visible output.\n")

                    conn.sendall(b"\n")


                    Logger.log(f"[SANDBOX RESULT] {result}")

                    conn.sendall(b"File downloaded and executed.\n")

                elif cmd in ["exit", "quit"]:
                    conn.sendall(b"logout\n")
                    break

                else:
                    conn.sendall(b"bash: command not found\n")

            except Exception as e:
                Logger.log(f"[SSH] Shell error: {e}")
                break

    def recv_line(self, conn):
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
        return data.strip().decode(errors="ignore")

    def now(self):
        return datetime.datetime.utcnow().isoformat()

 
# Web Honeypot (Fake Login Form)
 

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

WEB_ATTACK_STATE = {}

WEB_ATTACK_STATE = {}

class WebHandler(BaseHTTPRequestHandler):

    # ---------------- LOGIN PAGE ----------------
    def do_GET(self):
        ip = self.headers.get("X-Forwarded-For", self.client_address[0])

        collector_instance.add_event({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "type": "web_scan",
            "ip": ip,
            "path": self.path
        })
        html = """
<html>
<head>
<title>Secure Online Banking</title>

<style>
body {
    font-family: Arial, sans-serif;
    background: #f2f2f2;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
}
.login-box {
    background: white;
    padding: 35px;
    width: 350px;
    border-radius: 10px;
    box-shadow: 0 0 20px rgba(0,0,0,0.15);
}
.login-box h2 {
    text-align: center;
    margin-bottom: 20px;
    color: #0033a0;
}
input {
    width: 100%;
    padding: 12px;
    margin: 8px 0;
    border: 1px solid #ccc;
    border-radius: 6px;
}
input[type=submit] {
    background: #0033a0;
    color: white;
    cursor: pointer;
}
</style>
</head>

<body>
<div class="login-box">

<h2>Online Banking Login</h2>

<form method="post">
    <input type="text" name="u" placeholder="Customer ID">
    <input type="password" name="p" placeholder="Password">
    <input type="submit" value="Login">
</form>

</div>
</body>
</html>
"""
        self.respond(200, html)

    # ---------------- POST ----------------
    def do_POST(self):
        length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(length).decode()

        # ===== HANDLE TRANSFER =====
        if "transfer=1" in post_data:
            data = urllib.parse.parse_qs(post_data)

            ip = self.headers.get("X-Forwarded-For", self.client_address[0])

            acc_no = data.get("acc_no", [""])[0]
            ifsc = data.get("ifsc", [""])[0]
            amount = data.get("amount", [""])[0]

            Logger.log(f"[WEB][TRANSFER] {ip} → {acc_no} | {ifsc} | ₹{amount}")

            collector_instance.add_event({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "type": "fake_transfer",
                "ip": ip,
                "account": acc_no,
                "ifsc": ifsc,
                "amount": amount
            })

            return self.respond(200, f"""
            <h2 style='color:green;'>Transfer Successful ✅</h2>
            <p>₹{amount} sent to account {acc_no}</p>
            <a href="/">Back to Login</a>
            """)

        # ===== LOGIN =====
        data = urllib.parse.parse_qs(post_data)

        username = data.get("u", [""])[0]
        password = data.get("p", [""])[0]
        ip = self.headers.get("X-Forwarded-For", self.client_address[0])

        if ip not in WEB_ATTACK_STATE:
            WEB_ATTACK_STATE[ip] = {"attempts": 0, "logged_in": False}

        state = WEB_ATTACK_STATE[ip]
        state["attempts"] += 1

        Logger.log(f"[WEB] {ip} attempt {state['attempts']} → {username}/{password}")

        collector_instance.add_event({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "type": "web_login",
            "ip": ip,
            "username": username,
            "password": password,
            "attempt": state["attempts"]
        })

        # ❌ Fail first 5 attempts
        if state["attempts"] < 6:
            return self.respond(200, f"""
            <h3 style='color:red;'>Invalid login ❌ (Attempt {state['attempts']}/5)</h3>
            <a href="/">Try again</a>
            """)

        # ✅ Success
        return self.fake_user_panel(username)

    # ---------------- USER PANEL ----------------
    def fake_user_panel(self, username):
        acc_no = random.randint(1000000000, 9999999999)

        html = f"""
<html>
<head>
<title>MyBank Dashboard</title>

<style>
body {{
    font-family: Arial;
    background: #eef2f7;
}}

.container {{
    width: 500px;
    margin: 50px auto;
    background: white;
    padding: 20px;
    border-radius: 10px;
}}

input {{
    width: 100%;
    padding: 10px;
    margin: 10px 0;
}}

button {{
    background: #007bff;
    color: white;
    padding: 10px;
    border: none;
    width: 100%;
}}
</style>
</head>

<body>

<div class="container">
    <h2>Welcome, {username}</h2>
    <p><b>Account No:</b> {acc_no}</p>
    <p><b>Balance:</b> ₹{random.randint(20000,100000)}</p>

    <h3>Transfer Money</h3>

    <form method="post">
        <input type="hidden" name="transfer" value="1">

        <label>Account Number</label>
        <input name="acc_no" required>

        <label>IFSC Code</label>
        <input name="ifsc" required>

        <label>Amount</label>
        <input name="amount" type="number" required>

        <button type="submit">Transfer</button>
    </form>
</div>

</body>
</html>
"""
        return self.respond(200, html)

    # ---------------- RESPONSE ----------------
    def respond(self, code, content):
        self.send_response(code)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))
class WebHoneypot:
    def __init__(self, port=9090):
        self.port = port

    def start(self):
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        Logger.log(f"[WEB] Honeypot started on port {self.port}")

    def run(self):
        server = HTTPServer(("0.0.0.0", self.port), WebHandler)
        server.serve_forever()

 
# PART 3/7 — Event Collector + Enrichment Integration (FIXED)
 

class EventCollector:
    """Central pipeline that receives events from honeypots,
    enriches them with GeoIP & ASN info, and stores them."""

    def __init__(self):
        self.enricher = Enricher()
        self.queue = []
        self.lock = threading.Lock()

    def add_event(self, event: dict):
        """Add an event to internal queue before processing."""
        with self.lock:
            self.queue.append(event)

    def start(self):
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        Logger.log("[COLLECTOR] Collector thread started.")

    def run(self):
        while True:
            if self.queue:
                with self.lock:
                    event = self.queue.pop(0)

                ip = event.get("ip", "")

                # Enrich IP
                enriched = self.enricher.enrich_ip(ip)

                # Merge collected + enriched data
                merged = {**event, **enriched}

                # ❌ permanently remove vpn/cloud fields
                for field in ["is_vpn", "is_cloud", "vpn_confidence", "connection_type"]:
                    if field in merged:
                        del merged[field]

                # ML persona auto-tagging
                persona = PersonaClassifier().predict(ip)
                merged["persona"] = persona

                # FINAL OUTPUT → write to file (NO LOOP)
                Logger.save_event(merged)
                Logger.log(f"[COLLECTOR] Saved enriched event from {ip}")

            time.sleep(0.1)

# Global collector instance used by all modules
collector_instance = EventCollector()
collector_instance.start()

 
# PART 4/7 — Docker Sandbox Runner + Behavior Parser
 

class SandboxRunner:
    """Executes suspicious files inside an isolated Docker container."""

    def __init__(self):
        try:
            self.client = docker.from_env()
            Logger.log("[SANDBOX] Docker client initialized.")
        except Exception as e:
            Logger.log(f"[SANDBOX] Docker not available: {e}")
            self.client = None

    def run_in_sandbox(self, ip: str, file_path: str):
        """Run file inside a Docker container and capture its behavior."""
        
        if not self.client:
            Logger.log("[SANDBOX] Docker unavailable, skipping execution.")
            return {"error": "Docker not installed"}

        try:
            Logger.log(f"[SANDBOX] Starting sandbox for file: {file_path}")

            # Copy file into sandbox directory
            filename = os.path.basename(file_path)
            target_path = f"/tmp/{filename}"

            # Start a temporary container
            container = self.client.containers.run(
                "python:3.10-slim",
                command="sleep 9999",
                detach=True,
                tty=True
            )

            Logger.log(f"[SANDBOX] Container started: {container.short_id}")

            # Copy file to container
            with open(file_path, "rb") as f:
                container.put_archive("/tmp", self._tar_bytes(filename, f.read()))

            # Execute file inside the container
            exec_result = container.exec_run(
                cmd=f"timeout 5 sh -c 'python3 {target_path} && ls /tmp && cat /etc/passwd'",
                stdout=True,
                stderr=True,
            )

            output = exec_result.output.decode(errors="ignore")

            # Save sandbox logs
            log_path = os.path.join(CONFIG["SANDBOX_LOGS"], f"{ip}_{int(time.time())}.log")
            with open(log_path, "w") as f:
                f.write(output)

            Logger.log(f"[SANDBOX] Log saved: {log_path}")

            container.kill()
            container.remove()
            Logger.log("[SANDBOX] Container cleaned.")

            return {
                "log_file": log_path,
                "output": output
            }

        except Exception as e:
            return {"error": str(e)}

    def _tar_bytes(self, name, data):
        """Creates tar archive in-memory for copying to container."""
        import io, tarfile
        tarstream = io.BytesIO()
        tar = tarfile.TarFile(fileobj=tarstream, mode='w')
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        tar.close()
        tarstream.seek(0)
        return tarstream


class SandboxParser:
    """Parses sandbox output and extracts IoC indicators."""

    @staticmethod
    def parse_log(log_text: str):
        """Extract basic IoCs from sandbox log."""
        iocs = {
            "domains": re.findall(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", log_text),
            "ips": re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text),
            "suspicious_calls": [],
            "file_writes": [],
        }

        # Detect suspicious calls
        suspicious_keywords = ["subprocess", "socket", "connect", "exec", "chmod"]
        for keyword in suspicious_keywords:
            if keyword in log_text:
                iocs["suspicious_calls"].append(keyword)

        # Detect file writes
        file_write_patterns = re.findall(r"opened file (\/.*?) ", log_text)
        iocs["file_writes"] = list(set(file_write_patterns))

        return iocs

    @staticmethod
    def generate_summary(output: str, iocs: dict):
        """Creates a human-readable summary for dashboard + PDF."""
        summary = f"""
--- SANDBOX SUMMARY ---
Output:
{output}

Indicators of Compromise:
Domains: {iocs['domains']}
IPs: {iocs['ips']}
Suspicious API Calls: {iocs['suspicious_calls']}
File Writes: {iocs['file_writes']}
"""
        return summary

 
# PART 5/7 — Machine Learning: Feature Extraction + Persona Clustering
 

class FeatureExtractor:
    """Converts attacker logs into ML-ready numeric features."""

    @staticmethod
    def load_events():
        """Reads all enriched events from JSONL file."""
        events = []
        if not os.path.exists(CONFIG["EVENTS_FILE"]):
            return events

        with open(CONFIG["EVENTS_FILE"], "r") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except:
                    pass
        return events

    def extract_features(self):
        """Extract aggregated features per attacker IP."""
        events = self.load_events()
        features = {}

        for e in events:
            ip = e.get("ip")
            if not ip:
                continue

            if ip not in features:
                features[ip] = {
                    "ssh_commands": 0,
                    "web_attempts": 0,
                    "web_scans": 0,
                    "failed_logins": 0,
                    "unique_commands": set(),
                    "timestamps": [],
                }

            # Track timestamps
            if e.get("timestamp"):
                features[ip]["timestamps"].append(e["timestamp"])

            # SSH command count
            if e.get("type") == "ssh_command":
                features[ip]["ssh_commands"] += 1
                features[ip]["unique_commands"].add(e.get("command", ""))

            # Web login attempts
            if e.get("type") == "web_login":
                features[ip]["web_attempts"] += 1

            # Failed SSH login
            if e.get("type") == "ssh_login":
                features[ip]["failed_logins"] += 1

            if e.get("type") == "web_scan":
                features[ip]["web_scans"] += 1

        # Convert to ML feature vectors
        dataset = []
        ips = []

        for ip, data in features.items():
            timestamps = sorted(data["timestamps"])
            duration = 0

            if len(timestamps) >= 2:
                t1 = datetime.datetime.fromisoformat(timestamps[0])
                t2 = datetime.datetime.fromisoformat(timestamps[-1])
                duration = (t2 - t1).total_seconds()

            dataset.append([
                data["ssh_commands"],
                data["web_attempts"],
                data["web_scans"],
                data["failed_logins"],
                len(data["unique_commands"]),
                duration
            ])
            ips.append(ip)

        return np.array(dataset), ips


class PersonaClassifier:
    """ML model that clusters attackers into behavioral personas."""

    def __init__(self):
        self.model = None

    def train(self):
        fe = FeatureExtractor()
        X, ips = fe.extract_features()

        if len(X) < 3:
            Logger.log("[ML] Not enough data to train model.")
            return None

        # Train KMeans
        self.model = KMeans(n_clusters=3, random_state=0)
        labels = self.model.fit_predict(X)
        save_model(self.model)

        persona_map = {
            0: "Scanner",
            1: "Brute Forcer",
            2: "Interactive Intruder"
        }

        results = {}
        for ip, label in zip(ips, labels):
            results[ip] = persona_map[label]

        Logger.log("[ML] Persona clustering complete.")
        return results

    def predict(self, ip: str):
        """Predict persona for a specific IP."""
        if not self.model:
            self.model = load_model()
            if not self.model:
                return "Unknown"
        fe = FeatureExtractor()
        X, ips = fe.extract_features()

        if ip not in ips:
            return "Unknown"

        index = ips.index(ip)
        label = self.model.predict([X[index]])[0]

        persona_map = {
            0: "Scanner",
            1: "Brute Forcer",
            2: "Interactive Intruder"
        }

        return persona_map.get(label, "Unknown")

 
# PART 6/7 — Streamlit Dashboard UI
 

class StreamlitDashboard:
    """Interactive dashboard for live attacks, sandbox logs, and PDF reports."""

    def __init__(self):
        self.sandbox_parser = SandboxParser()
        self.ml_model = PersonaClassifier()

    def load_events(self):
        events = []
        if os.path.exists(CONFIG["EVENTS_FILE"]):
            with open(CONFIG["EVENTS_FILE"], "r") as f:
                for line in f:
                    try:
                        events.append(json.loads(line))
                    except:
                        pass
        return events

    def start(self):
        """Runs Streamlit in a separate thread."""
        thread = threading.Thread(target=self.run_streamlit, daemon=True)
        thread.start()
        Logger.log("[DASHBOARD] Streamlit dashboard launched.")

    def run_streamlit(self):
        """Launches the Streamlit UI."""
        import os
        cmd = f"streamlit run {os.path.abspath(__file__)} --server.port={CONFIG['DASHBOARD_PORT']}"
        os.system(cmd)

    # ------------------------------------------------------------
    # STREAMLIT PAGE LAYOUT
    # ------------------------------------------------------------
    def render(self):
        st.set_page_config(page_title="MazeCryptX Dashboard", layout="wide")
        st.title("🛡 MazeCryptX – Adaptive Honeypot & Forensic Intelligence Dashboard")

        tabs = st.tabs(["📡 Live Attacks", "💻 Session Replay", "🧪 Sandbox Output", 
                        "🧠 Persona Analysis", "📄 Forensic PDF"])

        # ========================================================
        # TAB 1: LIVE ATTACKS
        # ========================================================
        with tabs[0]:
            st.header("📡 Live Attack Feed")

            events = self.load_events()
            events_sorted = sorted(
                events,
                key=lambda x: x.get("timestamp", ""),
                reverse=True   # 🔥 IMPORTANT
            )

            if events_sorted:
                # Fields you want to HIDE
                hide_fields = []
                df_display = [
                    {k: v for k, v in e.items() if k not in hide_fields}
                    for e in events_sorted
                ]

                st.dataframe(df_display)
            else:
                st.info("No events yet.")

        # ========================================================
        # TAB 2: SESSION REPLAY
        # ========================================================
        with tabs[1]:
            st.header("💻 SSH Session Replay")

            events = self.load_events()
            ips = list(set(e["ip"] for e in events if "ip" in e))

            if ips:
                selected_ip = st.selectbox("Select Attacker IP", ips)

                if selected_ip:
                    session_cmds = [
                        e for e in events
                        if e.get("ip") == selected_ip and e.get("type") == "ssh_command"
                    ]

                    for e in session_cmds:
                        st.markdown(f"**{e['timestamp']}** — `{e['command']}`")
            else:
                st.info("No SSH sessions yet.")

        # ========================================================
        # TAB 3: SANDBOX OUTPUT
        # ========================================================
        with tabs[2]:
            st.header("🧪 Sandbox Execution Logs")

            log_files = os.listdir(CONFIG["SANDBOX_LOGS"])
            log_files = [f for f in log_files if f.endswith(".log")]

            if log_files:
                selected_file = st.selectbox("Select Sandbox Log", log_files)

                if selected_file:
                    with open(os.path.join(CONFIG["SANDBOX_LOGS"], selected_file), "r") as f:
                        content = f.read()

                    st.subheader("Raw Output")
                    st.code(content)

                    # IoC parsing
                    iocs = self.sandbox_parser.parse_log(content)
                    st.subheader("Extracted IoCs")
                    st.json(iocs)

            else:
                st.info("No sandbox logs yet.")

        # ========================================================
        # TAB 4: ML PERSONA ANALYSIS  (FIXED WITH SESSION_STATE)
        # ========================================================
        with tabs[3]:
            st.header("🧠 Attacker Persona Analysis")

            # Initialize session_state model
            if "trained_model" not in st.session_state:
                st.session_state.trained_model = None

            # Train Model Button
            if st.button("Train ML Model"):
                results = self.ml_model.train()
                if results:
                    st.success("Model trained successfully.")
                    st.json(results)

                    # Save model into Streamlit session
                    st.session_state.trained_model = self.ml_model.model
                else:
                    st.error("Not enough data to train ML model.")

            # Load event IP list
            events = self.load_events()
            ips = list(set(e["ip"] for e in events if "ip" in e))

            if ips:
                selected_ip = st.selectbox("Predict Persona for IP", ips)

                if st.button("Predict Persona"):
                    # Restore model if trained earlier
                    if st.session_state.trained_model:
                        self.ml_model.model = st.session_state.trained_model

                    persona = self.ml_model.predict(selected_ip)
                    st.write(f"### Persona: **{persona}**")
            else:
                st.info("No IPs available for persona prediction.")

        # ========================================================
        # TAB 5: PDF FORENSIC REPORT GENERATION
        # ========================================================
        with tabs[4]:
            st.header("📄 Generate Forensic Report")

            events = self.load_events()
            ips = list(set(e["ip"] for e in events if "ip" in e))

            if ips:
                selected_ip = st.selectbox("Select IP for Forensic Report", ips)

                if selected_ip and st.button("Generate PDF"):
                    pdf_path = PDFReportBuilder().generate_pdf(selected_ip)
                    st.success(f"PDF Report generated: {pdf_path}")
                    with open(pdf_path, "rb") as f:
                        st.download_button("Download Report", f, file_name=os.path.basename(pdf_path))
            else:
                st.info("No IPs to generate reports for.")

 
# PART 7/7 — PDF Report Generator + AppManager + MAIN()
 

class PDFReportBuilder:
    """Generates a forensic PDF report for each attacker."""

    def __init__(self):
        pass

    def generate_pdf(self, ip: str):
        safe_ip = safe_filename(ip)
        file_path = f"storage/forensic_{safe_ip}_{int(time.time())}.pdf"

        c = canvas.Canvas(file_path, pagesize=A4)

        events = FeatureExtractor().load_events()
        ip_events = [e for e in events if e.get("ip") == ip]
        # Header
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, 800, "MazeCryptX Forensic Report")

        c.setFont("Helvetica", 12)
        c.drawString(50, 780, f"Attacker IP: {ip}")
        c.drawString(50, 765, f"Generated: {datetime.datetime.utcnow()}")

        # GeoIP Information
        if ip_events:
            ev = ip_events[-1]
            c.drawString(50, 740, f"Country: {ev.get('country', 'N/A')}")
            c.drawString(50, 725, f"City: {ev.get('city', 'N/A')}")
            c.drawString(50, 710, f"ASN: {ev.get('asn', 'N/A')}")
            c.drawString(50, 695, f"Org: {ev.get('org', 'N/A')}")

        # Commands / Web logins
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, 650, "Attack Timeline:")
        c.setFont("Helvetica", 10)

        y = 630
        for e in ip_events:
            line = f"{e.get('timestamp')} — {e.get('type')}"

            if e.get("type") == "ssh_command":
                line += f" → {e.get('command')}"
            if e.get("type") == "web_login":
                line += f" → {e.get('username')}/{e.get('password')}"

            c.drawString(50, y, line)
            y -= 12
            if y < 50:
                c.showPage()
                y = 800

        # ML Persona
        model = PersonaClassifier()
        persona = model.predict(ip)

        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y - 20, f"Predicted Persona: {persona}")

        c.save()
        return file_path

 
# APP MANAGER — Starts SSH, Web, Dashboard
 

class AppManager:
    """Coordinates all components and runs the entire system."""

    def __init__(self):
        self.ssh = SSHHoneypot(port=CONFIG["SSH_PORT"])
        self.web = WebHoneypot(port=CONFIG["WEB_PORT"])
        # Dashboard is NOT launched from here anymore
        Logger.log("[SYSTEM] Dashboard must be started using: streamlit run app.py")

    def start(self):
        Logger.log("[SYSTEM] Starting MazeCryptX services...")

        # Start honeypots
        self.ssh.start()
        self.web.start()

        Logger.log("[SYSTEM] All services started!")
        Logger.log("[SYSTEM] SSH Honeypot → port {}".format(CONFIG["SSH_PORT"]))
        Logger.log("[SYSTEM] Web Honeypot → port {}".format(CONFIG["WEB_PORT"]))
        Logger.log("[SYSTEM] Dashboard → port {}".format(CONFIG["DASHBOARD_PORT"]))

        # Keep main thread alive
        while True:
            time.sleep(1)

 
# MAIN ENTRY POINT
 

if __name__ == "__main__":
    manager = AppManager()
    manager.start()
