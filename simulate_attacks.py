import json
import time

EVENT_FILE = "storage/events.jsonl"

def add_event(event):
    with open(EVENT_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

# --- fake attacker 1 ---
add_event({
    "timestamp": "2025-11-15T12:00:01",
    "type": "ssh_login",
    "ip": "23.14.55.77",
    "username": "root",
    "password": "toor"
})

add_event({
    "timestamp": "2025-11-15T12:00:04",
    "type": "ssh_command",
    "ip": "23.14.55.77",
    "command": "uname -a"
})

# --- fake attacker 2 ---
add_event({
    "timestamp": "2025-11-15T12:05:22",
    "type": "ssh_login",
    "ip": "162.19.221.44",
    "username": "admin",
    "password": "123456"
})

add_event({
    "timestamp": "2025-11-15T12:05:29",
    "type": "ssh_command",
    "ip": "162.19.221.44",
    "command": "ls /etc"
})

print("✔ Added 2 more attacker IPs directly into events.jsonl")
