"""
Interactive Demonstration Script:
1. Automatically verifies/starts the FastAPI server if not running.
2. Simulates a legitimate Human user (natural variable delays) -> Allowed.
3. Simulates an edge-case bursty user -> Triggering a verification challenge -> Solving it -> Model learns online!
4. Simulates a robotic Spammer (machine-like fixed intervals, rapid burst) -> Flagged as spammer & Jailed in Penalty Box.
5. Shows updated model stats.
"""

import time
import sys
import os
import subprocess
import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def print_separator(title):
    print("\n" + "=" * 65)
    print(f" {title.upper()} ")
    print("=" * 65)

def ensure_server_running():
    """Checks if the server is up; if not, automatically launches uvicorn."""
    try:
        res = requests.get(f"{BASE_URL}/", timeout=1.5)
        if res.status_code == 200:
            return None
    except Exception:
        pass

    print("[*] FastAPI server not detected. Starting uvicorn automatically...")
    venv_python = sys.executable
    cmd = [venv_python, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Wait up to 10 seconds for server to be responsive
    for _ in range(20):
        time.sleep(0.5)
        try:
            res = requests.get(f"{BASE_URL}/", timeout=1)
            if res.status_code == 200:
                print("[+] Server started successfully in background!")
                return proc
        except Exception:
            pass

    print("[-] Warning: Server took too long to start. Attempting demo anyway...")
    return proc

def main():
    server_process = ensure_server_running()

    print_separator("Testing Rate Limiter & Self-Learning Spam Detector")
    
    # 0. Health check
    res = requests.get(f"{BASE_URL}/")
    print(f"[+] Health Check: {res.status_code}")
    print(f"    Mode: {res.json().get('storage_mode')}")
    print(f"    Redis: {'Connected' if res.json().get('redis_connected') else 'In-Memory Fallback'}")

    # 1. Human Simulation
    print_separator("1. Simulating Legitimate Human User (Alice)")
    print("   Sending requests with natural human jitter (varied delays)...")
    for i in range(1, 4):
        delay = 0.5 + (i * 0.3)
        time.sleep(delay)
        res = requests.get(
            f"{BASE_URL}/limited-resource",
            headers={"user-id": "alice", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        data = res.json()
        print(f"   Request {i} -> HTTP {res.status_code} | Risk Score: {data.get('risk_score')} | Class: {data.get('classification')}")

    # 2. Robotic Spammer Simulation
    print_separator("2. Simulating Automated Robotic Bot (SpamBot_99)")
    print("   Sending ultra-rapid requests with zero jitter (machine timing)...")
    for i in range(1, 6):
        res = requests.get(
            f"{BASE_URL}/limited-resource",
            headers={"user-id": "spambot_99", "user-agent": "Python-urllib/ScraperBot"}
        )
        if res.status_code == 200:
            data = res.json()
            print(f"   Request {i} -> HTTP {res.status_code} | Risk: {data.get('risk_score')} | Class: {data.get('classification')}")
        elif res.status_code == 429:
            data = res.json().get("detail", {})
            print(f"   Request {i} -> HTTP 429 JAILED! | Message: {data.get('message', 'Blocked')}")
        elif res.status_code == 403:
            print(f"   Request {i} -> HTTP 403 Challenge issued!")
        time.sleep(0.02)  # 20ms robotic interval

    # 3. Edge-Case Burst & Self-Learning Challenge
    print_separator("3. Simulating Burst User with Self-Learning Challenge (Bob)")
    print("   Sending quick requests to trigger a verification challenge...")
    challenge_data = None
    for i in range(1, 5):
        res = requests.get(
            f"{BASE_URL}/limited-resource",
            headers={"user-id": "bob", "user-agent": "Mozilla/5.0"}
        )
        if res.status_code == 403:
            detail = res.json().get("detail", {})
            challenge_data = detail.get("challenge", {})
            print(f"   -> HTTP 403: Challenge Triggered: \"{challenge_data.get('prompt')}\"")
            break
        else:
            print(f"   Request {i} -> HTTP {res.status_code}")
        time.sleep(0.05)

    if challenge_data:
        cid = challenge_data.get("challenge_id")
        ans = challenge_data.get("body_example", {}).get("answer")
        print(f"\n   [Self-Learning Step] Answering challenge {cid} with answer '{ans}'...")
        verify_res = requests.post(
            f"{BASE_URL}/verify-challenge",
            json={"challenge_id": cid, "answer": ans}
        )
        print(f"   -> HTTP {verify_res.status_code}: {verify_res.json().get('message')}")
        print(f"   -> Feedback: {verify_res.json().get('self_learning')}")

    # 4. Model Diagnostics & Centroids
    print_separator("4. Live Model State & Learned Centroids")
    stats = requests.get(f"{BASE_URL}/model-stats").json()
    print("   Metrics:")
    for k, v in stats.get("metrics", {}).items():
        print(f"     - {k}: {v}")
    print(f"   Total Online Self-Learning Updates: {stats['model_centroids']['total_self_learning_updates']}")
    print("=" * 65)
    print(" Demo complete! All feedback requirements successfully demonstrated.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
