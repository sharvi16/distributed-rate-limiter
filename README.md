# Distributed Rate Limiter & Multi-Tier Abuse Defense System

An enterprise-grade, distributed rate limiting and anti-abuse architecture built with **FastAPI**, **Redis**, the **Token Bucket algorithm**, and an **Online Self-Learning Anomaly Detection Engine**.

---

## 🌟 Security Architecture & Defenses

```mermaid
flowchart TD
    Req[Incoming Request] --> PenaltyCheck{Tier 0: Penalty Box Check <br> User, IP, or Device Jailed?}
    
    PenaltyCheck -->|Jailed| BlockJail[HTTP 429: Access Blocked in Penalty Box]
    PenaltyCheck -->|Clean| VPNHopping{Tier 1: VPN Hopping Check <br> >2 distinct IPs for single device in 60s?}
    
    VPNHopping -->|Yes: VPN Churn| JailDevice[HTTP 429: VPN Hopping Detected! <br> Device Jailed for 120s]
    VPNHopping -->|Clean| SybilCheck{Tier 2: Sybil / ID Cycling Check <br> >3 distinct user-ids from single IP?}
    
    SybilCheck -->|Yes: Sybil Attack| JailIP[HTTP 429: Sybil Attack Detected! <br> IP Jailed for 120s]
    SybilCheck -->|Clean| OuterIPLimit{Tier 3: Outer IP Guardrail <br> >30 reqs/min for physical IP?}
    
    OuterIPLimit -->|Yes| BlockIP[HTTP 429: Physical IP Rate Limit Exceeded]
    OuterIPLimit -->|Clean| UserQuota{Tier 4: User Token Bucket <br> >10 reqs/min for user_id?}
    
    UserQuota -->|No Tokens Left| BlockUser[HTTP 429: Rate Limit Exceeded: Quota Exhausted]
    UserQuota -->|Tokens Available| VerifiedCheck{Tier 5: Verified Human Pass <br> Solved challenge in last 5 mins?}
    
    VerifiedCheck -->|Yes| AllowVerified[HTTP 200 OK: Allowed as Verified Human]
    VerifiedCheck -->|No| MLBehavior[Tier 6: Behavioral ML Engine <br> Timing Jitter & Burst Analysis]
    
    MLBehavior -->|Bot Machine Speed| JailBot[HTTP 429: Jailed for 60s]
    MLBehavior -->|Suspicious Burst| IssueChallenge[HTTP 403: Verification Challenge Required]
    MLBehavior -->|Natural Human Jitter| AllowHuman[HTTP 200 OK: Request Allowed]

    IssueChallenge -->|Solves Challenge| GrantPass[Unlocks 5-Min Verified Pass & Trains Model]
```

---

## 🛡️ Defenses Against Modern Attacks

| Attack Vector | How It Works | How Our System Neutralizes It |
| :--- | :--- | :--- |
| **Volumetric DDoS** | Sending hundreds of requests per second. | **Token Bucket (10 reqs/min)** hard ceiling stops all traffic. |
| **Robotic Scraping** | Bots sending rapid requests with machine-like timing ($<0.05$s gaps). | **Behavioral ML Timing Jitter ($\sigma$) Engine** detects zero-jitter metronomic timing and jails the bot on request #3. |
| **Sybil Attack (User-ID Cycling)** | Script cycles through `user_1`, `user_2`, `user_3` to get 10 fresh tokens each time. | **Identity Velocity Tracker** detects $>3$ distinct IDs from one IP in 60s and **jails the physical IP**. |
| **VPN / Proxy IP Rotation** | Attacker switches VPNs to rotate IP addresses. | **Device Fingerprinting & VPN Hopping Detector** detects a single device rotating across multiple IPs and **jails the Device Fingerprint (`dev_...`) for 120s**. Switching IPs will not unblock them! |
| **CAPTCHA Hell for Humans** | Legitimate fast humans getting constantly challenged on every click. | **Verified Human Session Pass**: Solved challenge grants a 5-minute verified pass to browse smoothly under their 10-req quota. |

---

## 🚀 Quick Start & Testing

### 1. Start the API Server
```powershell
.\.venv\Scripts\uvicorn.exe main:app --reload
```
Server runs at `http://127.0.0.1:8000`.

### 2. Run Verification & Interactive Demo

#### A. Master Exhaustive Test Suite (20 Automated Security Checks)
```powershell
.\.venv\Scripts\python.exe master_audit.py
```
Audits all 8 dimensions: Infrastructure, Real Human browsing, Bot detection, Human Challenge solving & 5-min Verified Pass, Hard 10-req quota, Sybil Attack defense, VPN Hopping device lockout, and Fault-Tolerance Edge Cases.

#### B. Interactive Terminal Demo
```powershell
.\.venv\Scripts\python.exe demo.py
```
Simulates real humans, burst challenges, and robotic spammers in real-time with visual terminal outputs.
