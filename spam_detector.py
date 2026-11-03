import time
import math
import uuid
from typing import Dict, Any, List, Optional, Tuple
import threading
import json
import redis

class AdaptiveSpamDetector:
    """
    Self-learning, adaptive abuse and spam detector.
    
    Extracts behavioral traffic features:
      1. Interval Jitter (Standard deviation of time gaps between requests)
         - Bots have near-zero jitter (machine-like fixed intervals, e.g. 100ms).
         - Humans have high natural jitter (e.g. 0.8s, 2.3s, 0.4s).
      2. Burst Rate (Number of requests in the last 2 seconds)
      3. Mean Request Interval (Average speed of requests)
      4. Client Header Entropy (User-Agent legitimacy)

    Uses an Online Gaussian Classifier with adaptive centroids.
    Learns continuously through an automated feedback loop:
      - When suspicious users (risk 0.4 - 0.75) are challenged and PASS -> auto-labeled HUMAN.
      - When users FAIL or get jailed (risk >= 0.75) -> auto-labeled SPAMMER.
      - The model updates its distribution parameters online without manual supervision.
    """

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        self._lock = threading.Lock()
        
        # Local in-memory store for fallback if Redis is unavailable
        self._local_history: Dict[str, List[float]] = {}
        self._local_penalty_box: Dict[str, float] = {}  # user_id -> expiry_timestamp
        self._local_challenges: Dict[str, Dict[str, Any]] = {}
        self._local_strikes: Dict[str, int] = {}  # Repeat offender strikes
        self._local_verified_humans: Dict[str, float] = {}  # user_id -> verified_until_timestamp
        
        # Model parameter centroids (seeded with reasonable prior distributions)
        # Features: [interval_std, burst_count, mean_interval]
        self.model_state = {
            "human": {
                "mean": [1.8, 1.2, 2.5],     # High jitter, low burst, slower pace
                "var":  [1.0, 0.5, 1.5],
                "count": 50
            },
            "spammer": {
                "mean": [0.04, 5.0, 0.15],   # Ultra-low jitter, high burst, robotic speed
                "var":  [0.02, 1.5, 0.05],
                "count": 50
            },
            "total_updates": 0
        }
        
        self.learning_rate = 0.05  # EMA weight for continuous online adaptation
        self.stats = {
            "total_evaluations": 0,
            "humans_allowed": 0,
            "challenges_issued": 0,
            "challenges_passed": 0,
            "spammers_blocked": 0
        }

    # -------------------------------------------------------------------------
    # Feature Extraction
    # -------------------------------------------------------------------------

    def record_and_extract_features(self, user_id: str, user_agent: str = "") -> Dict[str, float]:
        """
        Records the current request timestamp and extracts temporal features for the user.
        Uses a rolling session window (15s) so past gaps (like jail time) do not skew statistics.
        """
        now = time.time()
        
        # 1. User-Agent suspicion evaluation
        ua_lower = (user_agent or "").lower()
        if not user_agent:
            ua_suspicion = 0.5
        elif any(bot in ua_lower for bot in ["bot", "crawl", "spider", "scraper"]):
            ua_suspicion = 0.95
        elif "python" in ua_lower or "curl" in ua_lower:
            ua_suspicion = 0.4
        else:
            ua_suspicion = 0.05
        
        # 2. Update rolling history (prunes timestamps older than 15s)
        timestamps = self._get_and_update_history(user_id, now, max_history=12, window_seconds=15.0)
        
        if len(timestamps) < 3:
            # Baseline features for first couple requests
            burst_count = float(len(timestamps))
            return {
                "interval_std": 1.5,
                "burst_count": burst_count,
                "mean_interval": 2.0,
                "ua_suspicion": ua_suspicion
            }

        # Calculate time intervals between consecutive requests in current session
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        
        mean_interval = sum(intervals) / len(intervals)
        
        # Standard deviation (jitter)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        interval_std = math.sqrt(variance)
        
        # Burst count: requests within the last 2 seconds
        burst_count = sum(1 for t in timestamps if (now - t) <= 2.0)
        
        return {
            "interval_std": round(interval_std, 4),
            "burst_count": float(burst_count),
            "mean_interval": round(mean_interval, 4),
            "ua_suspicion": ua_suspicion
        }

    # -------------------------------------------------------------------------
    # Model Scoring (Bayesian Risk Classifier)
    # -------------------------------------------------------------------------

    def compute_risk_score(self, features: Dict[str, float], user_id: str = "") -> Tuple[float, str]:
        """
        Computes a continuous risk score between 0.0 (definitely human) and 1.0 (definitely spammer).
        Uses Gaussian likelihood comparison against current adaptive centroids,
        combined with client signature entropy and repeat offender history.
        """
        # Vector: [interval_std, burst_count, mean_interval]
        x = [features["interval_std"], features["burst_count"], features["mean_interval"]]
        
        def log_gaussian_prob(x_vec, mean_vec, var_vec):
            log_prob = 0.0
            for xi, mi, vi in zip(x_vec, mean_vec, var_vec):
                v = max(vi, 1e-4)  # Avoid division by zero
                log_prob += -0.5 * math.log(2 * math.pi * v) - ((xi - mi) ** 2) / (2 * v)
            return log_prob

        with self._lock:
            human_state = self.model_state["human"]
            spam_state = self.model_state["spammer"]
            
            log_p_human = log_gaussian_prob(x, human_state["mean"], human_state["var"])
            log_p_spam = log_gaussian_prob(x, spam_state["mean"], spam_state["var"])

        # Posterior probability via softmax / sigmoid of log likelihood ratio
        log_ratio = log_p_spam - log_p_human
        log_ratio = max(-20.0, min(20.0, log_ratio))
        base_risk = 1.0 / (1.0 + math.exp(-log_ratio))
        
        ua_suspicion = features["ua_suspicion"]
        
        # Compound risk evaluation:
        if ua_suspicion >= 0.8:
            # Client identifies as a bot/scraper (e.g. "PythonBot", "ScraperBot")
            if features["burst_count"] >= 3 or features["mean_interval"] < 0.5:
                # Fast requests from a declared bot -> immediate high risk!
                final_risk = max(base_risk, 0.88)
            else:
                final_risk = max(base_risk, 0.5 * base_risk + 0.5 * ua_suspicion)
        else:
            final_risk = 0.7 * base_risk + 0.3 * ua_suspicion

        # Repeat offender penalty: If previously jailed, elevate risk floor
        strikes = self.get_strikes(user_id)
        if strikes > 0:
            final_risk = min(1.0, final_risk + 0.15 * strikes)

        final_risk = round(max(0.0, min(1.0, final_risk)), 3)
        
        if final_risk < 0.40:
            classification = "human"
        elif final_risk < 0.75:
            classification = "suspicious"
        else:
            classification = "spammer"
            
        with self._lock:
            self.stats["total_evaluations"] += 1
            if classification == "human":
                self.stats["humans_allowed"] += 1
            elif classification == "suspicious":
                self.stats["challenges_issued"] += 1
            else:
                self.stats["spammers_blocked"] += 1

        return final_risk, classification

    # -------------------------------------------------------------------------
    # Self-Learning Feedback Loop
    # -------------------------------------------------------------------------

    def update_model(self, features: Dict[str, float], label: str):
        """
        Online adaptation step: When ground truth is established (e.g. through a challenge outcome),
        update the Gaussian distribution parameters using Exponential Moving Average.
        """
        x = [features["interval_std"], features["burst_count"], features["mean_interval"]]
        
        with self._lock:
            target = self.model_state.get(label)
            if not target:
                return

            lr = self.learning_rate
            mean = target["mean"]
            var = target["var"]

            for i in range(len(x)):
                delta = x[i] - mean[i]
                # Update running mean
                mean[i] = round(mean[i] + lr * delta, 4)
                # Update running variance
                new_var = (1 - lr) * var[i] + lr * (delta ** 2)
                var[i] = round(max(0.001, new_var), 4)

            target["count"] += 1
            self.model_state["total_updates"] += 1

    # -------------------------------------------------------------------------
    # Adaptive Challenge Management (Proof of Human)
    # -------------------------------------------------------------------------

    def generate_challenge(self, user_id: str, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Creates a lightweight verification challenge for suspicious users.
        """
        challenge_id = str(uuid.uuid4())[:8]
        import random
        num1 = random.randint(3, 19)
        num2 = random.randint(2, 9)
        expected_answer = str(num1 + num2)
        
        challenge_data = {
            "challenge_id": challenge_id,
            "user_id": user_id,
            "question": f"Human verification required: what is {num1} + {num2}?",
            "expected_answer": expected_answer,
            "features": features,
            "created_at": time.time(),
            "expires_at": time.time() + 120
        }
        
        with self._lock:
            self._local_challenges[challenge_id] = challenge_data
            
        return {
            "challenge_id": challenge_id,
            "prompt": challenge_data["question"],
            "verify_url": "/verify-challenge",
            "method": "POST",
            "body_example": {"challenge_id": challenge_id, "answer": expected_answer}
        }

    def has_pending_challenge(self, user_id: str) -> bool:
        """Checks if user already has an active, unsolved challenge."""
        if not user_id:
            return False
        now = time.time()
        with self._lock:
            for cid, cdata in list(self._local_challenges.items()):
                if cdata.get("user_id") == user_id:
                    if now < cdata.get("expires_at", 0):
                        return True
                    else:
                        del self._local_challenges[cid]
        return False

    def verify_challenge(self, challenge_id: str, user_answer: str) -> Tuple[bool, str]:
        """
        Validates the challenge. If correct, teaches the model that this pattern was HUMAN.
        If failed, treats the pattern as SPAMMER.
        """
        with self._lock:
            challenge = self._local_challenges.pop(challenge_id, None)
            
        if not challenge:
            return False, "Invalid or expired challenge."
            
        if time.time() > challenge["expires_at"]:
            return False, "Challenge expired. Please request a new one."
            
        is_correct = (str(user_answer).strip() == str(challenge["expected_answer"]).strip())
        features = challenge["features"]
        user_id = challenge["user_id"]
        
        if is_correct:
            # Self-learning: Learn that this feature set belonged to a legitimate human
            self.update_model(features, label="human")
            self.set_verified_human(user_id, duration_seconds=300)
            with self._lock:
                self.stats["challenges_passed"] += 1
                self._local_penalty_box.pop(user_id, None)
                self._local_history.pop(user_id, None)
                self._local_strikes.pop(user_id, None)
            return True, "Verification successful! You are verified as human for 5 minutes. You may continue using your remaining quota (up to 10 requests/min)."
        else:
            # Spammer failed challenge
            self.update_model(features, label="spammer")
            self.jail_user(user_id, duration_seconds=120)
            return False, "Incorrect verification answer. User temporarily jailed."

    def is_verified_human(self, user_id: str) -> bool:
        """Checks if a user holds an active Verified Human Session Pass."""
        if not user_id:
            return False
        now = time.time()
        if self.redis:
            try:
                ttl = self.redis.ttl(f"verified_human:{user_id}")
                if ttl and ttl > 0:
                    return True
            except Exception:
                pass
        with self._lock:
            expiry = self._local_verified_humans.get(user_id, 0)
            if now < expiry:
                return True
            elif expiry > 0:
                del self._local_verified_humans[user_id]
        return False

    def set_verified_human(self, user_id: str, duration_seconds: int = 300):
        """Grants user a 5-minute Verified Human Pass after solving a challenge."""
        if not user_id:
            return
        if self.redis:
            try:
                self.redis.setex(f"verified_human:{user_id}", duration_seconds, "verified")
            except Exception:
                pass
        with self._lock:
            self._local_verified_humans[user_id] = time.time() + duration_seconds

    # -------------------------------------------------------------------------
    # Penalty Box (Jail) Management
    # -------------------------------------------------------------------------

    def compute_device_fingerprint(self, headers: Any, user_agent: str = "") -> str:
        """
        Derives a deterministic Device Fingerprint based on hardware/client parameters
        or an explicit device-id header from a mobile/browser client.
        """
        import hashlib
        explicit_id = headers.get("device-id") or headers.get("x-device-id")
        if explicit_id:
            return str(explicit_id).strip()

        # Synthesize fingerprint from browser hardware parameters
        lang = headers.get("accept-language", "")
        enc = headers.get("accept-encoding", "")
        ch_ua = headers.get("sec-ch-ua", "")
        raw = f"{user_agent}|{lang}|{enc}|{ch_ua}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"dev_{digest}"

    def is_in_penalty_box(self, user_id: str, client_ip: str = "", device_id: str = "") -> Tuple[bool, int]:
        """
        Checks if a user, their physical client IP, OR their Device Fingerprint
        is currently jailed for spamming, Sybil attacks, or VPN hopping.
        Returns (is_jailed, remaining_seconds).
        """
        targets = [user_id]
        if client_ip:
            targets.append(f"ip:{client_ip}")
        if device_id:
            targets.append(f"dev:{device_id}")

        now = time.time()
        for target in targets:
            if not target:
                continue
            if self.redis:
                try:
                    ttl = self.redis.ttl(f"penalty_box:{target}")
                    if ttl and ttl > 0:
                        return True, ttl
                except Exception:
                    pass

            with self._lock:
                expiry = self._local_penalty_box.get(target)
                if expiry:
                    if now < expiry:
                        return True, int(expiry - now)
                    else:
                        del self._local_penalty_box[target]
                        
        return False, 0

    def track_vpn_hopping(self, device_id: str, client_ip: str, max_allowed_ips: int = 2, window_seconds: float = 60.0) -> Tuple[bool, int]:
        """
        Detects VPN / Proxy IP rotation attacks.
        If a single device fingerprint rotates across more than max_allowed_ips distinct IPs
        within window_seconds, flags as a VPN Hopping / IP Churning attack.
        Returns (is_vpn_hopping, distinct_ip_count).
        """
        if not device_id or not client_ip:
            return False, 1

        now = time.time()
        cutoff = now - window_seconds

        # Redis implementation
        if self.redis:
            try:
                key = f"dev_ips:{device_id}"
                self.redis.zremrangebyscore(key, 0, cutoff)
                self.redis.zadd(key, {client_ip: now})
                self.redis.expire(key, int(window_seconds) + 10)
                count = self.redis.zcard(key)
                if count > max_allowed_ips:
                    return True, count
                return False, count
            except Exception:
                pass

        # In-memory implementation
        with self._lock:
            if not hasattr(self, "_local_device_ips"):
                self._local_device_ips: Dict[str, Dict[str, float]] = {}
            if device_id not in self._local_device_ips:
                self._local_device_ips[device_id] = {}

            ip_map = self._local_device_ips[device_id]
            ip_map = {ip: t for ip, t in ip_map.items() if t > cutoff}
            ip_map[client_ip] = now
            self._local_device_ips[device_id] = ip_map

            count = len(ip_map)
            if count > max_allowed_ips:
                return True, count
            return False, count

    def track_identity_velocity(self, client_ip: str, user_id: str, max_allowed_ids: int = 3, window_seconds: float = 60.0) -> Tuple[bool, int]:
        """
        Detects Sybil / Account Cycling attacks.
        If a single IP uses more than max_allowed_ids distinct user_ids within window_seconds,
        flags as a Sybil attack.
        Returns (is_sybil_attack, distinct_id_count).
        """
        if not client_ip or not user_id:
            return False, 1

        now = time.time()
        cutoff = now - window_seconds

        # Redis implementation
        if self.redis:
            try:
                key = f"ip_identities:{client_ip}"
                self.redis.zremrangebyscore(key, 0, cutoff)
                self.redis.zadd(key, {user_id: now})
                self.redis.expire(key, int(window_seconds) + 10)
                count = self.redis.zcard(key)
                if count > max_allowed_ids:
                    return True, count
                return False, count
            except Exception:
                pass

        # In-memory implementation
        with self._lock:
            if not hasattr(self, "_local_ip_identities"):
                self._local_ip_identities: Dict[str, Dict[str, float]] = {}
            if client_ip not in self._local_ip_identities:
                self._local_ip_identities[client_ip] = {}

            id_map = self._local_ip_identities[client_ip]
            id_map = {uid: t for uid, t in id_map.items() if t > cutoff}
            id_map[user_id] = now
            self._local_ip_identities[client_ip] = id_map

            count = len(id_map)
            if count > max_allowed_ids:
                return True, count
            return False, count

    def jail_user(self, user_id: str, duration_seconds: int = 60):
        """
        Temporarily places a detected spammer in the penalty box.
        Clears historical timestamps so post-jail requests start with clean interval metrics.
        """
        strikes = self.get_strikes(user_id) + 1
        self.set_strikes(user_id, strikes)
        
        # Escalating jail duration for repeat offenders (60s -> 120s -> 180s)
        actual_duration = duration_seconds * min(strikes, 3)
        
        if self.redis:
            try:
                self.redis.setex(f"penalty_box:{user_id}", actual_duration, "jailed")
                # Clear traffic history to avoid interval skew after release
                self.redis.delete(f"traffic_history:{user_id}")
            except Exception:
                pass
                
        with self._lock:
            self._local_penalty_box[user_id] = time.time() + actual_duration
            self._local_history.pop(user_id, None)

    def get_strikes(self, user_id: str) -> int:
        if not user_id:
            return 0
        if self.redis:
            try:
                val = self.redis.get(f"strikes:{user_id}")
                if val:
                    return int(val)
            except Exception:
                pass
        with self._lock:
            return self._local_strikes.get(user_id, 0)

    def set_strikes(self, user_id: str, count: int):
        if not user_id:
            return
        if self.redis:
            try:
                self.redis.setex(f"strikes:{user_id}", 600, count)
            except Exception:
                pass
        with self._lock:
            self._local_strikes[user_id] = count

    # -------------------------------------------------------------------------
    # Helpers & Metrics
    # -------------------------------------------------------------------------

    def _get_and_update_history(self, user_id: str, timestamp: float, max_history: int = 12, window_seconds: float = 15.0) -> List[float]:
        """
        Maintains sliding window of request timestamps, pruning any that are older
        than window_seconds (session decay).
        """
        cutoff = timestamp - window_seconds
        
        # Redis implementation
        if self.redis:
            try:
                key = f"traffic_history:{user_id}"
                # 1. Prune timestamps older than window_seconds
                self.redis.zremrangebyscore(key, 0, cutoff)
                # 2. Add current timestamp
                self.redis.zadd(key, {str(timestamp): timestamp})
                # 3. Retain max_history items
                self.redis.zremrangebyrank(key, 0, -(max_history + 1))
                self.redis.expire(key, 120)
                raw = self.redis.zrange(key, 0, -1)
                return [float(x) for x in raw]
            except Exception:
                pass

        # In-memory implementation
        with self._lock:
            hist = self._local_history.get(user_id, [])
            # Prune old timestamps
            hist = [t for t in hist if t > cutoff]
            hist.append(timestamp)
            if len(hist) > max_history:
                hist = hist[-max_history:]
            self._local_history[user_id] = hist
            return list(hist)

    def get_diagnostics(self) -> Dict[str, Any]:
        """
        Returns model state, current centroids, and operational metrics.
        """
        with self._lock:
            return {
                "metrics": dict(self.stats),
                "model_centroids": {
                    "human": {
                        "mean_interval_std": self.model_state["human"]["mean"][0],
                        "mean_burst_count": self.model_state["human"]["mean"][1],
                        "mean_request_interval": self.model_state["human"]["mean"][2],
                        "trained_samples": self.model_state["human"]["count"]
                    },
                    "spammer": {
                        "mean_interval_std": self.model_state["spammer"]["mean"][0],
                        "mean_burst_count": self.model_state["spammer"]["mean"][1],
                        "mean_request_interval": self.model_state["spammer"]["mean"][2],
                        "trained_samples": self.model_state["spammer"]["count"]
                    },
                    "total_self_learning_updates": self.model_state["total_updates"]
                },
                "active_jailed_users": len(self._local_penalty_box)
            }
