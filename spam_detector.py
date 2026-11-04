import time
import math
import uuid
import secrets
from typing import Dict, Any, List, Optional, Tuple
import threading
import json
import redis
from rate_limiter import validate_positive_number, validate_positive_int

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
        self._lock = threading.RLock()
        
        # Local in-memory store for fallback if Redis is unavailable
        self._local_history: Dict[str, List[float]] = {}
        self._local_penalty_box: Dict[str, float] = {}  # user_id -> expiry_timestamp
        self._local_challenges: Dict[str, Dict[str, Any]] = {}
        self._local_strikes: Dict[str, int] = {}  # Repeat offender strikes
        self._local_verified_humans: Dict[str, float] = {}  # user_id -> verified_until_timestamp
        self._local_device_ips: Dict[str, Dict[str, float]] = {}
        self._local_ip_identities: Dict[str, Dict[str, float]] = {}
        self._local_challenge_throttles: Dict[str, List[float]] = {}
        
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
            "spammers_blocked": 0,
            "challenges_exhausted": 0
        }
        
        self.model_version = 1
        self._last_model_sync = 0.0

        self._verify_challenge_script = None
        self._update_model_script = None

        if self.redis:
            try:
                lua_verify = """
                local key = KEYS[1]
                local provided_answer = tostring(ARGV[1])
                local expected_user_id = tostring(ARGV[2])

                local state = redis.call('HMGET', key, 'user_id', 'expected_answer', 'features', 'attempts_left')
                local user_id = state[1]
                local expected_answer = state[2]
                local features_json = state[3]
                local attempts_left = tonumber(state[4])

                if not user_id then
                    return {"EXPIRED_OR_NOT_FOUND", "", "", 0}
                end

                if expected_user_id == "" or expected_user_id ~= user_id then
                    return {"USER_MISMATCH", user_id, "", attempts_left or 0}
                end

                local actual_pending_key = "user_pending_challenge:" .. user_id

                if provided_answer == expected_answer then
                    redis.call('DEL', key)
                    redis.call('DEL', actual_pending_key)
                    return {"SUCCESS", user_id, features_json, attempts_left or 0}
                else
                    attempts_left = (attempts_left or 3) - 1
                    if attempts_left <= 0 then
                        redis.call('DEL', key)
                        redis.call('DEL', actual_pending_key)
                        return {"EXHAUSTED", user_id, features_json, 0}
                    else
                        redis.call('HSET', key, 'attempts_left', attempts_left)
                        return {"WRONG_ANSWER", user_id, features_json, attempts_left}
                    end
                end
                """
                self._verify_challenge_script = self.redis.register_script(lua_verify)
            except Exception:
                self._verify_challenge_script = None

            try:
                lua_model = """
                local key = KEYS[1]
                local label = ARGV[1]
                local x0 = tonumber(ARGV[2])
                local x1 = tonumber(ARGV[3])
                local x2 = tonumber(ARGV[4])
                local lr = tonumber(ARGV[5])

                local state = redis.call('HMGET', key,
                    label .. ':mean:0', label .. ':mean:1', label .. ':mean:2',
                    label .. ':var:0', label .. ':var:1', label .. ':var:2',
                    label .. ':count', 'total_updates', 'version'
                )

                local m0 = tonumber(state[1]) or (label == 'human' and 1.8 or 0.04)
                local m1 = tonumber(state[2]) or (label == 'human' and 1.2 or 5.0)
                local m2 = tonumber(state[3]) or (label == 'human' and 2.5 or 0.15)
                local v0 = tonumber(state[4]) or (label == 'human' and 1.0 or 0.02)
                local v1 = tonumber(state[5]) or (label == 'human' and 0.5 or 1.5)
                local v2 = tonumber(state[6]) or (label == 'human' and 1.5 or 0.05)
                local count = tonumber(state[7]) or 50
                local total_updates = tonumber(state[8]) or 0
                local version = tonumber(state[9]) or 1

                local x = {x0, x1, x2}
                local m = {m0, m1, m2}
                local v = {v0, v1, v2}

                for i = 1, 3 do
                    local delta = x[i] - m[i]
                    m[i] = m[i] + (lr * delta)
                    local new_v = ((1.0 - lr) * v[i]) + (lr * (delta * delta))
                    if new_v < 0.001 then new_v = 0.001 end
                    v[i] = new_v
                end

                count = count + 1
                total_updates = total_updates + 1
                version = version + 1

                redis.call('HMSET', key,
                    label .. ':mean:0', m[1], label .. ':mean:1', m[2], label .. ':mean:2', m[3],
                    label .. ':var:0', v[1], label .. ':var:1', v[2], label .. ':var:2', v[3],
                    label .. ':count', count,
                    'total_updates', total_updates,
                    'version', version
                )

                return {tostring(version), tostring(total_updates), tostring(count), tostring(m[1]), tostring(m[2]), tostring(m[3]), tostring(v[1]), tostring(v[2]), tostring(v[3])}
                """
                self._update_model_script = self.redis.register_script(lua_model)
                self._init_or_load_redis_model()
            except Exception:
                self._update_model_script = None

            try:
                # Atomic sliding window cardinality script (for VPN hopping & Sybil tracking)
                lua_window = """
                local key = KEYS[1]
                local member = ARGV[1]
                local now = tonumber(ARGV[2])
                local cutoff = tonumber(ARGV[3])
                local max_allowed = tonumber(ARGV[4])
                local expire_seconds = tonumber(ARGV[5])

                redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
                redis.call('ZADD', key, now, member)
                redis.call('EXPIRE', key, expire_seconds)
                local count = redis.call('ZCARD', key)
                local is_violation = (count > max_allowed) and 1 or 0

                return {is_violation, count}
                """
                self._sliding_window_script = self.redis.register_script(lua_window)

                # Atomic traffic history update script (5 ops in 1 round trip)
                lua_history = """
                local key = KEYS[1]
                local now_str = tostring(ARGV[1])
                local now_num = tonumber(ARGV[1])
                local cutoff = tonumber(ARGV[2])
                local max_history = tonumber(ARGV[3])

                redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
                redis.call('ZADD', key, now_num, now_str)
                redis.call('ZREMRANGEBYRANK', key, 0, -(max_history + 1))
                redis.call('EXPIRE', key, 120)

                return redis.call('ZRANGE', key, 0, -1)
                """
                self._traffic_history_script = self.redis.register_script(lua_history)

                # Atomic multi-target penalty box checker
                lua_penalty = """
                for i = 1, #KEYS do
                    local ttl = redis.call('TTL', KEYS[i])
                    if ttl > 0 then
                        return {1, ttl, KEYS[i]}
                    end
                end
                return {0, 0, ""}
                """
                self._penalty_check_script = self.redis.register_script(lua_penalty)

                # Atomic jail with escalating strikes
                lua_jail = """
                local penalty_key = KEYS[1]
                local strike_key = KEYS[2]
                local history_key = KEYS[3]
                local base_duration = tonumber(ARGV[1])

                local strikes = tonumber(redis.call('GET', strike_key) or 0) + 1
                redis.call('SETEX', strike_key, 600, strikes)

                local multiplier = math.min(strikes, 3)
                local actual_duration = base_duration * multiplier

                redis.call('SETEX', penalty_key, actual_duration, 'jailed')
                redis.call('DEL', history_key)

                return {actual_duration, strikes}
                """
                self._jail_user_script = self.redis.register_script(lua_jail)
            except Exception:
                self._sliding_window_script = None
                self._traffic_history_script = None
                self._penalty_check_script = None
                self._jail_user_script = None

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
        self.sync_model_from_redis()
        # Vector: [interval_std, burst_count, mean_interval]
        x = [
            float(features.get("interval_std", 0.0)),
            float(features.get("burst_count", 1.0)),
            float(features.get("mean_interval", features.get("request_interval", 1.0)))
        ]
        
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

    def _init_or_load_redis_model(self):
        """Initializes model centroids in Redis if missing, or loads latest parameters."""
        if not self.redis:
            return
        key = "model_state:centroids"
        try:
            if not self.redis.exists(key):
                # Seed Redis with initial prior distributions
                self.redis.hset(key, mapping={
                    "human:mean:0": 1.8, "human:mean:1": 1.2, "human:mean:2": 2.5,
                    "human:var:0": 1.0, "human:var:1": 0.5, "human:var:2": 1.5,
                    "human:count": 50,
                    "spammer:mean:0": 0.04, "spammer:mean:1": 5.0, "spammer:mean:2": 0.15,
                    "spammer:var:0": 0.02, "spammer:var:1": 1.5, "spammer:var:2": 0.05,
                    "spammer:count": 50,
                    "total_updates": 0,
                    "version": 1
                })
            self.sync_model_from_redis(force=True)
        except Exception:
            pass

    def sync_model_from_redis(self, force: bool = False):
        """Synchronizes learned model parameters across distributed application instances."""
        if not self.redis:
            return
        now = time.time()
        if not force and (now - self._last_model_sync < 1.0):
            return  # Fast cache hit within 1 second

        key = "model_state:centroids"
        try:
            fields = [
                "human:mean:0", "human:mean:1", "human:mean:2",
                "human:var:0", "human:var:1", "human:var:2", "human:count",
                "spammer:mean:0", "spammer:mean:1", "spammer:mean:2",
                "spammer:var:0", "spammer:var:1", "spammer:var:2", "spammer:count",
                "total_updates", "version"
            ]
            raw = self.redis.hmget(key, fields)
            if raw[0] is not None:
                with self._lock:
                    self.model_state["human"]["mean"] = [round(float(raw[0]), 4), round(float(raw[1]), 4), round(float(raw[2]), 4)]
                    self.model_state["human"]["var"] = [round(float(raw[3]), 4), round(float(raw[4]), 4), round(float(raw[5]), 4)]
                    self.model_state["human"]["count"] = int(raw[6])
                    self.model_state["spammer"]["mean"] = [round(float(raw[7]), 4), round(float(raw[8]), 4), round(float(raw[9]), 4)]
                    self.model_state["spammer"]["var"] = [round(float(raw[10]), 4), round(float(raw[11]), 4), round(float(raw[12]), 4)]
                    self.model_state["spammer"]["count"] = int(raw[13])
                    self.model_state["total_updates"] = int(raw[14])
                    self.model_version = int(raw[15])
                    self._last_model_sync = now
        except Exception:
            pass

    def update_model(self, features: Dict[str, float], label: str):
        """
        Online adaptation step: When ground truth is established (e.g. through a challenge outcome),
        atomically updates the Gaussian distribution parameters across all distributed instances
        using Exponential Moving Average in Redis Lua.
        """
        x = [
            float(features.get("interval_std", 0.0)),
            float(features.get("burst_count", 1.0)),
            float(features.get("mean_interval", features.get("request_interval", 1.0)))
        ]
        
        # 1. Distributed Redis Atomic Update
        if self.redis and self._update_model_script:
            try:
                res = self._update_model_script(
                    keys=["model_state:centroids"],
                    args=[label, x[0], x[1], x[2], self.learning_rate]
                )
                version, total_updates, count, m0, m1, m2, v0, v1, v2 = res
                with self._lock:
                    target = self.model_state[label]
                    target["mean"] = [round(float(m0), 4), round(float(m1), 4), round(float(m2), 4)]
                    target["var"] = [round(float(v0), 4), round(float(v1), 4), round(float(v2), 4)]
                    target["count"] = int(count)
                    self.model_state["total_updates"] = int(total_updates)
                    self.model_version = int(version)
                    self._last_model_sync = time.time()
                return
            except Exception:
                pass

        # 2. Local Fallback Update
        with self._lock:
            target = self.model_state.get(label)
            if not target:
                return

            lr = self.learning_rate
            mean = target["mean"]
            var = target["var"]

            for i in range(len(x)):
                delta = x[i] - mean[i]
                mean[i] = round(mean[i] + lr * delta, 4)
                new_var = (1 - lr) * var[i] + lr * (delta ** 2)
                var[i] = round(max(0.001, new_var), 4)

            target["count"] += 1
            self.model_state["total_updates"] += 1
            self.model_version += 1

    def generate_challenge(self, user_id: str, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Creates a lightweight verification challenge for suspicious users.

        SECURITY & ARCHITECTURAL PROPERTIES:
          1. Answer Concealment: Answers stored strictly server-side in Redis. Never sent to client.
          2. Unpredictable IDs: Generated with `secrets.token_urlsafe(18)` (144-bit entropy).
          3. Single-Use Expiration: 120-second TTL enforced by Redis.
          4. Bounded Verification Attempts: Max 3 attempts before burning challenge and jailing.
          5. Session Binding: Bound to the requesting user_id.

        LIMITATION NOTE:
          Simple arithmetic challenges provide lightweight friction against basic scrapers,
          but do NOT provide cryptographic CAPTCHA or absolute proof-of-human guarantees.
        """
        # Per-user throttle: max 3 challenges per 5-minute window (300s)
        now = time.time()
        throttle_exceeded = False
        if self.redis:
            try:
                throttle_key = f"challenge_throttle:{user_id}"
                count = self.redis.incr(throttle_key)
                if count == 1:
                    self.redis.expire(throttle_key, 300)
                elif self.redis.ttl(throttle_key) == -1:
                    self.redis.expire(throttle_key, 300)
                if count > 3:
                    throttle_exceeded = True
            except Exception:
                pass

        with self._lock:
            history = self._local_challenge_throttles.get(user_id, [])
            history = [t for t in history if now - t < 300.0]
            if not throttle_exceeded:
                if len(history) >= 3:
                    throttle_exceeded = True
                else:
                    history.append(now)
            self._local_challenge_throttles[user_id] = history

        if throttle_exceeded:
            self.jail_user(user_id, duration_seconds=300)
            return {
                "error": "Challenge generation rate limit exceeded. User placed in penalty box.",
                "user_id": user_id,
                "jailed": True,
                "retry_after": 300
            }

        challenge_id = f"ch_{secrets.token_urlsafe(18)}"
        num1 = secrets.randbelow(17) + 3  # 3 to 19
        num2 = secrets.randbelow(8) + 2   # 2 to 9
        expected_answer = str(num1 + num2)
        prompt = f"Human verification required: what is {num1} + {num2}?"
        ttl = 120

        # Store in Redis
        if self.redis:
            try:
                pipe = self.redis.pipeline()
                pipe.hset(f"challenge:{challenge_id}", mapping={
                    "user_id": user_id,
                    "expected_answer": expected_answer,
                    "features": json.dumps(features),
                    "attempts_left": 3,
                    "created_at": str(time.time())
                })
                pipe.expire(f"challenge:{challenge_id}", ttl)
                pipe.setex(f"user_pending_challenge:{user_id}", ttl, challenge_id)
                pipe.execute()
            except Exception:
                pass

        # Local in-memory store
        with self._lock:
            self._local_challenges[challenge_id] = {
                "user_id": user_id,
                "expected_answer": expected_answer,
                "features": features,
                "attempts_left": 3,
                "expires_at": time.time() + ttl
            }

        return {
            "challenge_id": challenge_id,
            "user_id": user_id,
            "prompt": prompt,
            "verify_url": "/verify-challenge",
            "method": "POST",
            "expires_in_seconds": ttl,
            "body_example": {
                "challenge_id": challenge_id,
                "user_id": user_id,
                "answer": "<compute answer to prompt>"
            }
        }

    def has_pending_challenge(self, user_id: str) -> bool:
        """Checks if user already has an active, unsolved challenge."""
        if not user_id:
            return False
        if self.redis:
            try:
                cid = self.redis.get(f"user_pending_challenge:{user_id}")
                if cid:
                    return True
            except Exception:
                pass
        now = time.time()
        with self._lock:
            for cid, cdata in list(self._local_challenges.items()):
                if cdata.get("user_id") == user_id:
                    if now < cdata.get("expires_at", 0):
                        return True
                    else:
                        del self._local_challenges[cid]
        return False

    def verify_challenge(self, challenge_id: str, user_answer: str, expected_user_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validates the challenge atomically.
        If correct, updates the online Gaussian model to HUMAN and grants 5-min pass.
        If max attempts exceeded, updates model to SPAMMER and jails user.
        """
        user_answer_str = str(user_answer).strip()
        expected_user_str = str(expected_user_id or "").strip()
        if not expected_user_str:
            return False, "Challenge verification requires a valid user identity." 

        # 1. Distributed Redis Path (Atomic Lua Verification)
        if self.redis and self._verify_challenge_script:
            try:
                res = self._verify_challenge_script(
                    keys=[f"challenge:{challenge_id}"],
                    args=[user_answer_str, expected_user_str]
                )
                status, user_id, features_raw, attempts_left = res
                attempts_left = int(attempts_left)
                features = json.loads(features_raw) if features_raw else {}

                if status == "SUCCESS":
                    self.update_model(features, label="human")
                    self.set_verified_human(user_id, duration_seconds=300)
                    with self._lock:
                        self.stats["challenges_passed"] += 1
                        self._local_penalty_box.pop(user_id, None)
                        self._local_history.pop(user_id, None)
                        self._local_strikes.pop(user_id, None)
                        self._local_challenges.pop(challenge_id, None)
                    return True, "Verification successful! You are verified as human for 5 minutes. You may continue using your remaining quota (up to 10 requests/min)."

                elif status == "WRONG_ANSWER":
                    return False, f"Incorrect verification answer. {attempts_left} attempt(s) remaining."

                elif status == "EXHAUSTED":
                    self.update_model(features, label="spammer")
                    self.jail_user(user_id, duration_seconds=120)
                    with self._lock:
                        self.stats["challenges_exhausted"] += 1
                    return False, "Incorrect verification answer. Maximum verification attempts exceeded. User temporarily jailed."

                elif status == "USER_MISMATCH":
                    return False, "Challenge was issued to a different user session."

                else:
                    return False, "Invalid or expired challenge. Please request a new one."
            except Exception:
                pass

        # 2. Local Fallback Verification Path
        now = time.time()
        with self._lock:
            challenge = self._local_challenges.get(challenge_id)
            if not challenge:
                return False, "Invalid or expired challenge. Please request a new one."

            if now > challenge["expires_at"]:
                del self._local_challenges[challenge_id]
                return False, "Challenge expired. Please request a new one."

            user_id = challenge["user_id"]
            if not expected_user_str or expected_user_str != user_id:
                return False, "Challenge was issued to a different user session."

            features = challenge["features"]
            is_correct = (user_answer_str == str(challenge["expected_answer"]).strip())

            if is_correct:
                del self._local_challenges[challenge_id]
                self.update_model(features, label="human")
                self.set_verified_human(user_id, duration_seconds=300)
                self.stats["challenges_passed"] += 1
                self._local_penalty_box.pop(user_id, None)
                self._local_history.pop(user_id, None)
                self._local_strikes.pop(user_id, None)
                return True, "Verification successful! You are verified as human for 5 minutes. You may continue using your remaining quota (up to 10 requests/min)."
            else:
                challenge["attempts_left"] = challenge.get("attempts_left", 3) - 1
                if challenge["attempts_left"] <= 0:
                    del self._local_challenges[challenge_id]
                    self.update_model(features, label="spammer")
                    self.jail_user(user_id, duration_seconds=120)
                    self.stats["challenges_exhausted"] += 1
                    return False, "Incorrect verification answer. Maximum verification attempts exceeded. User temporarily jailed."
                return False, f"Incorrect verification answer. {challenge['attempts_left']} attempt(s) remaining."

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
        duration_seconds = int(validate_positive_number("duration_seconds", duration_seconds))
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
        Derives a heuristic Device Fingerprint based on untrusted client telemetry
        (browser headers and optional client-provided device ID).

        SECURITY NOTICE:
        HTTP request headers and device IDs are entirely client-controlled untrusted
        telemetry. They are NOT tamper-resistant or cryptographically secure, and CANNOT
        provide verified hardware identity. This fingerprint serves strictly as a heuristic
        anomaly detection signal (e.g. for statistical VPN-hopping clustering) and MUST NEVER
        be used as an authentication mechanism.
        """
        import hashlib
        explicit_id = str(headers.get("device-id") or headers.get("x-device-id") or "").strip()
        lang = headers.get("accept-language", "")
        enc = headers.get("accept-encoding", "")
        ch_ua = headers.get("sec-ch-ua", "")
        platform = headers.get("sec-ch-ua-platform", "")
        raw = f"{explicit_id}|{user_agent}|{lang}|{enc}|{ch_ua}|{platform}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"dev_{digest}"
    def is_in_penalty_box(self, user_id: str, client_ip: str = "", device_id: str = "") -> Tuple[bool, int]:
        """
        Checks if a user, their physical client IP, OR their Device Fingerprint
        is currently jailed in a single atomic round trip.
        Returns (is_jailed, remaining_seconds).
        """
        targets = []
        if user_id:
            targets.append(user_id)
        if client_ip:
            targets.append(f"ip:{client_ip}")
        if device_id:
            targets.append(f"dev:{device_id}")

        if not targets:
            return False, 0

        # 1. Distributed Redis Atomic Path
        if self.redis and getattr(self, "_penalty_check_script", None):
            try:
                keys = [f"penalty_box:{t}" for t in targets]
                res = self._penalty_check_script(keys=keys)
                is_jailed, ttl, _ = res
                if is_jailed == 1 and ttl > 0:
                    return True, int(ttl)
            except Exception:
                pass

        # 2. Local Fallback Path
        now = time.time()
        with self._lock:
            for target in targets:
                expiry = self._local_penalty_box.get(target)
                if expiry:
                    if now < expiry:
                        return True, int(expiry - now)
                    else:
                        del self._local_penalty_box[target]

        return False, 0

    def track_vpn_hopping(self, device_id: str, client_ip: str, max_allowed_ips: int = 2, window_seconds: float = 60.0) -> Tuple[bool, int]:
        """
        Detects VPN / Proxy IP rotation attacks atomically.
        If a single device fingerprint rotates across more than max_allowed_ips distinct IPs
        within window_seconds, flags as a VPN Hopping / IP Churning attack.
        Returns (is_vpn_hopping, distinct_ip_count).
        """
        max_allowed_ips = validate_positive_int("max_allowed_ips", max_allowed_ips)
        window_seconds = validate_positive_number("window_seconds", window_seconds)
        if not device_id or not client_ip:
            return False, 1

        now = time.time()
        cutoff = now - window_seconds
        expire_seconds = int(window_seconds) + 10

        # 1. Redis Atomic Lua Script
        if self.redis and getattr(self, "_sliding_window_script", None):
            try:
                key = f"dev_ips:{device_id}"
                res = self._sliding_window_script(
                    keys=[key],
                    args=[client_ip, now, cutoff, max_allowed_ips, expire_seconds]
                )
                is_violation, count = res
                return bool(is_violation == 1), int(count)
            except Exception:
                pass

        # 2. Local In-Memory Fallback
        with self._lock:
            if device_id not in self._local_device_ips:
                self._local_device_ips[device_id] = {}

            ip_map = self._local_device_ips[device_id]
            ip_map = {ip: t for ip, t in ip_map.items() if t > cutoff}
            ip_map[client_ip] = now
            self._local_device_ips[device_id] = ip_map

            count = len(ip_map)
            return (count > max_allowed_ips), count

    def track_identity_velocity(self, client_ip: str, user_id: str, max_allowed_ids: int = 3, window_seconds: float = 60.0) -> Tuple[bool, int]:
        """
        Detects Sybil / Account Cycling attacks atomically.
        If a single IP uses more than max_allowed_ids distinct user_ids within window_seconds,
        flags as a Sybil attack.
        Returns (is_sybil_attack, distinct_id_count).
        """
        max_allowed_ids = validate_positive_int("max_allowed_ids", max_allowed_ids)
        window_seconds = validate_positive_number("window_seconds", window_seconds)
        if not client_ip or not user_id:
            return False, 1

        now = time.time()
        cutoff = now - window_seconds
        expire_seconds = int(window_seconds) + 10

        # 1. Redis Atomic Lua Script
        if self.redis and getattr(self, "_sliding_window_script", None):
            try:
                key = f"ip_identities:{client_ip}"
                res = self._sliding_window_script(
                    keys=[key],
                    args=[user_id, now, cutoff, max_allowed_ids, expire_seconds]
                )
                is_violation, count = res
                return bool(is_violation == 1), int(count)
            except Exception:
                pass

        # 2. Local In-Memory Fallback
        with self._lock:
            if client_ip not in self._local_ip_identities:
                self._local_ip_identities[client_ip] = {}

            id_map = self._local_ip_identities[client_ip]
            id_map = {uid: t for uid, t in id_map.items() if t > cutoff}
            id_map[user_id] = now
            self._local_ip_identities[client_ip] = id_map

            count = len(id_map)
            return (count > max_allowed_ids), count

    def jail_user(self, user_id: str, duration_seconds: int = 60):
        """
        Temporarily places a detected spammer in the penalty box atomically.
        Clears historical timestamps so post-jail requests start with clean interval metrics.
        """
        if not user_id:
            return
        duration_seconds = int(validate_positive_number("duration_seconds", duration_seconds))

        # 1. Redis Atomic Jail Script
        if self.redis and getattr(self, "_jail_user_script", None):
            try:
                penalty_key = f"penalty_box:{user_id}"
                strike_key = f"strikes:{user_id}"
                history_key = f"traffic_history:{user_id}"
                res = self._jail_user_script(
                    keys=[penalty_key, strike_key, history_key],
                    args=[duration_seconds]
                )
                actual_duration, strikes = res
                with self._lock:
                    self._local_penalty_box[user_id] = time.time() + float(actual_duration)
                    self._local_history.pop(user_id, None)
                    self._local_strikes[user_id] = int(strikes)
                return
            except Exception:
                pass

        # 2. Local Fallback
        with self._lock:
            strikes = self._local_strikes.get(user_id, 0) + 1
            self._local_strikes[user_id] = strikes
            actual_duration = duration_seconds * min(strikes, 3)
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
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"count must be a non-negative integer, got {count}")
        if self.redis:
            try:
                self.redis.setex(f"strikes:{user_id}", 600, count)
            except Exception:
                pass
        with self._lock:
            self._local_strikes[user_id] = count

    def _get_and_update_history(self, user_id: str, timestamp: float, max_history: int = 12, window_seconds: float = 15.0) -> List[float]:
        """
        Maintains sliding window of request timestamps atomically.
        Prunes old timestamps and caps history in a single Redis transaction.
        """
        cutoff = timestamp - window_seconds

        # 1. Redis Atomic History Script
        if self.redis and getattr(self, "_traffic_history_script", None):
            try:
                key = f"traffic_history:{user_id}"
                raw = self._traffic_history_script(
                    keys=[key],
                    args=[timestamp, cutoff, max_history]
                )
                return [float(x) for x in raw]
            except Exception:
                pass

        # 2. Local Fallback
        with self._lock:
            hist = self._local_history.get(user_id, [])
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
        now = time.time()
        with self._lock:
            active_local = sum(1 for exp in self._local_penalty_box.values() if exp > now)
            metrics_dict = dict(self.stats)
            centroids = {
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
            }

        redis_jailed_count = 0
        redis_active = False
        if self.redis:
            try:
                count = 0
                for _ in self.redis.scan_iter("penalty_box:*"):
                    count += 1
                redis_jailed_count = count
                redis_active = True
            except Exception:
                redis_active = False

        if redis_active:
            total_jailed = redis_jailed_count + active_local
            note = "Aggregated count from Redis cluster (penalty_box:*) and local in-memory fallback state."
        else:
            total_jailed = active_local
            note = "Count reflects local in-memory fallback state only (Redis unavailable or not connected)."

        return {
            "metrics": metrics_dict,
            "model_centroids": centroids,
            "active_jailed_users": total_jailed,
            "active_jailed_users_note": note
        }
