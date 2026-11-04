"""
Process and Server Lifecycle Manager for Benchmark Orchestration.
Guarantees clean startup, readiness probing, and strict termination of Uvicorn & Redis servers.
"""

import os
import socket
import subprocess
import sys
import time
import threading
from typing import Optional, Tuple, Dict, Any
import redis
import httpx

from benchmarks.config import BenchmarkConfig


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks whether a local TCP port is already open and accepting connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def find_free_port(start_port: int = 8000, max_tries: int = 50) -> int:
    """Finds an unused local TCP port."""
    for p in range(start_port, start_port + max_tries):
        if not is_port_in_use(p):
            return p
    raise RuntimeError(f"Unable to find free port in range {start_port}..{start_port + max_tries}")


class RedisServerManager:
    """
    Manages Redis connectivity.
    If external Redis is reachable at config.redis_url, uses it.
    Otherwise, starts an embedded TCP Redis server via fakeredis for local zero-dependency testing.
    """

    def __init__(self, target_url: str = "redis://127.0.0.1:6379", fallback_port: int = 6389):
        self.target_url = target_url
        self.fallback_port = fallback_port
        self.active_url = target_url
        self.is_embedded = False
        self._server = None
        self._thread = None

    def start(self) -> str:
        # First check if external Redis is alive
        try:
            r = redis.from_url(self.target_url, socket_timeout=0.5, socket_connect_timeout=0.5)
            if r.ping():
                self.active_url = self.target_url
                self.is_embedded = False
                return self.active_url
        except Exception:
            pass

        # Start embedded TCP Redis server
        try:
            import fakeredis
            free_p = find_free_port(self.fallback_port)
            self._server = fakeredis.TcpFakeServer(("127.0.0.1", free_p))
            self._server.daemon_threads = True
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            time.sleep(0.3)

            # Probe embedded server
            probe = redis.Redis(host="127.0.0.1", port=free_p, socket_timeout=1.0)
            if probe.ping():
                self.active_url = f"redis://127.0.0.1:{free_p}"
                self.is_embedded = True
                return self.active_url
            else:
                raise RuntimeError("Embedded Redis server failed ping probe.")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Redis backend: {e}") from e

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
            self._thread = None
            self.is_embedded = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


class UvicornServerManager:
    """
    Manages Uvicorn FastAPI server subprocess lifecycle.
    Supports running with configurable worker processes (1, 2, 4) and strict teardown.
    """

    def __init__(
        self,
        config: BenchmarkConfig,
        workers: int = 1,
        redis_url: Optional[str] = None,
        extra_env: Optional[Dict[str, str]] = None
    ):
        self.config = config
        self.workers = workers
        self.redis_url = redis_url or config.redis_url
        self.extra_env = extra_env or {}
        self.process: Optional[subprocess.Popen] = None
        self.port = config.port

    def start(self) -> str:
        # Check if port is free
        if is_port_in_use(self.port, self.config.host):
            self.port = find_free_port(self.port + 1)

        env = os.environ.copy()
        env["REDIS_URL"] = self.redis_url
        env["ENVIRONMENT"] = "production"
        env["AUTH_SECRET_KEY"] = self.config.auth_secret_key
        env["ADMIN_API_KEY"] = "admin-secret-at-least-32-chars-long-12345"
        env["METRICS_API_KEY"] = "metrics-secret-at-least-32-chars-long-12345"
        env["REQUIRE_AUTH"] = "true"
        env["PROTECT_METRICS"] = "true"
        env["ALLOW_UNAUTHENTICATED_DEV_HEADERS"] = "false"
        env["RATE_LIMITER_FAILURE_MODE"] = "fail_closed"
        if self.config.redis_password:
            env["REDIS_PASSWORD"] = self.config.redis_password
            env["REDIS_AUTH_MODE"] = "password"
        else:
            # Attest local loopback/isolated benchmark Redis
            env["REDIS_AUTH_MODE"] = "network_isolated"
            env["ATTEST_NETWORK_ISOLATED_REDIS"] = "true"
        env["RATE_LIMITER_CAPACITY"] = "100000.0"
        env["IP_RATE_LIMITER_CAPACITY"] = "100000.0"
        env["RATE_LIMITER_REFILL_RATE"] = "1.0"
        env["IP_RATE_LIMITER_REFILL_RATE"] = "1.0"

        for k, v in self.extra_env.items():
            env[k] = v

        cmd = [
            sys.executable,
            "-m", "uvicorn",
            "main:app",
            "--host", self.config.host,
            "--port", str(self.port),
            "--workers", str(self.workers),
            "--log-level", "warning"
        ]

        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.config.output_dir / f"uvicorn_{self.port}.log"
        self.log_file = open(self.log_path, "w", encoding="utf-8", errors="replace")

        self.process = subprocess.Popen(
            cmd,
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Readiness Probe
        base_url = f"http://{self.config.host}:{self.port}"
        ready = False
        start_wait = time.perf_counter()

        while time.perf_counter() - start_wait < 15.0:
            if self.process.poll() is not None:
                self.log_file.flush()
                err_text = ""
                if self.log_path.exists():
                    try:
                        err_text = self.log_path.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        pass
                raise RuntimeError(
                    f"Uvicorn process exited prematurely with code {self.process.returncode}:\n{err_text}"
                )
            try:
                with httpx.Client(timeout=0.5) as client:
                    resp = client.get(f"{base_url}/")
                    if resp.status_code == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.2)

        if not ready:
            self.stop()
            raise TimeoutError(f"Uvicorn server failed to report ready within 15 seconds on port {self.port}")

        return base_url

    def stop(self) -> None:
        if self.process:
            try:
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                        capture_output=True,
                        check=False
                    )
                else:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=3.0)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=2.0)
            except Exception:
                pass
            finally:
                self.process = None

        if hasattr(self, "log_file") and self.log_file:
            try:
                self.log_file.flush()
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None

    def __enter__(self):
        url = self.start()
        return url

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
