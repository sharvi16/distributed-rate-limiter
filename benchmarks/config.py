"""
Benchmark Configuration and Environment Metadata Models.
"""

from dataclasses import dataclass, field, asdict
import os
import platform
import multiprocessing
import sys
import time
from typing import List, Dict, Any, Optional
from pathlib import Path


@dataclass
class EnvironmentMetadata:
    """Metadata describing the runtime hardware, OS, and software environment."""
    os_name: str = field(default_factory=platform.system)
    os_release: str = field(default_factory=platform.release)
    os_version: str = field(default_factory=platform.version)
    platform_machine: str = field(default_factory=platform.machine)
    processor: str = field(default_factory=platform.processor)
    cpu_cores: int = field(default_factory=multiprocessing.cpu_count)
    python_version: str = field(default_factory=lambda: sys.version.split()[0])
    python_implementation: str = field(default_factory=platform.python_implementation)
    timestamp_utc: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    redis_version: Optional[str] = None
    redis_mode: str = "distributed"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkConfig:
    """Configuration settings for benchmark runs."""
    concurrency_levels: List[int] = field(default_factory=lambda: [1, 10, 50, 100, 250, 500])
    worker_counts: List[int] = field(default_factory=lambda: [1, 2, 4])
    default_concurrency: int = 50
    requests_per_test: int = 1000
    warmup_requests: int = 100
    duration_seconds: float = 5.0
    warmup_duration_seconds: float = 1.0
    timeout_seconds: float = 10.0
    host: str = "127.0.0.1"
    port: int = 8000
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://127.0.0.1:6379"))
    redis_password: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_PASSWORD"))
    auth_secret_key: str = field(
        default_factory=lambda: os.getenv(
            "AUTH_SECRET_KEY",
            "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e"
        )
    )
    output_dir: Path = field(default_factory=lambda: Path("benchmarks/results"))
    quick_mode: bool = False

    def __post_init__(self):
        if self.quick_mode:
            self.concurrency_levels = [1, 10, 50]
            self.worker_counts = [1, 2]
            self.requests_per_test = 200
            self.warmup_requests = 20
            self.duration_seconds = 2.0
            self.warmup_duration_seconds = 0.5

        if isinstance(self.output_dir, str):
            self.output_dir = Path(self.output_dir)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
