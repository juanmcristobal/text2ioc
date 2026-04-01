from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.oracle_ioc import extract_iocs_with_tlds
from text2ioc import extract_iocs
from text2ioc.core.ioc import load_valid_tlds

FAKE_SUFFIX_LIST = """
// benchmark suffix list
ac
co
com
edu
gov
io
mil
net
org
rs
sh
uk
xyz
cn
"""

CORPUS_SEGMENTS = [
    "Download from https://dpaste[.]com/9MQEJ6VYR.txt and copy it to /tmp/9MQEJ6VYR.txt.",
    "Observed 77.221.158[.]154 contacting tracker.badactor[.]net from bob.smith@sub.mail-domain.co.",
    'Windows paths included "C:\\Windows\\System32\\winevt\\logs\\ Security.evtx " and D:\\Backups\\My Documents\\file.txt.',
    "Payloads included evil.exe, archive.tar, ${CONFIG_PATH}, CVE-2021-34527, and e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
]


def build_corpus(multiplier: int = 400) -> str:
    return "\n".join(CORPUS_SEGMENTS * multiplier)


def benchmark(fn, text: str, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn(text)
    return time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=80)
    parser.add_argument("--min-speedup", type=float, default=5.0)
    args = parser.parse_args()

    cache_dir = Path(".benchmark-cache")
    cache_dir.mkdir(exist_ok=True)
    cache_path = cache_dir / "public_suffix_list.dat"
    cache_path.write_text(FAKE_SUFFIX_LIST, encoding="utf-8")
    os.environ["IOC_TLD_CACHE"] = str(cache_path.resolve())

    valid_tlds = load_valid_tlds(str(cache_path))
    corpus = build_corpus()

    expected = extract_iocs_with_tlds(corpus, valid_tlds)
    actual = extract_iocs(corpus)
    if actual != expected:
        raise SystemExit("Rust runtime output does not match the Python oracle.")

    oracle_time = benchmark(
        lambda payload: extract_iocs_with_tlds(payload, valid_tlds), corpus, args.iterations
    )
    rust_time = benchmark(extract_iocs, corpus, args.iterations)
    speedup = oracle_time / rust_time if rust_time else float("inf")

    print(f"oracle_time={oracle_time:.6f}s")
    print(f"rust_time={rust_time:.6f}s")
    print(f"speedup={speedup:.2f}x")

    if speedup < args.min_speedup:
        raise SystemExit(
            f"Expected at least {args.min_speedup:.2f}x speedup, observed {speedup:.2f}x."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
