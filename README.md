# text2ioc

`text2ioc` extracts Indicators of Compromise (IoCs) from unstructured text such as articles, reports, logs, and threat-intelligence notes.

The package now uses a Rust core built with `PyO3` and `maturin` while preserving the existing Python API:

- `extract_iocs(text: str) -> dict[str, list[str]]`
- `get_tld_set_from_public_suffix_list() -> set[str]`
- `post_filter_false_positives(entries, kind, text=None) -> list[str]`
- `_is_unlikely_linux_path(path: str) -> bool`
- `_find_invalid_occurrences(text: str, sub: str) -> bool`

## Development prerequisites

- Python 3.10+
- Rust stable toolchain installed with `rustup`
- `maturin`

Local toolchain setup:

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
pip3 install --user -r requirements_dev.txt
```

## Local development

Build the native module into your active Python environment:

```bash
maturin develop --release
```

Run the test suite:

```bash
pytest
```

Run coverage:

```bash
coverage run --source text2ioc -m pytest
coverage report --show-missing --fail-under=95
```

Run the parity and performance benchmark against the Python oracle:

```bash
python benchmarks/benchmark_extract.py --min-speedup 5
```

## Tox

```bash
tox
tox -e benchmark
```

## CI and packaging

- Tests run on Linux, macOS, and Windows.
- Wheels and sdist are built with `maturin-action`.
- The Python implementation under `tests/oracle_ioc.py` is kept only as a private oracle for parity and benchmark checks.

## Authors

- **Juan Manuel Cristóbal Moreno** - <juanmcristobal@gmail.com>
