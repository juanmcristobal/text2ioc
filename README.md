# text2ioc

`text2ioc` extracts Indicators of Compromise (IoCs) from unstructured text such as articles, reports, logs, and threat-intelligence notes.

Install from PyPI:

```bash
pip install test2ioc
```

## Usage

```python
from text2ioc.ioc import extract_iocs

text = (
    "Download https://dpaste[.]com/9MQEJ6VYR.txt from 77.221.158[.]154 "
    "and contact ops[at]example.org."
)

iocs = extract_iocs(text)
print(iocs["url"])
print(iocs["ipv4"])
print(iocs["email"])
```

Expected output:

```python
['https://dpaste[.]com/9MQEJ6VYR.txt']
['77.221.158[.]154']
['ops[at]example.org']
```

## Public API

- `extract_iocs(text: str) -> dict[str, list[str]]`
- `get_tld_set_from_public_suffix_list() -> set[str]`
- `post_filter_false_positives(entries, kind, text=None) -> list[str]`
- `_is_unlikely_linux_path(path: str) -> bool`
- `_find_invalid_occurrences(text: str, sub: str) -> bool`

## Development

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

## Tox

```bash
tox
```

## CI and packaging

- Tests run on Linux, macOS, and Windows.
- Coverage is still checked in CI.
- Wheels and sdist are built with `maturin-action`.
- The distributed package name is `test2ioc` and the import package remains `text2ioc`.

## Authors

- **Juan Manuel Cristóbal Moreno** - <juanmcristobal@gmail.com>
