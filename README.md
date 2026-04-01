<p align="center">
  <img src="banner-header.png" alt="text2ioc banner">
</p>

# text2ioc

`text2ioc` extracts Indicators of Compromise (IoCs) from unstructured text such as articles, reports, logs, and threat-intelligence notes.

> Disclaimer
> `text2ioc` is a deterministic pattern-extraction package, not a threat-intelligence validation engine. It combines regex matching with heuristic post-filtering, so many returned values are best understood as candidate IoC-like patterns rather than strict, confirmed IoCs.

Install from PyPI:

```bash
pip install text2ioc
```

## Usage

```python
import json

from text2ioc.ioc import extract_iocs

text = (
    "Download https://dpaste[.]com/9MQEJ6VYR.txt from 77.221.158[.]154, "
    "contact ops[at]example.org, and review T1059.001 linked to TA0002."
)

iocs = extract_iocs(text)
print(json.dumps(iocs, indent=2))
```

Expected output:

```json
{
  "filepath": [],
  "file": [],
  "url": [
    "https://dpaste[.]com/9MQEJ6VYR.txt"
  ],
  "domain": [],
  "email": [
    "ops[at]example.org"
  ],
  "ipv4": [
    "77.221.158[.]154"
  ],
  "ipv6": [],
  "md5": [],
  "sha1": [],
  "sha256": [],
  "cve": [],
  "expressions": [],
  "attack_technique_id": [
    "T1059.001"
  ],
  "attack_tactic_id": [
    "TA0002"
  ],
  "registry_key": [],
  "cwe": [],
  "ghsa": [],
  "capec": []
}
```

## Field Semantics

The extractor is regex-first, then removes false positives with explicit heuristics. It does not resolve domains, validate reachability, or decide whether an indicator is malicious. It only returns strings that match the current parsing rules.

- `filepath`: Unix, Windows, UNC, and relative paths. It trims trailing punctuation, keeps quoted paths, and discards bare basenames without extensions, unlikely Linux roots, and slash-prefixed strings that do not appear in a path-like context.
- `file`: File names and suspicious extensions, including defanged forms like `cmd[dot]exe`. It excludes obvious domains, version-like tokens, `e.g` / `i.e`, and many-segment dotted identifiers that look more like namespaces than files.
- `url`: URLs with an explicit scheme, optional port, and optional path. It accepts normal and defanged separators, plus IPv4 hosts. It does not keep malformed schemes, malformed ports, or plain hostnames without a scheme.
- `domain`: Plain domains, subdomains, wildcard domains, defanged domains, and `.onion` addresses. It excludes items with invalid or unsupported TLDs, file extensions, `README.md`, permission-style names, reverse-domain identifiers, EC2 shapes, Azure namespaces, `ANY.RUN`, code symbols like `EndpointRequest.to()`, markup/CMS fragments, and legal-entity strings like `Co.LTD` when the surrounding context looks organizational rather than web-related.
- `email`: Standard and defanged email addresses. The domain part must end in a valid TLD and must not look like a file extension. Domain-like fragments that are only part of an email are intentionally not duplicated under `domain`.
- `ipv4`: Standard and defanged IPv4 addresses. It excludes invalid octets, partial quads, and version-like quads in advisory/product contexts, including cases with leading-zero octets such as `16.03.08.12` or parenthetical build suffixes such as `1.2.0.14(408)`.
- `ipv6`: Standard and compressed IPv6 forms such as `::1` and `2001:db8::1`. It excludes malformed addresses with invalid hex groups or invalid double compression.
- `md5`: Exactly 32 hexadecimal characters.
- `sha1`: Exactly 40 hexadecimal characters.
- `sha256`: Exactly 64 hexadecimal characters.
- `cve`: Tokens matching `CVE-YYYY-NNNN...`.
- `expressions`: Template-like expressions in `${...}` form.
- `attack_technique_id`: MITRE ATT&CK technique IDs such as `T1059` or `T1059.001`. It does not synthesize IDs from ATT&CK URL paths like `/T1059/001/`.
- `attack_tactic_id`: MITRE ATT&CK tactic IDs such as `TA0001`.
- `registry_key`: Windows registry paths rooted in a known hive such as `HKLM`, `HKCU`, or `HKEY_LOCAL_MACHINE`, with one or more subkeys. It avoids swallowing trailing command arguments.
- `cwe`: Tokens matching `CWE-N`.
- `ghsa`: GitHub advisory IDs such as `GHSA-v63m-x9r9-8gqp`.
- `capec`: Tokens matching `CAPEC-N`.

General filtering that is already codified today:

- Results are deduplicated, and shorter matches that are fully contained inside longer ones are dropped.
- The extractor uses the Public Suffix List for domain and email TLD validation, with a built-in fallback set when the suffix list cannot be fetched or parsed.
- For `domain`, if mixed defanged/plain candidates appear together, the code keeps the explicitly domain-like ones and avoids re-emitting noisy fragments.

## Support & Connect

* ⭐ **Star the repo** if you found it useful
* ☕ **Support me:** Say thanks by buying me a coffee! [https://buymeacoffee.com/juanmcristobal](https://buymeacoffee.com/juanmcristobal)
* 💼 **Open to work:** [https://www.linkedin.com/in/jmcristobal/](https://www.linkedin.com/in/jmcristobal/)
