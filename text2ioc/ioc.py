"""Python shim for the native Rust IoC extractor."""

from __future__ import annotations

import os
import re
import tempfile
from functools import lru_cache
from importlib import import_module
from pathlib import Path
from typing import Literal

import requests

_native = import_module("text2ioc._native")

FORCE_FILE_EXT = {
    "7z",
    "apk",
    "arj",
    "bat",
    "cab",
    "chm",
    "cmd",
    "cpl",
    "crt",
    "csv",
    "deb",
    "dll",
    "do",
    "doc",
    "docm",
    "docx",
    "drv",
    "elf",
    "evtx",
    "exe",
    "go",
    "gz",
    "hta",
    "ini",
    "iso",
    "jar",
    "java",
    "jpg",
    "js",
    "json",
    "jsp",
    "key",
    "ko",
    "lnk",
    "log",
    "mdb",
    "msg",
    "msi",
    "pdf",
    "pem",
    "php",
    "pif",
    "ppt",
    "pptm",
    "pptx",
    "py",
    "rar",
    "reg",
    "rpm",
    "rtf",
    "scr",
    "sh",
    "so",
    "sys",
    "tar",
    "text",
    "txt",
    "url",
    "vbe",
    "vbs",
    "war",
    "wav",
    "wsf",
    "xls",
    "xlsm",
    "xlsx",
    "xml",
    "yaml",
    "yml",
    "zip",
}

DEFAULT_TLDS = {
    "ac",
    "biz",
    "br",
    "cl",
    "cn",
    "co",
    "com",
    "de",
    "edu",
    "es",
    "fr",
    "gov",
    "hosting",
    "info",
    "io",
    "local",
    "mil",
    "mx",
    "net",
    "no",
    "onion",
    "org",
    "pl",
    "rs",
    "run",
    "sh",
    "tr",
    "uk",
    "xyz",
}

_DEFAULT_SORTED_TLDS = tuple(sorted(DEFAULT_TLDS))

IOC_REGEX = {
    "filepath": re.compile(
        r"""
        (?:
            (?: (?:~|\.{1,2})(?:/[\w.\-<>]+)+ (?:\.[a-zA-Z0-9]{1,6})? )
            |
            (?: /(?:[\w.\-<>]+/)*[\w.\-<>]+ (?:\.[a-zA-Z0-9]{1,6})? )
            |
            (?: \\\\[\w.$()<>-]+\\[\w.$()<>-]+(?:\\[\w.$()<>-]+)* )
            |
            (?: [A-Za-z]:\\(?:[\w\s().<>-]+\\)*(?:[\w\s().<>-]+(?:\.[A-Za-z0-9]{1,6})?)?\\? )
        )
        """,
        re.VERBOSE | re.IGNORECASE,
    ),
    "file": re.compile(
        r"""
        (?<![A-Za-z0-9_./$-])
        (
            [A-Za-z0-9][A-Za-z0-9_~-]*(?:\.[A-Za-z][A-Za-z0-9]{0,2}){1,3}
            |
            [A-Za-z0-9][A-Za-z0-9_~-]*
            (?:(?:\[\.\]|\[dot\]|\(dot\))[A-Za-z0-9][A-Za-z0-9_~-]*)*
            (?:\[\.\]|\[dot\]|\(dot\))
            (?:exe|dll|sys|scr|lnk|hta|bat|cmd|ps1|vbs|vbe|jse|jar|zip|rar|7z|iso|img|doc|docm|xls|xlsm|rtf|pdf|aspx|jsp|php)
        )
        (?![A-Za-z0-9_.-])
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    "url": re.compile(
        r"""
        \b
        (?:[A-Za-z][A-Za-z0-9+\-.]*)
        (?::|(?:\[\:\]))
        //
        (?:
            (?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:(?:\.|\[\.\]|\[dot\]|\(dot\)))){3}
            (?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})
            |
            [A-Za-z0-9-]+(?:(?:\.|\[\.\]|\[dot\]|\(dot\))[A-Za-z0-9-]+)+
        )
        (?::\d{1,5})?
        (?:/[^\s'"<>]*)?
        (?=$|[\s'"<>\]),.;:!?])
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    "domain": re.compile(
        r"""
        (?<![A-Za-z0-9-])
        (?:@)?
        (
            (?:\*\.)?
            [A-Za-z0-9-]+
            (?:(?:\.|\[\.\]|\[dot\]|\(dot\))[A-Za-z0-9-]+)+
        )
        \b
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    "email": re.compile(
        r"\b[a-z0-9._%+-]+(?:@|\[\@\]|\[at\]|\(at\))[a-z0-9-]+"
        r"(?:(?:\.|\[\.\]|\[dot\]|\(dot\))[a-z0-9-]+)*"
        r"(?:\.|\[\.\]|\[dot\]|\(dot\))[a-z]{2,63}\b",
        re.IGNORECASE,
    ),
    "ipv4": re.compile(
        r"\b(?:(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.|\[\.\]|\[dot\]|\(dot\))){3}"
        r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}))\b",
        re.IGNORECASE,
    ),
    "ipv6": re.compile(r"(?i)(?:^|[^0-9A-Za-z:])([0-9A-Fa-f:]{2,})(?:$|[^0-9A-Za-z:])"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "expressions": re.compile(r"\$\{[^}]+\}", re.IGNORECASE),
    "attack_technique_id": re.compile(
        r"(?i)(?:^|[^A-Za-z0-9_-])(T\d{4}(?:\.\d{3})?)(?:$|[^A-Za-z0-9_-])"
    ),
    "attack_tactic_id": re.compile(
        r"(?i)(?:^|[^A-Za-z0-9_-])(TA\d{4})(?:$|[^A-Za-z0-9_-])"
    ),
    "registry_key": re.compile(
        r"""
        (?:
            ^|[^A-Za-z0-9_]
        )
        (
            (?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)
            (?:\\[^\\/"'“”\r\n]+)+
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    "cwe": re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE),
    "ghsa": re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE),
    "capec": re.compile(r"\bCAPEC-\d{1,5}\b", re.IGNORECASE),
}

_CONTEXTUAL_FILE_RE = re.compile(
    r"""
    (?:
        ["“]
        |
        \(\s*["“]?
    )
    (
        [^"”'\n)]{1,220}
        \.(?:tar\.gz|tar\.bz2|tgz|zip|rar|7z|gz|exe|dll|sys|scr|lnk|hta|bat|cmd|ps1|vbs|vbe|jse|jar|iso|img|doc|docm|xls|xlsm|rtf|pdf|aspx|jsp|php|apk)
    )
    (?:
        ["”]
        |
        ["”]?\s*\)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def load_valid_tlds(file_path: str) -> set[str]:
    """Parse a public suffix list file via the native parser."""
    return set(_native.load_valid_tlds(file_path))


@lru_cache(maxsize=8)
def _load_sorted_valid_tlds_cached(cache_path: str, mtime_ns: int) -> tuple[str, ...]:
    valid_tlds = load_valid_tlds(cache_path)
    valid_tlds.add("onion")
    return tuple(sorted(valid_tlds))


def _get_sorted_valid_tlds() -> tuple[str, ...]:
    default_cache = Path(tempfile.gettempdir()) / "public_suffix_list.dat"
    cache_path = Path(os.getenv("IOC_TLD_CACHE", str(default_cache)))
    if not cache_path.exists():
        try:
            response = requests.get(
                "https://publicsuffix.org/list/public_suffix_list.dat", timeout=10
            )
            response.raise_for_status()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(response.text, encoding="utf-8")
        except (OSError, requests.RequestException):
            return _DEFAULT_SORTED_TLDS

    try:
        resolved = str(cache_path.resolve())
        mtime_ns = cache_path.stat().st_mtime_ns
        return _load_sorted_valid_tlds_cached(resolved, mtime_ns)
    except OSError:
        return _DEFAULT_SORTED_TLDS


def get_tld_set_from_public_suffix_list() -> set[str]:
    """Ensure the suffix list is downloaded and cached locally, then parsed."""
    return set(_get_sorted_valid_tlds())


def _is_unlikely_linux_path(path: str) -> bool:
    """Check if the root directory of a Linux path is uncommon."""
    return _native._is_unlikely_linux_path(path)


def _find_invalid_occurrences(text: str, sub: str) -> bool:
    """Check if `sub` appears in `text` in a valid file path context."""
    return _native._find_invalid_occurrences(text, sub)


def post_filter_false_positives(
    entries: list[str],
    kind: Literal[
        "domain",
        "email",
        "file",
        "filepath",
        "ipv4",
        "attack_technique_id",
        "attack_tactic_id",
        "registry_key",
        "cwe",
        "ghsa",
        "capec",
    ],
    text: str | None = None,
) -> list[str]:
    """Filter out false positives from domains, file names, or paths."""
    valid_tlds = _get_sorted_valid_tlds()
    return list(_native.post_filter_false_positives(entries, kind, valid_tlds, text))


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract and deduplicate Indicators of Compromise from text."""
    valid_tlds = _get_sorted_valid_tlds()
    return _native.extract_iocs(text, valid_tlds)


__all__ = [
    "IOC_REGEX",
    "_find_invalid_occurrences",
    "_is_unlikely_linux_path",
    "load_valid_tlds",
    "extract_iocs",
    "get_tld_set_from_public_suffix_list",
    "post_filter_false_positives",
]
