"""Python oracle implementation used only for parity and benchmark tests."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal, Optional

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
    "mitre_attack_t": re.compile(
        r"(?i)(?:^|[^A-Za-z0-9_-])(T\d{4}(?:\.\d{3})?)(?:$|[^A-Za-z0-9_-])"
    ),
    "mitre_tactic": re.compile(
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

CONTEXTUAL_FILE_RE = re.compile(
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


def _push_unique(values: list[str], seen: set[str], value: str) -> None:
    if value not in seen:
        seen.add(value)
        values.append(value)


def _extract_direct(pattern: re.Pattern[str], text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for matched in pattern.finditer(text):
        _push_unique(values, seen, matched.group(0))
    return values


def _extract_capture_group(
    pattern: re.Pattern[str], text: str, group: int = 1
) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for capture in pattern.finditer(text):
        _push_unique(values, seen, capture.group(group))
    return values


def _extract_url_matches(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for matched in IOC_REGEX["url"].finditer(text):
        item = matched.group(0).rstrip(" \t\r\n'\"<>),.;:!?]")
        if not item:
            continue
        item_end = matched.start() + len(item)
        if item_end < len(text) and (
            text[item_end] == ":" or text[item_end] == "_" or text[item_end].isalnum()
        ):
            continue
        _push_unique(values, seen, item)
    return values


def _extract_file_matches(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for capture in IOC_REGEX["file"].finditer(text):
        if not _is_valid_file_boundary(text, capture.start(), capture.end()):
            continue
        _push_unique(values, seen, capture.group(1))
    for capture in CONTEXTUAL_FILE_RE.finditer(text):
        item = capture.group(1).strip().rstrip(" .,:;!?")
        if not item:
            continue
        _push_unique(values, seen, item)
    return values


def _extract_domain_matches(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for capture in IOC_REGEX["domain"].finditer(text):
        if not _is_valid_domain_start(text, capture.start()):
            continue
        if _is_embedded_email_domain_start(text, capture.start(1)):
            continue
        _push_unique(values, seen, capture.group(1))
    return values


def _extract_registry_matches(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for capture in IOC_REGEX["registry_key"].finditer(text):
        item = capture.group(1).strip().rstrip(" .,:;!?)]")
        if not item:
            continue
        _push_unique(values, seen, item)
    return values


def _extract_ipv4_matches(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for matched in IOC_REGEX["ipv4"].finditer(text):
        start, end = matched.span()
        prev_char = text[start - 1] if start > 0 else None
        next_char = text[end] if end < len(text) else None
        if prev_char and (prev_char.isalnum() or prev_char == "_"):
            continue
        if next_char and (next_char.isalnum() or next_char == "_"):
            continue
        _push_unique(values, seen, matched.group(0))
    return values


def _extract_ipv6_matches(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for capture in IOC_REGEX["ipv6"].finditer(text):
        item = capture.group(1)
        if ":" not in item or item.count(":") < 2:
            continue
        if not any(ch.isdigit() for ch in item):
            continue
        try:
            ipaddress.IPv6Address(item)
        except ValueError:
            continue
        _push_unique(values, seen, item)
    return values


def _is_valid_file_boundary(text: str, start: int, end: int) -> bool:
    prev_char = text[start - 1] if start > 0 else None
    next_char = text[end] if end < len(text) else None
    if prev_char and (prev_char.isalnum() or prev_char in {"_", ".", "/", "$", "-"}):
        return False
    if next_char and (next_char.isalnum() or next_char in {"_", ".", "-"}):
        return False
    return True


def _is_valid_domain_start(text: str, start: int) -> bool:
    if start == 0:
        return True
    prev_char = text[start - 1]
    return not (prev_char.isalnum() or prev_char == "-")


def _is_embedded_email_domain_start(text: str, start: int) -> bool:
    if start == 0 or text[start - 1] != "@":
        return False
    if start < 2:
        return False
    return text[start - 2].isalnum() or text[start - 2] in {".", "_", "%", "+", "-"}


def _canonicalize_dot_separators(value: str) -> str:
    return value.replace("[.]", ".").replace("[dot]", ".").replace("(dot)", ".")


def _canonicalize_email_separators(value: str) -> str:
    return (
        _canonicalize_dot_separators(value)
        .replace("[@]", "@")
        .replace("[at]", "@")
        .replace("(at)", "@")
    )


def _contains_defanged_dot(value: str) -> bool:
    return "[.]" in value or "[dot]" in value or "(dot)" in value


def _should_keep_domain_in_mixed_results(domain: str) -> bool:
    lower = domain.lower()
    return _contains_defanged_dot(lower) or _canonicalize_dot_separators(
        lower
    ).endswith(".onion")


def _is_unlikely_linux_path(path: str) -> bool:
    valid_root_dirs = {
        "bin",
        "boot",
        "cdrom",
        "dev",
        "etc",
        "home",
        "lib",
        "lib32",
        "lib64",
        "libx32",
        "lost+found",
        "media",
        "mnt",
        "opt",
        "path",
        "proc",
        "root",
        "run",
        "sbin",
        "snap",
        "srv",
        "sys",
        "tmp",
        "usr",
        "var",
    }
    if not path.startswith("/") or len(path) < 2:
        return False
    parts = path[1:].split("/")
    return parts[0] not in valid_root_dirs


def _find_invalid_occurrences(text: str, sub: str) -> bool:
    idx = 0
    text_aux = text
    while idx < len(text_aux):
        idx = text_aux.find(sub)
        if idx == -1:
            break
        if (
            idx > 0
            and text_aux[idx - 1] in {".", "~", " ", "'", '"'}
            and not _is_unlikely_linux_path(sub)
        ):
            return True
        if (
            idx == 0
            and text_aux[idx] in {".", "~", " ", "'", '"', "/"}
            and not _is_unlikely_linux_path(sub)
        ):
            return True
        next_index = idx + len(sub)
        text_aux = text_aux[next_index:]
    return False


_IPV4_VERSION_CONTEXT_RE = re.compile(
    r"""
    \b(?:versions?|release(?:d)?|build|firmware|patch(?:ed)?|fixed|affected|vendor|product|model|
    portal|router|plugin|component|module|appliance|kernel|dxp|edition|revision|rev|
    through|up\s+to|prior\s+to|before|since|until|lt|lte|gt|gte)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)
_IPV4_ADVISORY_WORD_RE = re.compile(
    r"\b(?:vulnerability|vulnerable|issue|flaw|advisory|classified|detected|discovered|found)\b",
    re.IGNORECASE,
)
_THREE_PART_VERSION_CAPTURE_RE = re.compile(
    r"(?<![\d.])(\d+\.\d+\.\d+)(?!\.\d)", re.IGNORECASE
)
_IPV4_PAREN_SUFFIX_RE = re.compile(r"^\s*\([0-9A-Za-z._-]{1,24}\)")


def _normalize_ipv4_context(text: str) -> str:
    return " ".join(_canonicalize_dot_separators(text.lower()).split())


def _has_leading_zero_ipv4_octet(value: str) -> bool:
    parts = _canonicalize_dot_separators(value.lower()).split(".")
    return any(len(part) > 1 and part.startswith("0") for part in parts)


def _has_ipv4_parenthetical_suffix(text: str, entry_pos: int, entry: str) -> bool:
    if not text or entry_pos < 0:
        return False
    end = min(entry_pos + len(entry), len(text))
    return bool(_IPV4_PAREN_SUFFIX_RE.match(text[end:]))


def _is_ipv4_context_break(ch: str) -> bool:
    return ch in {"\n", "\r", "!", "?", ";"}


def _ipv4_context_window(text: str, entry_pos: int, entry: str) -> str:
    if not text or entry_pos < 0:
        return ""

    window = 160
    end = min(entry_pos + len(entry), len(text))
    left = max(0, entry_pos - window)
    right = min(len(text), end + window)

    for idx in range(entry_pos - 1, left - 1, -1):
        if _is_ipv4_context_break(text[idx]):
            left = idx + 1
            break

    for idx in range(end, right):
        if _is_ipv4_context_break(text[idx]):
            right = idx
            break

    return text[left:right].strip()


def _has_ipv4_range_pattern(context: str, item: str) -> bool:
    keywords = (
        "through",
        "up to",
        "prior to",
        "before",
        "since",
        "until",
        "lt",
        "lte",
        "gt",
        "gte",
    )
    return any(
        f"{keyword} {item}" in context or f"{item} {keyword}" in context
        for keyword in keywords
    )


def _has_direct_ipv4_version_label(context: str, item: str) -> bool:
    labels = (
        "version",
        "versions",
        "release",
        "released",
        "build",
        "firmware",
        "revision",
        "rev",
    )
    return any(f"{label} {item}" in context or f"{item} {label}" in context for label in labels)


def _has_product_like_prefix(context: str, item: str) -> bool:
    item_pos = context.find(item)
    if item_pos == -1:
        return False

    prefix = context[:item_pos].rstrip(" ([{:,")
    for token in reversed(prefix.split()[-3:]):
        if token in {"in", "on", "for", "to", "the", "of", "and"}:
            continue
        if any(ch.isalpha() for ch in token) and (
            any(ch.isdigit() for ch in token) or "-" in token
        ):
            return True
    return False


def _has_nearby_three_part_version_token(context: str, item: str) -> bool:
    item_pos = context.find(item)
    if item_pos == -1:
        return False

    for match in _THREE_PART_VERSION_CAPTURE_RE.finditer(context):
        distance = match.start(1) - item_pos if match.start(1) > item_pos else item_pos - match.end(1)
        if distance <= 48:
            return True
    return False


def _has_version_list_separator(context: str) -> bool:
    return "|" in context or "," in context or " and " in context or " or " in context


def _is_probable_ipv4_version(entry: str, text: str, entry_pos: int) -> bool:
    if _has_leading_zero_ipv4_octet(entry) or _has_ipv4_parenthetical_suffix(
        text, entry_pos, entry
    ):
        return True

    if not text or entry_pos < 0:
        return False

    raw_context = _ipv4_context_window(text, entry_pos, entry)
    if not raw_context:
        return False

    normalized_context = _normalize_ipv4_context(raw_context)
    if not normalized_context:
        return False

    normalized_item = _canonicalize_dot_separators(entry.lower())
    has_context_keyword = bool(
        _IPV4_VERSION_CONTEXT_RE.search(normalized_context)
        or _IPV4_ADVISORY_WORD_RE.search(normalized_context)
    )
    has_nearby_three_part = _has_nearby_three_part_version_token(
        normalized_context, normalized_item
    )
    has_range_pattern = _has_ipv4_range_pattern(normalized_context, normalized_item)
    has_direct_version_label = _has_direct_ipv4_version_label(
        normalized_context, normalized_item
    )
    has_version_enumeration = has_nearby_three_part and _has_version_list_separator(
        normalized_context
    )
    has_product_prefix = bool(
        _IPV4_ADVISORY_WORD_RE.search(normalized_context)
        and _has_product_like_prefix(normalized_context, normalized_item)
    )

    return has_context_keyword and (
        has_nearby_three_part
        or has_range_pattern
        or has_direct_version_label
        or has_version_enumeration
        or has_product_prefix
    )


def _is_proper_substring(shorter: str, longer: str) -> bool:
    return shorter != longer and shorter in longer


def post_filter_false_positives_with_tlds(
    entries: list[str],
    kind: Literal["domain", "email", "file", "filepath", "ipv4"],
    valid_tlds: set[str],
    text: Optional[str] = None,
) -> list[str]:
    text = text or ""

    ipv4 = IOC_REGEX["ipv4"]
    python_module_pattern = re.compile(
        r"^(os|sys|re|json|time|datetime|subprocess|pathlib|shutil|logging|math|base64|hashlib)"
        r"\.[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$",
        re.IGNORECASE,
    )
    tech_keywords_pattern = re.compile(
        r"\b(node\.?js|asp\.?net|python|java|json|yaml)\b", re.IGNORECASE
    )
    reverse_domain_identifier_pattern = re.compile(
        r"^(?:com|org|net|edu|gov)(?:\.[\w-]+){1,}$", re.IGNORECASE
    )
    ec2_pattern = re.compile(
        r"""\b
        (?:[a-z]\d[a-z0-9]*|[cmrtz]5[nb]?)\.
        (?:nano|micro|small|medium|large|xlarge|[0-9]+xlarge)
        \b""",
        re.IGNORECASE | re.VERBOSE,
    )
    azure_namespace_pattern = re.compile(r"^Microsoft\.[A-Za-z0-9]+$", re.IGNORECASE)
    version_pattern = re.compile(
        r"^v?\d+\.[a-z0-9]{1,4}(?:\.[a-z0-9]{1,4})?(?:-[a-z0-9]+)?$",
        re.IGNORECASE,
    )
    version_word_re = re.compile(r"\b(?:versions?|releases?)\b", re.IGNORECASE)
    version_words = list(version_word_re.finditer(text))
    mitre_technique_re = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

    result = []
    for entry in entries:
        item = entry.lower()
        normalized_item = _canonicalize_dot_separators(item)

        if ipv4.fullmatch(normalized_item) and kind != "ipv4":
            continue
        if python_module_pattern.fullmatch(normalized_item):
            continue
        if tech_keywords_pattern.search(normalized_item):
            continue
        if reverse_domain_identifier_pattern.fullmatch(normalized_item):
            continue
        if ec2_pattern.fullmatch(normalized_item):
            continue
        if normalized_item == "any.run":
            continue
        if azure_namespace_pattern.fullmatch(normalized_item):
            continue
        if mitre_technique_re.fullmatch(normalized_item):
            continue
        if re.fullmatch(r"\d+\.\d+\.\d+", normalized_item):
            continue

        entry_pos = text.find(entry)
        if kind == "ipv4" and _is_probable_ipv4_version(entry, text, entry_pos):
            continue

        version_found = False
        if kind != "ipv4" and version_words and entry_pos != -1:
            for version_word in version_words:
                distance = abs(version_word.end() - entry_pos)
                if distance <= 50:
                    version_found = True
                    break
        if version_found:
            continue

        if kind == "domain" and "." in normalized_item:
            if normalized_item == "readme.md":
                continue
            if ".permission." in normalized_item or ".permissions." in normalized_item:
                continue
            tld = normalized_item.rsplit(".", 1)[-1]
            if tld not in valid_tlds or tld in FORCE_FILE_EXT:
                continue

        if kind == "email":
            normalized_email = _canonicalize_email_separators(item)
            if "@" not in normalized_email:
                continue
            domain_part = normalized_email.rsplit("@", 1)[-1]
            tld = domain_part.rsplit(".", 1)[-1]
            if tld not in valid_tlds or tld in FORCE_FILE_EXT:
                continue

        if kind in {"file", "filepath"} and "." in normalized_item:
            if normalized_item in {"e.g", "i.e"}:
                continue
            tld = normalized_item.rsplit(".", 1)[-1]
            if tld in valid_tlds and tld not in FORCE_FILE_EXT:
                continue
            if version_pattern.fullmatch(normalized_item):
                continue
            if re.match(r"^[\w-]+(\.[\w-]+){3,}$", normalized_item):
                continue

        if kind == "filepath":
            entry = entry.strip()
            path_parts = entry.rsplit("\\", 1)
            if len(path_parts) == 2:
                path_dir, basename = path_parts
            else:
                path_dir, basename = "", path_parts[0]

            if " " in basename:
                for part in basename.split():
                    if "." in part:
                        basename = part
                        break
                else:
                    continue

            if path_dir:
                entry = f"{path_dir}\\{basename}"
            else:
                entry = basename

            entry = entry.rstrip(" .,:;")

            if entry in {"/", "\\", "."}:
                continue

            if (
                entry.startswith("/")
                and text
                and not _find_invalid_occurrences(text, entry)
            ):
                continue
            if entry.startswith("/") and _is_unlikely_linux_path(entry):
                continue

        result.append(entry)

    return result


def extract_iocs_with_tlds(text: str, valid_tlds: set[str]) -> dict[str, list[str]]:
    iocs: dict[str, list[str]] = {
        "filepath": _extract_direct(IOC_REGEX["filepath"], text),
        "file": _extract_file_matches(text),
        "url": _extract_url_matches(text),
        "domain": _extract_domain_matches(text),
        "email": _extract_direct(IOC_REGEX["email"], text),
        "ipv4": _extract_ipv4_matches(text),
        "ipv6": _extract_ipv6_matches(text),
        "md5": _extract_direct(IOC_REGEX["md5"], text),
        "sha1": _extract_direct(IOC_REGEX["sha1"], text),
        "sha256": _extract_direct(IOC_REGEX["sha256"], text),
        "cve": _extract_direct(IOC_REGEX["cve"], text),
        "expressions": _extract_direct(IOC_REGEX["expressions"], text),
        "mitre_attack_t": _extract_capture_group(IOC_REGEX["mitre_attack_t"], text),
        "mitre_tactic": _extract_capture_group(IOC_REGEX["mitre_tactic"], text),
        "registry_key": _extract_registry_matches(text),
        "cwe": _extract_direct(IOC_REGEX["cwe"], text),
        "ghsa": _extract_direct(IOC_REGEX["ghsa"], text),
        "capec": _extract_direct(IOC_REGEX["capec"], text),
    }

    if any(_contains_defanged_dot(domain.lower()) for domain in iocs.get("domain", [])):
        iocs["domain"] = [
            domain
            for domain in iocs["domain"]
            if _should_keep_domain_in_mixed_results(domain)
        ]
    if any(_contains_defanged_dot(ip.lower()) for ip in iocs.get("ipv4", [])):
        iocs["ipv4"] = [ip for ip in iocs["ipv4"] if _contains_defanged_dot(ip.lower())]

    dedupe_keys = (
        "filepath",
        "file",
        "url",
        "domain",
        "email",
        "ipv4",
        "ipv6",
        "md5",
        "sha1",
        "sha256",
        "cve",
        "expressions",
    )
    all_iocs = [item for key in dedupe_keys for item in iocs[key]]
    to_keep = {
        candidate
        for candidate in all_iocs
        if not any(_is_proper_substring(candidate, other) for other in all_iocs)
    }
    for key in dedupe_keys:
        iocs[key] = [item for item in iocs[key] if item in to_keep]

    if "ipv4" in iocs:
        iocs["ipv4"] = post_filter_false_positives_with_tlds(
            iocs["ipv4"], "ipv4", valid_tlds, text
        )
    if "domain" in iocs:
        iocs["domain"] = post_filter_false_positives_with_tlds(
            iocs["domain"], "domain", valid_tlds, text
        )
    if "email" in iocs:
        iocs["email"] = post_filter_false_positives_with_tlds(
            iocs["email"], "email", valid_tlds, text
        )
    if "file" in iocs:
        iocs["file"] = post_filter_false_positives_with_tlds(
            iocs["file"], "file", valid_tlds, text
        )
    if "filepath" in iocs:
        iocs["filepath"] = post_filter_false_positives_with_tlds(
            iocs["filepath"], "filepath", valid_tlds, text
        )

    return iocs
