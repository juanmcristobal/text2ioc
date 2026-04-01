use once_cell::sync::Lazy;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use regex::Regex;
use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

const IOC_KEYS: [&str; 18] = [
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
    "attack_technique_id",
    "attack_tactic_id",
    "registry_key",
    "cwe",
    "ghsa",
    "capec",
];

static FILEPATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        (?:
            (?:(?:~|\.{1,2})(?:/[\w.\-<>]+)+(?:\.[a-zA-Z0-9]{1,6})?)
            |
            (?:/(?:[\w.\-<>]+/)*[\w.\-<>]+(?:\.[a-zA-Z0-9]{1,6})?)
            |
            (?:\\\\[\w.$()<>-]+\\[\w.$()<>-]+(?:\\[\w.$()<>-]+)*)
            |
            (?:[A-Za-z]:\\(?:[\w\s().<>-]+\\)*(?:[\w\s().<>-]+(?:\.[A-Za-z0-9]{1,6})?)?\\?)
        )
        "#,
    )
    .expect("valid filepath regex")
});

static FILE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        (?:(?:^|[^A-Za-z0-9_./$-]))
        (
            (?:
                [A-Za-z0-9][A-Za-z0-9_~-]*(?:\.[A-Za-z][A-Za-z0-9]{0,2}){1,3}
                |
                [A-Za-z0-9][A-Za-z0-9_~-]*
                (?:(?:\[\.\]|\[dot\]|\(dot\))[A-Za-z0-9][A-Za-z0-9_~-]*)*
                (?:\[\.\]|\[dot\]|\(dot\))
                (?:exe|dll|sys|scr|lnk|hta|bat|cmd|ps1|vbs|vbe|jse|jar|zip|rar|7z|iso|img|doc|docm|xls|xlsm|rtf|pdf|aspx|jsp|php)
            )
        )
        "#,
    )
    .expect("valid file regex")
});

static CONTEXTUAL_FILE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
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
        "#,
    )
    .expect("valid contextual file regex")
});

static URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
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
        (?:$|[\s'"<>\]),.;:!?])
        "#,
    )
    .expect("valid url regex")
});

static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)@?((?:\*\.)?[A-Za-z0-9-]+(?:(?:\.|\[\.\]|\[dot\]|\(dot\))[A-Za-z0-9-]+)+)")
        .expect("valid domain regex")
});

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b[a-z0-9._%+-]+(?:@|\[\@\]|\[at\]|\(at\))[a-z0-9-]+(?:(?:\.|\[\.\]|\[dot\]|\(dot\))[a-z0-9-]+)*(?:\.|\[\.\]|\[dot\]|\(dot\))[a-z]{2,63}\b",
    )
        .expect("valid email regex")
});

static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.|\[\.\]|\[dot\]|\(dot\))){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}))\b",
    )
    .expect("valid ipv4 regex")
});

static IPV6_CANDIDATE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:^|[^0-9A-Za-z:])([0-9A-Fa-f:]{2,})(?:$|[^0-9A-Za-z:])").unwrap());
static MD5_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap());
static SHA1_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap());
static SHA256_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap());
static CVE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCVE-\d{4}-\d{4,7}\b").unwrap());
static EXPRESSIONS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").unwrap());
static ATTACK_TECHNIQUE_ID_CAPTURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[^A-Za-z0-9_-])(T\d{4}(?:\.\d{3})?)(?:$|[^A-Za-z0-9_-])").unwrap()
});
static ATTACK_TACTIC_ID_CAPTURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[^A-Za-z0-9_-])(TA\d{4})(?:$|[^A-Za-z0-9_-])").unwrap()
});
static REGISTRY_KEY_CAPTURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        (?:^|[^A-Za-z0-9_])
        (
            (?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)
            (?:\\[^\\/"'“”\r\n]+)+
        )
        "#,
    )
    .unwrap()
});
static CWE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCWE-\d{1,5}\b").unwrap());
static GHSA_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b").unwrap());
static CAPEC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCAPEC-\d{1,5}\b").unwrap());

static PYTHON_MODULE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^(os|sys|re|json|time|datetime|subprocess|pathlib|shutil|logging|math|base64|hashlib)\.[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$",
    )
    .unwrap()
});
static TECH_KEYWORDS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(node\.?js|asp\.?net|python|java|json|yaml)\b").unwrap());
static REVERSE_DOMAIN_IDENTIFIER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^(?:com|org|net|edu|gov)(?:\.[\w-]+){1,}$").unwrap());
static EC2_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)\b(?:[a-z]\d[a-z0-9]*|[cmrtz]5[nb]?)\.(?:nano|micro|small|medium|large|xlarge|[0-9]+xlarge)\b",
    )
    .unwrap()
});
static AZURE_NAMESPACE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Microsoft\.[A-Za-z0-9]+$").unwrap());
static VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^v?\d+\.[a-z0-9]{1,4}(?:\.[a-z0-9]{1,4})?(?:-[a-z0-9]+)?$").unwrap()
});
static VERSION_WORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:versions?|releases?)\b").unwrap());
static IPV4_VERSION_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        \b(?:versions?|release(?:d)?|build|firmware|patch(?:ed)?|fixed|affected|vendor|product|model|portal|router|plugin|component|module|appliance|kernel|dxp|edition|revision|rev|through|up\s+to|prior\s+to|before|since|until|lt|lte|gt|gte)\b
        ",
    )
    .unwrap()
});
static ADVISORY_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:vulnerability|vulnerable|issue|flaw|advisory|classified|detected|discovered|found)\b").unwrap()
});
static DOMAIN_MARKUP_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:wp:(?:paragraph|image|heading|list(?:-item)?)|kg-card-[\w-]+|linkdestination|sizeslug)\b
        |
        /wp:(?:paragraph|image|heading|list(?:-item)?)
        |
        html \s* [x×]
        |
        "\s*(?:id|sizeslug|linkdestination)"\s*:
        "#,
    )
    .unwrap()
});
static DOMAIN_CODE_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)\b(?:package|module|namespace|class|function|method|component|plugin|manifest|permission|library|sdk|import|extension)\b",
    )
    .unwrap()
});
static DOMAIN_ORG_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?ix)\borg\s*\||\b(?:vendor|organization|company|manufacturer|product)\b")
        .unwrap()
});
static DOMAIN_PRESERVE_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)\b(?:domains?|sites?|websites?|hosts?|urls?|c2|callbacks?|resolves?|connects?\s+to|hosted\s+on)\b",
    )
    .unwrap()
});
static MITRE_TECHNIQUE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bT\d{4}(?:\.\d{3})?\b").unwrap());
static THREE_PART_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d+\.\d+\.\d+$").unwrap());
static THREE_PART_VERSION_CAPTURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[^0-9.])(\d+\.\d+\.\d+)(?:$|[^0-9.])").unwrap()
});
static MANY_SEGMENTS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[\w-]+(\.[\w-]+){3,}$").unwrap());
static IPV4_PAREN_SUFFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*\([0-9A-Za-z._-]{1,24}\)").unwrap());

static FORCE_FILE_EXT: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "7z", "apk", "arj", "bat", "cab", "chm", "cmd", "cpl", "crt", "csv", "deb", "dll",
        "do", "doc", "docm", "docx", "drv", "elf", "evtx", "exe", "go", "gz", "hta", "ini",
        "iso", "jar", "java", "jpg", "js", "json", "jsp", "key", "ko", "lnk", "log", "mdb",
        "msg", "msi", "pdf", "pem", "php", "pif", "ppt", "pptm", "pptx", "py", "rar", "reg",
        "rpm", "rtf", "scr", "sh", "so", "sys", "tar", "text", "txt", "url", "vbe", "vbs",
        "war", "wav", "wsf", "xls", "xlsm", "xlsx", "xml", "yaml", "yml", "zip",
    ])
});

const MISSING_START: usize = usize::MAX;

#[derive(Clone, Debug)]
struct MatchRecord {
    value: String,
    start: usize,
}

#[derive(Default)]
struct IocBuckets {
    filepath: Vec<MatchRecord>,
    file: Vec<MatchRecord>,
    url: Vec<MatchRecord>,
    domain: Vec<MatchRecord>,
    email: Vec<MatchRecord>,
    ipv4: Vec<MatchRecord>,
    ipv6: Vec<MatchRecord>,
    md5: Vec<MatchRecord>,
    sha1: Vec<MatchRecord>,
    sha256: Vec<MatchRecord>,
    cve: Vec<MatchRecord>,
    expressions: Vec<MatchRecord>,
    attack_technique_id: Vec<MatchRecord>,
    attack_tactic_id: Vec<MatchRecord>,
    registry_key: Vec<MatchRecord>,
    cwe: Vec<MatchRecord>,
    ghsa: Vec<MatchRecord>,
    capec: Vec<MatchRecord>,
}

impl IocBuckets {
    fn slices(&self) -> [&[MatchRecord]; 18] {
        [
            &self.filepath,
            &self.file,
            &self.url,
            &self.domain,
            &self.email,
            &self.ipv4,
            &self.ipv6,
            &self.md5,
            &self.sha1,
            &self.sha256,
            &self.cve,
            &self.expressions,
            &self.attack_technique_id,
            &self.attack_tactic_id,
            &self.registry_key,
            &self.cwe,
            &self.ghsa,
            &self.capec,
        ]
    }
}

struct TldCacheEntry {
    key: Vec<String>,
    set: Arc<HashSet<String>>,
}

static VALID_TLD_CACHE: Lazy<Mutex<Option<TldCacheEntry>>> = Lazy::new(|| Mutex::new(None));

fn parse_valid_tlds_impl(text: &str) -> Vec<String> {
    let mut valid_tlds = HashSet::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with("//")
            || line.starts_with("*.")
            || line.starts_with('!')
        {
            continue;
        }

        let tld = line.to_ascii_lowercase();
        if tld.chars().all(|ch| ch.is_ascii_alphabetic()) && (2..=63).contains(&tld.len()) {
            valid_tlds.insert(tld);
        }
    }

    let mut result: Vec<String> = valid_tlds.into_iter().collect();
    result.sort_unstable();
    result
}

fn valid_tld_set(valid_tlds: Vec<String>) -> Arc<HashSet<String>> {
    let key: Vec<String> = valid_tlds
        .into_iter()
        .map(|tld| tld.to_ascii_lowercase())
        .collect();

    let mut cache = VALID_TLD_CACHE.lock().expect("valid tld cache lock");
    if let Some(entry) = cache.as_ref() {
        if entry.key == key {
            return Arc::clone(&entry.set);
        }
    }

    let set = Arc::new(key.iter().cloned().collect());
    *cache = Some(TldCacheEntry {
        key,
        set: Arc::clone(&set),
    });
    set
}

fn push_unique_record(
    values: &mut Vec<MatchRecord>,
    seen: &mut HashSet<String>,
    value: &str,
    start: usize,
) {
    if seen.contains(value) {
        return;
    }
    let owned = value.to_string();
    seen.insert(owned.clone());
    values.push(MatchRecord {
        value: owned,
        start,
    });
}

fn next_byte(text: &str, index: usize) -> Option<u8> {
    text.as_bytes().get(index).copied()
}

fn prev_char(text: &str, index: usize) -> Option<(usize, char)> {
    text.get(..index)?.char_indices().next_back()
}

fn next_char(text: &str, index: usize) -> Option<char> {
    text.get(index..)?.chars().next()
}

fn is_email_local_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-')
}

fn is_file_next_invalid(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

fn is_valid_domain_start(text: &str, start: usize) -> bool {
    if let Some((at_idx, '@')) = prev_char(text, start) {
        if text[..at_idx]
            .chars()
            .next_back()
            .is_some_and(is_email_local_char)
        {
            return false;
        }
    }

    !prev_char(text, start).is_some_and(|(_, ch)| ch.is_alphanumeric() || ch == '-')
}

fn is_valid_domain_end(text: &str, end: usize) -> bool {
    !next_char(text, end).is_some_and(|ch| ch.is_alphanumeric() || ch == '-' || ch == '_')
}

fn extract_direct(pattern: &Regex, text: &str) -> Vec<MatchRecord> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for matched in pattern.find_iter(text) {
        push_unique_record(&mut values, &mut seen, matched.as_str(), matched.start());
    }

    values
}

fn extract_capture_group(pattern: &Regex, text: &str, group: usize) -> Vec<MatchRecord> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for capture in pattern.captures_iter(text) {
        let item = capture.get(group).expect("capture group match");
        push_unique_record(&mut values, &mut seen, item.as_str(), item.start());
    }

    values
}

fn extract_url_matches(text: &str) -> Vec<MatchRecord> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for matched in URL_RE.find_iter(text) {
        let item = matched
            .as_str()
            .trim_end_matches(|ch: char| {
                matches!(
                    ch,
                    ' ' | '\t' | '\n' | '\r' | '\'' | '"' | '<' | '>' | ')' | ']' | ','
                        | '.'
                        | ';'
                        | ':'
                        | '!'
                        | '?'
                )
            });

        if item.is_empty() {
            continue;
        }

        let item_end = matched.start() + item.len();
        if next_byte(text, item_end)
            .is_some_and(|byte| byte == b':' || byte == b'_' || (byte as char).is_ascii_alphanumeric())
        {
            continue;
        }
        push_unique_record(&mut values, &mut seen, item, matched.start());
    }

    values
}

fn extract_ipv6_matches(text: &str) -> Vec<MatchRecord> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for capture in IPV6_CANDIDATE_RE.captures_iter(text) {
        let item_match = capture.get(1).expect("ipv6 capture");
        let item = item_match.as_str();
        if !item.contains(':') || item.matches(':').count() < 2 {
            continue;
        }
        if !item.chars().any(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if item.parse::<Ipv6Addr>().is_err() {
            continue;
        }
        push_unique_record(&mut values, &mut seen, item, item_match.start());
    }

    values
}

fn extract_file_matches(text: &str) -> Vec<MatchRecord> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for capture in FILE_RE.captures_iter(text) {
        let item = capture.get(1).expect("file capture");
        if next_byte(text, item.end()).is_some_and(is_file_next_invalid) {
            continue;
        }
        push_unique_record(&mut values, &mut seen, item.as_str(), item.start());
    }

    for capture in CONTEXTUAL_FILE_RE.captures_iter(text) {
        let item = capture.get(1).expect("contextual file capture");
        let trimmed = item
            .as_str()
            .trim()
            .trim_end_matches([' ', '.', ',', ':', ';', '!', '?']);
        if trimmed.is_empty() {
            continue;
        }
        push_unique_record(&mut values, &mut seen, trimmed, item.start());
    }

    values
}

fn extract_domain_matches(text: &str) -> Vec<MatchRecord> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for capture in DOMAIN_RE.captures_iter(text) {
        let whole = capture.get(0).expect("whole domain match");
        if !is_valid_domain_start(text, whole.start()) || !is_valid_domain_end(text, whole.end()) {
            continue;
        }
        let item = capture.get(1).expect("domain capture");
        push_unique_record(&mut values, &mut seen, item.as_str(), item.start());
    }

    values
}

fn extract_registry_matches(text: &str) -> Vec<MatchRecord> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for capture in REGISTRY_KEY_CAPTURE_RE.captures_iter(text) {
        let item = capture.get(1).expect("registry capture");
        let trimmed = item
            .as_str()
            .trim()
            .trim_end_matches([' ', '.', ',', ':', ';', '!', '?', ')', ']']);
        if trimmed.is_empty() {
            continue;
        }
        push_unique_record(&mut values, &mut seen, trimmed, item.start());
    }

    values
}

fn canonicalize_dot_separators(value: &str) -> Cow<'_, str> {
    if !contains_defanged_dot(value) {
        return Cow::Borrowed(value);
    }

    Cow::Owned(
        value
            .replace("[.]", ".")
            .replace("[dot]", ".")
            .replace("(dot)", "."),
    )
}

fn canonicalize_email_separators(value: &str) -> Cow<'_, str> {
    let normalized = canonicalize_dot_separators(value);
    if !(normalized.contains("[@]") || normalized.contains("[at]") || normalized.contains("(at)")) {
        return normalized;
    }

    Cow::Owned(
        normalized
            .replace("[@]", "@")
            .replace("[at]", "@")
            .replace("(at)", "@"),
    )
}

fn contains_defanged_dot(value: &str) -> bool {
    value.contains("[.]") || value.contains("[dot]") || value.contains("(dot)")
}

fn should_keep_domain_in_mixed_results(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    contains_defanged_dot(&lower) || canonicalize_dot_separators(&lower).ends_with(".onion")
}

fn collect_version_word_ends(text: &str) -> Vec<usize> {
    VERSION_WORD_RE.find_iter(text).map(|matched| matched.end()).collect()
}

fn has_version_word_near(start: usize, version_word_ends: &[usize]) -> bool {
    if start == MISSING_START || version_word_ends.is_empty() {
        return false;
    }

    let lower = start.saturating_sub(50);
    let upper = start.saturating_add(50);
    let idx = version_word_ends.partition_point(|end| *end < lower);
    version_word_ends
        .get(idx)
        .is_some_and(|end| *end <= upper)
}

fn normalize_context(text: &str) -> String {
    let lowered = text.to_ascii_lowercase();
    let normalized = canonicalize_dot_separators(&lowered);
    let mut compact = String::with_capacity(normalized.len());
    let mut in_whitespace = false;

    for ch in normalized.chars() {
        if ch.is_whitespace() {
            if !in_whitespace {
                compact.push(' ');
                in_whitespace = true;
            }
        } else {
            compact.push(ch);
            in_whitespace = false;
        }
    }

    compact.trim().to_string()
}

fn has_leading_zero_ipv4_octet(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    let normalized = canonicalize_dot_separators(&lowered);
    normalized
        .split('.')
        .any(|part| part.len() > 1 && part.starts_with('0'))
}

fn has_ipv4_parenthetical_suffix(text: &str, start: usize, value: &str) -> bool {
    if text.is_empty() || start == MISSING_START {
        return false;
    }

    let end = start.saturating_add(value.len()).min(text.len());
    IPV4_PAREN_SUFFIX_RE.is_match(&text[end..])
}

fn is_context_break(ch: char) -> bool {
    matches!(ch, '\n' | '\r' | '!' | '?' | ';')
}

fn previous_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn next_char_boundary(text: &str, mut index: usize) -> usize {
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn context_window<'a>(text: &'a str, start: usize, value: &str) -> &'a str {
    const WINDOW: usize = 160;

    if text.is_empty() || start == MISSING_START {
        return "";
    }

    let end = start.saturating_add(value.len()).min(text.len());
    let lower = next_char_boundary(text, start.saturating_sub(WINDOW));
    let upper = previous_char_boundary(text, (end + WINDOW).min(text.len()));

    let mut left = lower;
    for (idx, ch) in text[lower..start].char_indices().rev() {
        if is_context_break(ch) {
            left = lower + idx + ch.len_utf8();
            break;
        }
    }

    let mut right = upper;
    for (idx, ch) in text[end..upper].char_indices() {
        if is_context_break(ch) {
            right = end + idx;
            break;
        }
    }

    text[left..right].trim()
}

fn has_domain_path_suffix(text: &str, start: usize, value: &str) -> bool {
    if text.is_empty() || start == MISSING_START {
        return false;
    }

    let end = start.saturating_add(value.len()).min(text.len());
    let suffix = text[end..].trim_start();
    suffix.starts_with('/') || suffix.starts_with(':')
}

fn has_domain_symbol_suffix(text: &str, start: usize, value: &str) -> bool {
    if text.is_empty() || start == MISSING_START {
        return false;
    }

    let end = start.saturating_add(value.len()).min(text.len());
    let suffix = text[end..].trim_start();
    suffix.starts_with('(') || suffix.starts_with("::")
}

fn has_code_style_domain_casing(value: &str) -> bool {
    let stripped = value.trim_start_matches("*.");

    stripped.split('.').any(|label| {
        let mut chars = label.chars();
        let Some(first) = chars.next() else {
            return false;
        };

        if !first.is_ascii_alphabetic() {
            return false;
        }

        let mut saw_upper = first.is_ascii_uppercase();
        let mut saw_noninitial_upper = false;
        let mut saw_lower = first.is_ascii_lowercase();

        for ch in chars {
            if ch.is_ascii_uppercase() {
                saw_upper = true;
                saw_noninitial_upper = true;
            }
            if ch.is_ascii_lowercase() {
                saw_lower = true;
            }
        }

        saw_noninitial_upper || (saw_upper && !saw_lower && label.len() > 1)
    })
}

fn is_probable_legal_entity_domain(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    let normalized = canonicalize_dot_separators(&lowered);
    let labels: Vec<&str> = normalized.trim_start_matches("*.").split('.').collect();

    !labels.is_empty()
        && labels.len() <= 2
        && value.chars().any(|ch| ch.is_ascii_uppercase())
        && labels.iter().all(|label| {
            !label.is_empty() && label.len() <= 4 && label.chars().all(|ch| ch.is_ascii_alphabetic())
        })
}

fn has_explicit_domain_web_context(value: &str, start: usize, text: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    let normalized_item = canonicalize_dot_separators(&lowered);

    if contains_defanged_dot(&lowered)
        || lowered.starts_with("*.")
        || normalized_item.ends_with(".onion")
        || has_domain_path_suffix(text, start, value)
    {
        return true;
    }

    if text.is_empty() || start == MISSING_START {
        return false;
    }

    let raw_context = context_window(text, start, value);
    if raw_context.is_empty() {
        return false;
    }

    let normalized_context = normalize_context(raw_context);
    DOMAIN_PRESERVE_CONTEXT_RE.is_match(&normalized_context)
}

fn is_probable_false_domain(value: &str, start: usize, text: &str) -> bool {
    if has_explicit_domain_web_context(value, start, text) {
        return false;
    }

    if has_domain_symbol_suffix(text, start, value) {
        return true;
    }

    if text.is_empty() || start == MISSING_START {
        return has_code_style_domain_casing(value);
    }

    let raw_context = context_window(text, start, value);
    if raw_context.is_empty() {
        return has_code_style_domain_casing(value);
    }

    let normalized_context = normalize_context(raw_context);
    if normalized_context.is_empty() {
        return has_code_style_domain_casing(value);
    }

    let has_code_style = has_code_style_domain_casing(value);
    let has_markup_context = DOMAIN_MARKUP_CONTEXT_RE.is_match(raw_context);
    let has_code_context = DOMAIN_CODE_CONTEXT_RE.is_match(&normalized_context);
    let has_org_context = DOMAIN_ORG_CONTEXT_RE.is_match(&normalized_context);
    let has_advisory_context = ADVISORY_CONTEXT_RE.is_match(&normalized_context);

    has_markup_context
        || has_code_context
        || (is_probable_legal_entity_domain(value) && (has_org_context || has_advisory_context))
        || (has_code_style && raw_context == value)
        || (has_code_style && (has_org_context || has_advisory_context))
}

fn has_ipv4_range_pattern(context: &str, item: &str) -> bool {
    const RANGE_KEYWORDS: [&str; 10] = [
        "through", "up to", "prior to", "before", "since", "until", "lt", "lte", "gt", "gte",
    ];

    RANGE_KEYWORDS.iter().any(|keyword| {
        context.contains(&format!("{keyword} {item}")) || context.contains(&format!("{item} {keyword}"))
    })
}

fn has_direct_ipv4_version_label(context: &str, item: &str) -> bool {
    const DIRECT_LABELS: [&str; 8] = [
        "version",
        "versions",
        "release",
        "released",
        "build",
        "firmware",
        "revision",
        "rev",
    ];

    DIRECT_LABELS.iter().any(|label| {
        context.contains(&format!("{label} {item}")) || context.contains(&format!("{item} {label}"))
    })
}

fn has_product_like_prefix(context: &str, item: &str) -> bool {
    let Some(item_pos) = context.find(item) else {
        return false;
    };

    let prefix = context[..item_pos]
        .trim_end_matches(|ch: char| ch.is_whitespace() || matches!(ch, '(' | '[' | '{' | ':' | ','));

    let mut saw_product_token = false;
    for token in prefix.split_whitespace().rev().take(3) {
        if matches!(token, "in" | "on" | "for" | "to" | "the" | "of" | "and") {
            continue;
        }

        if token.chars().any(|ch| ch.is_ascii_alphabetic())
            && (token.chars().any(|ch| ch.is_ascii_digit()) || token.contains('-'))
        {
            saw_product_token = true;
            break;
        }
    }

    saw_product_token
}

fn has_nearby_three_part_version_token(context: &str, item: &str) -> bool {
    let Some(item_pos) = context.find(item) else {
        return false;
    };

    THREE_PART_VERSION_CAPTURE_RE.captures_iter(context).any(|capture| {
        let token = capture.get(1).expect("three-part version capture");
        let distance = if token.start() > item_pos {
            token.start() - item_pos
        } else {
            item_pos.saturating_sub(token.end())
        };
        distance <= 48
    })
}

fn has_version_list_separator(context: &str) -> bool {
    context.contains('|') || context.contains(',') || context.contains(" and ") || context.contains(" or ")
}

fn is_probable_ipv4_version(value: &str, start: usize, text: &str) -> bool {
    if has_leading_zero_ipv4_octet(value) || has_ipv4_parenthetical_suffix(text, start, value) {
        return true;
    }

    if text.is_empty() || start == MISSING_START {
        return false;
    }

    let raw_context = context_window(text, start, value);
    if raw_context.is_empty() {
        return false;
    }

    let normalized_context = normalize_context(raw_context);
    if normalized_context.is_empty() {
        return false;
    }

    let lowered = value.to_ascii_lowercase();
    let normalized_item = canonicalize_dot_separators(&lowered).into_owned();
    let has_context_keyword =
        IPV4_VERSION_CONTEXT_RE.is_match(&normalized_context) || ADVISORY_CONTEXT_RE.is_match(&normalized_context);
    let has_nearby_three_part = has_nearby_three_part_version_token(&normalized_context, &normalized_item);
    let has_range_pattern = has_ipv4_range_pattern(&normalized_context, &normalized_item);
    let has_direct_version_label = has_direct_ipv4_version_label(&normalized_context, &normalized_item);
    let has_version_enumeration = has_nearby_three_part && has_version_list_separator(&normalized_context);
    let has_product_prefix =
        ADVISORY_CONTEXT_RE.is_match(&normalized_context) && has_product_like_prefix(&normalized_context, &normalized_item);

    has_context_keyword
        && (has_nearby_three_part
            || has_range_pattern
            || has_direct_version_label
            || has_version_enumeration
            || has_product_prefix)
}

fn is_unlikely_linux_path_impl(path: &str) -> bool {
    const VALID_ROOT_DIRS: [&str; 25] = [
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
    ];

    if !path.starts_with('/') || path.len() < 2 {
        return false;
    }

    let root = path[1..].split('/').next().unwrap_or_default();
    !VALID_ROOT_DIRS.contains(&root)
}

fn find_invalid_occurrences_impl(text: &str, sub: &str) -> bool {
    let mut text_aux = text;

    while let Some(idx) = text_aux.find(sub) {
        if idx > 0 {
            let prev = text_aux.as_bytes()[idx - 1] as char;
            if ['.', '~', ' ', '\'', '"'].contains(&prev) && !is_unlikely_linux_path_impl(sub) {
                return true;
            }
        }

        if idx == 0 {
            let first = text_aux.as_bytes()[idx] as char;
            if ['.', '~', ' ', '\'', '"', '/'].contains(&first)
                && !is_unlikely_linux_path_impl(sub)
            {
                return true;
            }
        }

        text_aux = &text_aux[idx + sub.len()..];
    }

    false
}

fn post_filter_false_positives_records_impl(
    entries: Vec<MatchRecord>,
    kind: &str,
    text: &str,
    version_word_ends: &[usize],
    valid_tlds: &HashSet<String>,
) -> Vec<MatchRecord> {
    let mut result = Vec::with_capacity(entries.len());

    for mut record in entries {
        let item = record.value.to_ascii_lowercase();
        let normalized_item = canonicalize_dot_separators(&item);
        let normalized_item = normalized_item.as_ref();

        if kind != "ipv4"
            && IPV4_RE
                .find(normalized_item)
                .is_some_and(|matched| {
                    matched.start() == 0 && matched.end() == normalized_item.len()
                })
        {
            continue;
        }
        if PYTHON_MODULE_RE.is_match(normalized_item) {
            continue;
        }
        if TECH_KEYWORDS_RE.is_match(normalized_item) {
            continue;
        }
        if REVERSE_DOMAIN_IDENTIFIER_RE.is_match(normalized_item) {
            continue;
        }
        if EC2_RE.is_match(normalized_item) {
            continue;
        }
        if normalized_item == "any.run" {
            continue;
        }
        if AZURE_NAMESPACE_RE.is_match(normalized_item) {
            continue;
        }
        if MITRE_TECHNIQUE_RE.is_match(normalized_item) {
            continue;
        }
        if THREE_PART_VERSION_RE.is_match(normalized_item) {
            continue;
        }

        if kind == "ipv4" && is_probable_ipv4_version(&record.value, record.start, text) {
            continue;
        }

        if kind != "ipv4" && has_version_word_near(record.start, version_word_ends) {
            continue;
        }

        if kind == "domain" && normalized_item.contains('.') {
            if normalized_item == "readme.md" {
                continue;
            }
            if normalized_item.contains(".permission.")
                || normalized_item.contains(".permissions.")
            {
                continue;
            }
            if let Some(tld) = normalized_item.rsplit('.').next() {
                if !valid_tlds.contains(tld) || FORCE_FILE_EXT.contains(tld) {
                    continue;
                }
            }
            if is_probable_false_domain(&record.value, record.start, text) {
                continue;
            }
        }

        if kind == "email" {
            let normalized_email = canonicalize_email_separators(&item);
            let Some((_, domain_part)) = normalized_email.as_ref().rsplit_once('@') else {
                continue;
            };
            let Some(tld) = domain_part.rsplit('.').next() else {
                continue;
            };
            if !valid_tlds.contains(tld) || FORCE_FILE_EXT.contains(tld) {
                continue;
            }
        }

        if (kind == "file" || kind == "filepath") && normalized_item.contains('.') {
            if normalized_item == "e.g" || normalized_item == "i.e" {
                continue;
            }
            if let Some(tld) = normalized_item.rsplit('.').next() {
                if valid_tlds.contains(tld) && !FORCE_FILE_EXT.contains(tld) {
                    continue;
                }
            }
            if VERSION_RE.is_match(&normalized_item) {
                continue;
            }
            if MANY_SEGMENTS_RE.is_match(&normalized_item) {
                continue;
            }
        }

        if kind == "filepath" {
            record.value = record.value.trim().to_string();

            let (path_dir, mut basename) = match record.value.rsplit_once('\\') {
                Some((path_dir, basename)) => (path_dir.to_string(), basename.to_string()),
                None => (String::new(), record.value.clone()),
            };

            if basename.contains(' ') {
                if let Some(part) = basename.split_whitespace().find(|part| part.contains('.')) {
                    basename = part.to_string();
                } else {
                    continue;
                }
            }

            record.value = if path_dir.is_empty() {
                basename
            } else {
                format!("{path_dir}\\{basename}")
            };
            record.value = record
                .value
                .trim_end_matches([' ', '.', ',', ':', ';'])
                .to_string();

            if record.value == "/" || record.value == "\\" || record.value == "." {
                continue;
            }

            if record.value.starts_with('/')
                && !text.is_empty()
                && !find_invalid_occurrences_impl(text, &record.value)
            {
                continue;
            }
            if record.value.starts_with('/') && is_unlikely_linux_path_impl(&record.value) {
                continue;
            }
        }

        result.push(record);
    }

    result
}

fn retain_with_flags(bucket: &mut Vec<MatchRecord>, flags: &[bool]) {
    let mut idx = 0;
    bucket.retain(|_| {
        let keep = flags[idx];
        idx += 1;
        keep
    });
}

fn dedupe_substring_matches(iocs: &mut IocBuckets) {
    let mut flat: Vec<&str> = Vec::new();
    flat.extend(iocs.filepath.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.file.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.url.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.domain.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.email.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.ipv4.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.ipv6.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.md5.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.sha1.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.sha256.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.cve.iter().map(|record| record.value.as_str()));
    flat.extend(iocs.expressions.iter().map(|record| record.value.as_str()));
    if flat.is_empty() {
        return;
    }

    let mut keep = vec![true; flat.len()];
    let mut order: Vec<usize> = (0..flat.len()).collect();
    order.sort_unstable_by_key(|idx| Reverse(flat[*idx].len()));

    for pos in 0..order.len() {
        let current = order[pos];
        let candidate = flat[current];
        for other in &order[..pos] {
            if flat[*other] != candidate && flat[*other].contains(candidate) {
                keep[current] = false;
                break;
            }
        }
    }

    let mut offset = 0;
    let len = iocs.filepath.len();
    retain_with_flags(&mut iocs.filepath, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.file.len();
    retain_with_flags(&mut iocs.file, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.url.len();
    retain_with_flags(&mut iocs.url, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.domain.len();
    retain_with_flags(&mut iocs.domain, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.email.len();
    retain_with_flags(&mut iocs.email, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.ipv4.len();
    retain_with_flags(&mut iocs.ipv4, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.ipv6.len();
    retain_with_flags(&mut iocs.ipv6, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.md5.len();
    retain_with_flags(&mut iocs.md5, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.sha1.len();
    retain_with_flags(&mut iocs.sha1, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.sha256.len();
    retain_with_flags(&mut iocs.sha256, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.cve.len();
    retain_with_flags(&mut iocs.cve, &keep[offset..offset + len]);
    offset += len;
    let len = iocs.expressions.len();
    retain_with_flags(&mut iocs.expressions, &keep[offset..offset + len]);
}

fn post_filter_false_positives_impl(
    entries: Vec<String>,
    kind: &str,
    text: Option<&str>,
    valid_tlds: &HashSet<String>,
) -> Vec<String> {
    if matches!(
        kind,
        "attack_technique_id" | "attack_tactic_id" | "registry_key" | "cwe" | "ghsa" | "capec"
    ) {
        return entries;
    }

    let text = text.unwrap_or("");
    let version_word_ends = collect_version_word_ends(text);
    let records: Vec<MatchRecord> = entries
        .into_iter()
        .map(|entry| MatchRecord {
            start: if text.is_empty() {
                MISSING_START
            } else {
                text.find(&entry).unwrap_or(MISSING_START)
            },
            value: entry,
        })
        .collect();

    post_filter_false_positives_records_impl(records, kind, text, &version_word_ends, valid_tlds)
        .into_iter()
        .map(|record| record.value)
        .collect()
}

fn extract_iocs_impl(text: &str, valid_tlds: &HashSet<String>) -> IocBuckets {
    let mut iocs = IocBuckets {
        filepath: extract_direct(&FILEPATH_RE, text),
        file: extract_file_matches(text),
        url: extract_url_matches(text),
        domain: extract_domain_matches(text),
        email: extract_direct(&EMAIL_RE, text),
        ipv4: extract_direct(&IPV4_RE, text),
        ipv6: extract_ipv6_matches(text),
        md5: extract_direct(&MD5_RE, text),
        sha1: extract_direct(&SHA1_RE, text),
        sha256: extract_direct(&SHA256_RE, text),
        cve: extract_direct(&CVE_RE, text),
        expressions: extract_direct(&EXPRESSIONS_RE, text),
        attack_technique_id: extract_capture_group(&ATTACK_TECHNIQUE_ID_CAPTURE_RE, text, 1),
        attack_tactic_id: extract_capture_group(&ATTACK_TACTIC_ID_CAPTURE_RE, text, 1),
        registry_key: extract_registry_matches(text),
        cwe: extract_direct(&CWE_RE, text),
        ghsa: extract_direct(&GHSA_RE, text),
        capec: extract_direct(&CAPEC_RE, text),
    };

    if iocs
        .domain
        .iter()
        .any(|domain| contains_defanged_dot(&domain.value.to_ascii_lowercase()))
    {
        iocs.domain
            .retain(|domain| should_keep_domain_in_mixed_results(&domain.value));
    }

    if iocs
        .ipv4
        .iter()
        .any(|ip| contains_defanged_dot(&ip.value.to_ascii_lowercase()))
    {
        iocs.ipv4
            .retain(|ip| contains_defanged_dot(&ip.value.to_ascii_lowercase()));
    }

    dedupe_substring_matches(&mut iocs);

    let version_word_ends = collect_version_word_ends(text);
    iocs.ipv4 = post_filter_false_positives_records_impl(
        std::mem::take(&mut iocs.ipv4),
        "ipv4",
        text,
        &version_word_ends,
        valid_tlds,
    );
    iocs.domain = post_filter_false_positives_records_impl(
        std::mem::take(&mut iocs.domain),
        "domain",
        text,
        &version_word_ends,
        valid_tlds,
    );
    iocs.email = post_filter_false_positives_records_impl(
        std::mem::take(&mut iocs.email),
        "email",
        text,
        &version_word_ends,
        valid_tlds,
    );
    iocs.file = post_filter_false_positives_records_impl(
        std::mem::take(&mut iocs.file),
        "file",
        text,
        &version_word_ends,
        valid_tlds,
    );
    iocs.filepath = post_filter_false_positives_records_impl(
        std::mem::take(&mut iocs.filepath),
        "filepath",
        text,
        &version_word_ends,
        valid_tlds,
    );

    iocs
}

#[pyfunction]
fn load_valid_tlds(file_path: &str) -> PyResult<Vec<String>> {
    let text =
        fs::read_to_string(file_path).map_err(|err| PyErr::new::<PyOSError, _>(err.to_string()))?;
    Ok(parse_valid_tlds_impl(&text))
}

#[pyfunction]
fn parse_valid_tlds_text(text: &str) -> Vec<String> {
    parse_valid_tlds_impl(text)
}

#[pyfunction]
fn _is_unlikely_linux_path(path: &str) -> bool {
    is_unlikely_linux_path_impl(path)
}

#[pyfunction]
fn _find_invalid_occurrences(text: &str, sub: &str) -> bool {
    find_invalid_occurrences_impl(text, sub)
}

#[pyfunction(name = "post_filter_false_positives", signature = (entries, kind, valid_tlds, text=None))]
fn py_post_filter_false_positives(
    entries: Vec<String>,
    kind: &str,
    valid_tlds: Vec<String>,
    text: Option<&str>,
) -> Vec<String> {
    let valid_tlds = valid_tld_set(valid_tlds);
    post_filter_false_positives_impl(entries, kind, text, valid_tlds.as_ref())
}

#[pyfunction]
fn extract_iocs(py: Python<'_>, text: &str, valid_tlds: Vec<String>) -> PyResult<PyObject> {
    let valid_tlds = valid_tld_set(valid_tlds);
    let iocs = extract_iocs_impl(text, &valid_tlds);
    let dict = PyDict::new(py);

    for (key, records) in IOC_KEYS.iter().zip(iocs.slices()) {
        let values: Vec<String> = records.iter().map(|record| record.value.clone()).collect();
        dict.set_item(*key, values)?;
    }

    Ok(dict.into())
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(load_valid_tlds, module)?)?;
    module.add_function(wrap_pyfunction!(parse_valid_tlds_text, module)?)?;
    module.add_function(wrap_pyfunction!(_is_unlikely_linux_path, module)?)?;
    module.add_function(wrap_pyfunction!(_find_invalid_occurrences, module)?)?;
    module.add_function(wrap_pyfunction!(py_post_filter_false_positives, module)?)?;
    module.add_function(wrap_pyfunction!(extract_iocs, module)?)?;
    Ok(())
}
