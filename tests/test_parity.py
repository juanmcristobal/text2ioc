from pathlib import Path

import pytest

from tests.oracle_ioc import extract_iocs_with_tlds
from text2ioc import extract_iocs
from text2ioc.core.ioc import load_valid_tlds

FAKE_SUFFIX_LIST = """
// This is a comment
ac
co
com
edu
gov
global
hosting
io
mil
net
no
onion
org
rs
sh
tech
uk
xyz
cn
"""

PARITY_SAMPLES = [
    "Download from https://dpaste[.]com/9MQEJ6VYR.txt and keep a copy in /tmp/9MQEJ6VYR.txt.",
    "Contact alice@example[.]com, then hit ftp[:]//ftp.jeepcommerce[.]rs from 77.221.158[.]154.",
    'Process "C:\\Windows\\System32\\winevt\\logs\\ Security.evtx " and report CVE-2021-34527.',
    "Hosts seen: tracker.badactor[.]net, *.evil-domain.com, bob.smith@sub.mail-domain.co, 8.8.8.8.",
    "Artifacts: evil.exe, readme.pdf, ${CONFIG_PATH}, 44d88612fea8a8f36de82e1278abb02f.",
    "Reach http://192.168.1.113:8080/Login.jsp and copy \\\\ad02\\sysvol\\gaze.exe.",
    "Exploit contact cy[at]live.no and decoy booking(dot)com.",
    "Loopback ::1 resolved ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion.",
    "Contacts: lir[@]pq[.]hosting, noc[@]the.hosting, and dvizheniesrs[@]proton[.]me.",
    "Hosts: https://192.168.50.17/ https://192.168.50.15:4444/ http://172.24.0.1:8000/.",
    "Ignore invalid http://127.0.0.1:105xx/ and https://0.0.0.0:{port} placeholders.",
    "Files: OutlookEN[dot]aspx WebView[dot]exe dogovor[dot]vbe cmd[dot]exe but not Next[dot]js or Node[dot]js.",
    "Legitimate channel: hxxps://legionliberty[.]army.",
    "Compiler notes mention d.global_relocs and spoofed woocommėrce[.]com, "
    "but stats live on pepy.tech while anupm019@gmail[.]com stays an email "
    "and README.md is not a domain.",
    "Preparing to unpack .../socat_2.0.0~beta9-1_amd64.deb while roadmap "
    "notes say e.g. updates and GT-AC2900_3.0.0.4_384_82072 should not "
    "yield an ipv4.",
    'The archive ("Bank Handlowy w Warszawie - dowód wpłaty_pdf.tar.gz") conceals a malicious loader.',
    'The attachment "Factura marzo 2025-área.pdf" was delivered while the '
    'archive ("Mise à jour système 2025.apk") was dropped.',
    "The sample (Factura marzo 2025.pdf) was unpacked before the lure "
    "“Raport końcowy 2025.xlsm” was opened.",
    'The decoy ("Incident Report Q1 2025.docm") shipped with the sample '
    "(loader build 2025.tgz).",
    "Execution (TA0002) used Spearphishing Attachment (T1566.001) and "
    "PowerShell (T1059.001) while reg add "
    '"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
    "/v fDenyTSConnections /t REG_DWORD /d 0 /f modified the host.",
    "References: CWE-295 GHSA-v63m-x9r9-8gqp CAPEC-233 and advisory link "
    "https://github.com/advisories/GHSA-v63m-x9r9-8gqp.",
    "Technique link: https://attack.mitre.org/techniques/T1059/001/ should "
    "stay a URL, while T1195.001 remains a mitre_attack_t.",
    "Tactics observed: TA0001, TA0005, TA0010, and tactic link "
    "https://attack.mitre.org/tactics/TA0001/ should stay a URL.",
]


@pytest.fixture
def parity_tlds(monkeypatch, tmp_path: Path):
    cache_file = tmp_path / "public_suffix_list.dat"
    cache_file.write_text(FAKE_SUFFIX_LIST, encoding="utf-8")
    monkeypatch.setenv("IOC_TLD_CACHE", str(cache_file))
    return load_valid_tlds(str(cache_file))


@pytest.mark.parametrize("text", PARITY_SAMPLES)
def test_extract_iocs_matches_oracle_for_representative_cases(parity_tlds, text):
    assert extract_iocs(text) == extract_iocs_with_tlds(text, parity_tlds)


def test_extract_iocs_matches_oracle_for_long_mixed_corpus(parity_tlds):
    corpus = "\n".join(PARITY_SAMPLES * 80)
    assert extract_iocs(corpus) == extract_iocs_with_tlds(corpus, parity_tlds)
