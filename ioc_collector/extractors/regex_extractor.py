import re
import ipaddress
from typing import Dict, List
from ..utils.defanger import refang
from urllib.parse import urlparse
from datetime import datetime, timezone

# --- IPv4 ---
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# --- IPv6 ---
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3}\b"
)

# --- Domain ---
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b"
)

# --- URL ---
URL_RE = re.compile(
    r"\b(?:https?|hxxps?|ftp)://[^\s\"\'<>]+",
    re.IGNORECASE
)

# --- Email ---
EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+(?:@|\[@\]|\[at\])[a-zA-Z0-9.-]+(?:\.|\[\.\]|\[dot\])[a-zA-Z]{2,}\b",
    re.IGNORECASE
)

# --- CVE ---
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# --- MITRE ATT&CK ---
MITRE_RE = re.compile(r"\b[TS]\d{4}(?:\.\d{3})?\b")

# --- Hash ---
SHA512_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])")
SHA256_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")
SHA1_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")
MD5_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")

# --- Domain false positive kontrolü ---
BAD_DOMAIN_SUFFIXES = (
    ".exe", ".dll", ".zip", ".rar", ".7z", ".msi", ".ps1",
    ".bat", ".cmd", ".scr", ".tmp", ".log", ".txt", ".cfg",
    ".sys", ".ini", ".bak", ".old", ".doc", ".docx", ".xls",
    ".xlsx", ".pdf", ".png", ".jpg", ".gif", ".mp4", ".mp3",
)

# Bilinen geçerli TLD listesi (en yaygın olanlar)
VALID_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int",
    "io", "co", "us", "uk", "de", "fr", "ru", "cn", "jp",
    "br", "in", "au", "ca", "it", "es", "nl", "se", "no",
    "fi", "dk", "pl", "cz", "at", "ch", "be", "pt", "tr",
    "kr", "tw", "hk", "sg", "my", "th", "vn", "id", "ph",
    "za", "ng", "ke", "eg", "ma", "ar", "mx", "cl", "pe",
    "info", "biz", "name", "pro", "mobi", "tel", "asia",
    "cat", "jobs", "travel", "museum", "aero", "coop",
    "xyz", "online", "site", "store", "tech", "app",
    "dev", "page", "blog", "cloud", "ai", "ml", "cc",
    "me", "tv", "ly", "to", "la", "pw", "ws", "tk",
    "buzz", "top", "win", "bid", "space", "link",
    "gov.tr", "edu.tr", "com.tr", "org.tr",
    "co.uk", "org.uk", "ac.uk",
    "com.au", "com.br", "co.jp", "co.kr",
}

RESERVED_DOMAINS = {
    "localhost", "example.com", "example.org", "example.net",
    "test.com", "invalid", "local",
}


def validate_ipv4(ip_str: str) -> bool:
    """IPv4 adresini doğrular"""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ipv6(ip_str: str) -> bool:
    """IPv6 adresini ipaddress modülü ile doğrular"""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_domain(domain: str) -> bool:
    """Domain doğrulaması yapar"""
    domain = domain.lower().strip()

    # Dosya uzantısı gibi görünen string'leri filtrele
    if domain.endswith(BAD_DOMAIN_SUFFIXES):
        return False

    # En az bir nokta olmalı
    if "." not in domain:
        return False

    # Reserved domain'leri filtrele
    if domain in RESERVED_DOMAINS:
        return False

    # TLD kontrolü
    parts = domain.rsplit(".", 1)
    if len(parts) < 2:
        return False

    tld = parts[1]

    # İki parçalı TLD kontrolü (com.tr, co.uk vb.)
    all_parts = domain.split(".")
    if len(all_parts) >= 3:
        two_part_tld = f"{all_parts[-2]}.{all_parts[-1]}"
        if two_part_tld in VALID_TLDS:
            return True

    if tld not in VALID_TLDS:
        return False

    # Sadece sayılardan oluşan subdomain'leri filtrele (version numaraları gibi)
    subdomain = parts[0]
    if subdomain.replace(".", "").replace("-", "").isdigit():
        return False

    return True


def domains_from_urls(urls):
    """URL'lerden domain çıkar"""
    out = []
    for u in urls:
        try:
            pu = urlparse(u)
            if pu.hostname:
                out.append(pu.hostname)
        except Exception:
            pass
    return out


def extract_hashes(text: str) -> Dict[str, List[str]]:
    """Hash'leri çıkarır."""
    found_positions = set()  # (start, end) pozisyonlarını takip et

    result = {
        "hash_sha512": [],
        "hash_sha256": [],
        "hash_sha1": [],
        "hash_md5": [],
    }

    # Uzundan kısaya sırala
    patterns = [
        ("hash_sha512", SHA512_RE, 128),
        ("hash_sha256", SHA256_RE, 64),
        ("hash_sha1", SHA1_RE, 40),
        ("hash_md5", MD5_RE, 32),
    ]

    for hash_type, pattern, expected_len in patterns:
        for match in pattern.finditer(text):
            value = match.group().lower()
            start, end = match.start(), match.end()

            # Bu pozisyon daha önce uzun bir hash'in parçası mıydı?
            is_substring = False
            for ps, pe in found_positions:
                if start >= ps and end <= pe:
                    is_substring = True
                    break

            if not is_substring and len(value) == expected_len:
                result[hash_type].append(value)
                found_positions.add((start, end))

    return result


def extract_iocs(text: str, do_refang: bool = True, unique: bool = True) -> Dict[str, List[str]]:
    """Ana IOC çıkarma fonksiyonu"""
    raw = refang(text) if do_refang else text
    now = datetime.now(timezone.utc).isoformat()

    # IPv4
    raw_ipv4 = IPV4_RE.findall(raw)
    valid_ipv4 = [ip for ip in raw_ipv4 if validate_ipv4(ip)]

    # IPv6
    raw_ipv6 = IPV6_RE.findall(raw)
    valid_ipv6 = [ip for ip in raw_ipv6 if validate_ipv6(ip)]

    # Hash'leri çıkar
    hashes = extract_hashes(raw)

    iocs = {
        "ipv4": valid_ipv4,
        "ipv6": valid_ipv6,
        "domains": DOMAIN_RE.findall(raw),
        "urls": URL_RE.findall(raw),
        "emails": EMAIL_RE.findall(text),  # email defang için orijinalde [@] olabilir
        "cves": CVE_RE.findall(raw),
        "mitre_techniques": MITRE_RE.findall(raw),
        "hash_md5": hashes["hash_md5"],
        "hash_sha1": hashes["hash_sha1"],
        "hash_sha256": hashes["hash_sha256"],
        "hash_sha512": hashes["hash_sha512"],
        "metadata": {
            "extracted_at": now,
        }
    }

    # URL'lerden domain türet, domain listesini doğrula (#1.3)
    derived = domains_from_urls(iocs["urls"])
    iocs["domains"].extend(derived)
    iocs["domains"] = [d for d in iocs["domains"] if validate_domain(d)]

    # Email refang
    if do_refang:
        iocs["emails"] = [refang(e) for e in iocs["emails"]]

    # Deduplication
    if unique:
        for k, v in iocs.items():
            if isinstance(v, list):
                iocs[k] = list(dict.fromkeys(v))

    return iocs