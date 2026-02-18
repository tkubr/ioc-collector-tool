"""
IOC Validator — IOC doğrulama yardımcı modülü.
"""
import ipaddress
import re


def validate_ipv4(ip: str) -> bool:
    """IPv4 adresini doğrular"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ipv6(ip: str) -> bool:
    """IPv6 adresini doğrular"""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_hash(hash_str: str) -> str | None:
    """
    Hash tipini belirler ve doğrular.
    Returns: 'md5', 'sha1', 'sha256', 'sha512' veya None
    """
    hash_str = hash_str.strip().lower()
    if not re.match(r'^[a-f0-9]+$', hash_str):
        return None

    length_map = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512',
    }
    return length_map.get(len(hash_str))


def validate_cve(cve: str) -> bool:
    """CVE ID doğrulaması"""
    return bool(re.match(r'^CVE-\d{4}-\d{4,7}$', cve, re.IGNORECASE))


def validate_domain(domain: str) -> bool:
    """Domain adı temel doğrulaması"""
    if not domain or "." not in domain:
        return False
    # En az 2 karakter TLD
    tld = domain.rsplit(".", 1)[-1]
    return len(tld) >= 2 and tld.isalpha()


def validate_email(email: str) -> bool:
    """Email adresi temel doğrulaması"""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def validate_url(url: str) -> bool:
    """URL doğrulaması"""
    return bool(re.match(r'^(https?|ftp)://', url, re.IGNORECASE))
