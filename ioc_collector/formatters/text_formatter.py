"""
Text Formatter — Plain text çıktı formatı.
"""
from datetime import datetime, timezone


def format_text(iocs: dict, source: str = "unknown") -> str:
    """IOC'ları plain text rapor formatında döndürür."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    lines.append("=" * 40)
    lines.append("  IOC Extraction Report")
    lines.append("=" * 40)
    lines.append(f"Source: {source}")
    lines.append(f"Date: {now}")
    lines.append("")

    type_labels = {
        "ipv4": "IPv4 Addresses",
        "ipv6": "IPv6 Addresses",
        "domains": "Domains",
        "urls": "URLs",
        "emails": "Email Addresses",
        "cves": "CVE IDs",
        "mitre_techniques": "MITRE ATT&CK IDs",
    }

    total = 0

    for key, label in type_labels.items():
        items = iocs.get(key, [])
        if isinstance(items, list) and len(items) > 0:
            lines.append(f"[{label}] ({len(items)} found)")
            for item in items:
                lines.append(f"  - {item}")
            lines.append("")
            total += len(items)

    # Hashes — ayrı kategori
    hash_types = {
        "hash_md5": "MD5",
        "hash_sha1": "SHA1",
        "hash_sha256": "SHA256",
        "hash_sha512": "SHA512",
    }

    hash_items_exist = any(
        isinstance(iocs.get(k, []), list) and len(iocs.get(k, [])) > 0
        for k in hash_types
    )

    if hash_items_exist:
        lines.append("[Hashes]")
        for key, label in hash_types.items():
            items = iocs.get(key, [])
            if isinstance(items, list) and len(items) > 0:
                lines.append(f"  {label} ({len(items)} found):")
                for item in items:
                    lines.append(f"    - {item}")
                total += len(items)
        lines.append("")

    lines.append(f"Total IOCs: {total}")
    lines.append("")

    return "\n".join(lines)
