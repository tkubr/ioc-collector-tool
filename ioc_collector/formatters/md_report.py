from datetime import datetime, timezone


def format_markdown_report(source: str, iocs: dict, total: int, confidence: str = "High") -> str:
    """Zenginleştirilmiş Markdown raporu üretir."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []

    # Başlık
    lines.append("# 🛡️ Threat Intelligence Report — IOC Analysis")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append(f"- **Kaynak:** `{source}`")
    lines.append(f"- **Tarih:** {now}")
    lines.append(f"- **Toplam IOC:** **{total}**")
    lines.append(f"- **Confidence:** {confidence}")
    lines.append("")

    # IOC Type Breakdown Tablosu
    lines.append("## IOC Dağılımı")
    lines.append("")
    lines.append("| IOC Türü | Adet |")
    lines.append("|----------|------|")

    type_labels = {
        "ipv4": "IPv4 Adresleri",
        "ipv6": "IPv6 Adresleri",
        "domains": "Domain Adları",
        "urls": "URL'ler",
        "emails": "Email Adresleri",
        "cves": "CVE Tanımlayıcıları",
        "mitre_techniques": "MITRE ATT&CK ID'leri",
        "hash_md5": "MD5 Hash",
        "hash_sha1": "SHA1 Hash",
        "hash_sha256": "SHA256 Hash",
        "hash_sha512": "SHA512 Hash",
    }

    for key, label in type_labels.items():
        items = iocs.get(key, [])
        if isinstance(items, list) and len(items) > 0:
            lines.append(f"| {label} | {len(items)} |")

    lines.append("")

    # Detaylı IOC Listesi
    lines.append("## Detaylı IOC Listesi")
    lines.append("")

    for key, label in type_labels.items():
        items = iocs.get(key, [])
        if isinstance(items, list) and len(items) > 0:
            lines.append(f"### {label} ({len(items)} adet)")
            for item in items[:50]:  # En fazla 50 adet göster
                lines.append(f"- `{item}`")
            if len(items) > 50:
                lines.append(f"- ... ve {len(items) - 50} adet daha")
            lines.append("")

    # Kullanım Notları
    lines.append("---")
    lines.append("")
    lines.append("## Kullanım Notları")
    lines.append("- Bu IOC'lar SOC/CTI ekipleri tarafından tespit, zenginleştirme ve engelleme amacıyla kullanılabilir.")
    lines.append("- IOC'lar paylaşılmadan önce TLP sınıflandırmasına dikkat ediniz.")
    lines.append("- Yanlış pozitif (false positive) riskini azaltmak için IOC'ları doğrulayınız.")
    lines.append("")

    return "\n".join(lines)