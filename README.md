# IOC Collector

**IOC Collector**, CTI (Cyber Threat Intelligence) analistleri ve SOC ekipleri için geliştirilmiş, çeşitli kaynaklardan (dosya, URL, CERT feed'leri, GitHub repoları) Indicator of Compromise (IOC) verilerini toplayan, doğrulayan ve zenginleştiren gelişmiş bir komut satırı aracıdır.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Status](https://img.shields.io/badge/Status-Working-success)

## Özellikler

- **Gelişmiş Extraction:** IPv4, IPv6, Domain, URL, Email, Hash (MD5, SHA1, SHA256, SHA512), CVE ve MITRE ATT&CK ID'lerini tespit eder.
- **Doğrulama & Güvenlik:**
  - Geçersiz IP/Domain'leri filtreler.
  - Hash çakışmalarını önler (örn: SHA256 içindeki MD5 eşleşmeleri).
  - Defanged IOC'leri (örn: `1.1.1[.]1`) otomatik `refang` eder.
  - Çıktıda güvenli paylaşım için `defang` desteği sunar.
- **Feed Entegrasyonu (Gelişmiş):**
  - **Dynamic Feed Management:** Kendi feed'lerinizi ekleyebilir ve yönetebilirsiniz.
  - **Caching:** Tekrarlayan istekleri önlemek için akıllı caching ve ETag desteği.
  - **GitHub Entegrasyonu:** `stamparm/maltrail`, `pan-unit42` gibi popüler repolardan veya RAW URL'den veri çeker.
  - **CERT Feed'leri:** USOM (TR), CISA (US), CERT-EU ve daha fazlası.
- **Zenginleştirme (Enrichment):** VirusTotal API ile IOC skorlama ve doğrulama.
- **Esnek Çıktı:** JSON, CSV, Plain Text, Markdown ve **STIX 2.1** formatlarında raporlama.
- **Network Ayarları:** Proxy desteği ve SSL doğrulama kontrolü.

## Kurulum

```bash
# Projeyi klonlayın
git clone https://github.com/user/ioc-collector.git
cd ioc-collector

# Bağımlılıkları yükleyin
pip install -r requirements.txt

# (Opsiyonel) Sistem geneline kurun
pip install .
```

## Kullanım

### Temel Komutlar

```bash
# Dosyadan IOC çıkarma
ioc-collector -f report.txt --export-json output.json

# URL'den IOC çekme
ioc-collector -u https://example.com/malware-analysis --export-md report.md

# Stdin'den okuma (pipe)
cat logs.txt | ioc-collector -f - --format text
```

### Feed Kullanımı (YENİ)

```bash
# Mevcut tüm feed'leri listele
ioc-collector --list-feeds

# USOM zararlı bağlantı listesini çek
ioc-collector --cert-feed TR --format csv

# Tüm CERT feed'lerini çek
ioc-collector --cert-feed all --unique

# Bilinen bir GitHub reposundan çek (örn: Maltrail)
ioc-collector --github-feed stamparm/maltrail

# Özel bir GitHub Raw URL'den çek
ioc-collector --github-feed-url https://raw.githubusercontent.com/user/repo/main/iocs.txt

# Kendi özel feed'inizi ekleyin (Kalıcı olarak kaydedilir)
ioc-collector --add-feed MyFeed https://example.com/feed.txt
```

### Zenginleştirme (Enrichment)

VirusTotal entegrasyonu için API anahtarı gereklidir:

```bash
export VT_API_KEY="your_api_key_here"

# IOC'ları çıkar ve VirusTotal ile zenginleştir
ioc-collector -f suspicious.txt --enrich --enrich-max 5
```

### Gelişmiş Ağ Ayarları

```bash
# SSL sertifika doğrulamasını kapat (Self-signed sertifikalar için)
ioc-collector -u https://internal-threat-feed.local --no-verify

# Proxy üzerinden çıkış yap
ioc-collector -u https://example.com --proxy http://user:pass@10.10.1.1:8080
```

### Metadata ve Filtreleme

```bash
# Sadece IP ve Hash'leri çıkar
ioc-collector -f report.txt --types ip,hash

# TLP etiketi ve Confidence belirle
ioc-collector -f report.txt --tlp TLP:AMBER --confidence High

# Çıktıyı defanged formatta (güvenli) ver
ioc-collector -f report.txt --defang-output
```

## Çıktı Formatları

| Format | Açıklama |
|--------|----------|
| `json` | Tam detaylı, makine okunabilir format. Metadata içerir. |
| `csv` | Excel/Splunk import için düzleştirilmiş satırlar. |
| `text` | İnsan okunabilir basit liste. |
| `md` | Markdown formatında, tablolar içeren şık rapor. |
| `stix` | STIX 2.1 standardında JSON bundle (Threat Intelligence paylaşımı için). |

## Testler

Proje kapsamlı bir test suite'e sahiptir:

```bash
python3 -m unittest discover tests -v
```


