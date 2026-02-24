<p align="center">
  <h1 align="center"> IOC Collector</h1>
  <p align="center">
    <strong>Kapsamlı Tehdit İstihbaratı IOC Toplama ve Zenginleştirme Aracı</strong>
  </p>
  <p align="center">
  </p>
  
---

**IOC Collector**, CTI (Cyber Threat Intelligence) analistleri ve SOC ekipleri için geliştirilmiş, **31 farklı tehdit istihbaratı kaynağından** IOC (Indicator of Compromise) verilerini toplayan, doğrulayan ve **5 farklı API** ile zenginleştiren gelişmiş bir komut satırı aracıdır.

## İçindekiler

- [Özellikler](#-özellikler)
- [Mimari](#-mimari)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
  - [Temel Komutlar](#temel-komutlar)
  - [Threat Intelligence Feed'leri](#threat-intelligence-feedleri)
  - [Enrichment (Zenginleştirme)](#enrichment-zenginleştirme)
  - [Gelişmiş Ayarlar](#gelişmiş-ayarlar)
- [Desteklenen Kaynaklar](#-desteklenen-kaynaklar)
- [Çıktı Formatları](#-çıktı-formatları)
- [Proje Yapısı](#-proje-yapısı)
- [Testler](#-testler)
- [Konfigürasyon](#️-konfigürasyon)


## Özellikler

### IOC Extraction
| IOC Türü | Örnekler |
|---|---|
| **IPv4 / IPv6** | `192.168.1.1`, `2001:db8::1` |
| **Domain** | `evil-domain.com` |
| **URL** | `https://malware-site.com/payload` |
| **Hash** | MD5, SHA1, SHA256, SHA512 |
| **Email** | `attacker@evil.com` |
| **CVE** | `CVE-2024-1234` |
| **MITRE ATT&CK** | `T1059.001`, `TA0001` |

### Akıllı İşleme
-  **Defang/Refang** — `hxxps://evil[.]com` ↔ `https://evil.com`
-  **Deduplikasyon** — Tekrar eden IOC'leri otomatik kaldırma
-  **Doğrulama** — Geçersiz IP, private range, TLD kontrolü
-  **Hash Çakışma Önleme** — SHA256 içindeki MD5 false positive'lerini filtreler

###  Entegre Kaynaklar
-  **6 CERT Feed** — TR, US, EU, NL, FR, JP
-  **5 abuse.ch Feed** — URLhaus, MalBazaar, ThreatFox, Feodo, SSL BL
-  **5 IP Blocklist** — Blocklist.de, Emerging Threats, Spamhaus, Cinsscore, Talos
-  **4 Phishing/C2 Feed** — OpenPhish, PhishTank, Bambenek, CyberCrime Tracker
-  **7 GitHub IOC Repo** — Maltrail, MISP, Firehol, YARAify, ThreatHunter, ESET APT, Malpedia
-  **5 Enrichment API** — VirusTotal, OTX AlienVault, AbuseIPDB, Shodan, GreyNoise

### Çıktı Formatları
`JSON` · `CSV` · `Markdown` · `Plain Text` · `STIX 2.1`

##  Mimari

```
ioc_collector/
├── cli.py                     # Ana CLI arayüzü (argparse)
├── extractors/                # IOC tespit motoru
│   ├── regex_extractor.py     # Merkezi regex motoru
│   ├── ip.py                  # IPv4/IPv6 extractor
│   ├── domain.py              # Domain extractor + TLD doğrulama
│   ├── url.py                 # URL extractor
│   ├── hash.py                # Hash extractor (MD5-SHA512)
│   ├── email.py               # Email extractor
│   └── cve.py                 # CVE + MITRE ATT&CK extractor
├── sources/                   # Veri kaynakları
│   ├── remote_fetcher.py      # HTTP client (cache, ETag, proxy)
│   ├── feed_manager.py        # Feed kayıt ve yönetim sistemi
│   ├── cert_feeds.py          # CERT feed'leri (6 ülke)
│   ├── abuse_ch_feeds.py      # abuse.ch ailesi (5 feed)
│   ├── ip_blocklist_feeds.py  # IP blocklist'leri (5 kaynak)
│   ├── phishing_feeds.py      # Phishing/C2 feed'leri (4 kaynak)
│   └── github_feed.py         # GitHub repo preset sistemi (7 repo)
├── formatters/                # Çıktı formatlayıcıları
│   ├── json_formatter.py
│   ├── csv_formatter.py
│   ├── text_formatter.py
│   ├── md_report.py
│   └── stix_formatter.py
└── utils/                     # Yardımcı araçlar
    ├── enrichment.py           # 5 API entegrasyonu
    ├── defanger.py             # Defang/refang
    └── validator.py            # IP/domain doğrulama
```

##  Kurulum

### Gereksinimler
- Python **3.9+**
- `requests`, `tldextract`

```bash
# Klonlayın
git clone https://github.com/Emre-aldmz/IOC-Collector.git
cd IOC-Collector

# Bağımlılıkları yükleyin
pip install -r requirements.txt

# (Opsiyonel) Sistem geneline kurun
pip install .
```

##  Kullanım

### Temel Komutlar

```bash
# Dosyadan IOC çıkarma
ioc-collector -f report.txt --export-json output.json

# Birden fazla dosyadan
ioc-collector -f file1.txt file2.log file3.pdf --unique

# URL'den IOC çekme
ioc-collector -u https://example.com/malware-analysis --export-md report.md

# Stdin'den okuma (pipe)
cat logs.txt | ioc-collector -f - --format text

# Sadece belirli IOC türlerini çıkar
ioc-collector -f report.txt --types ip,hash,cve

# Defanged çıktı (güvenli paylaşım)
ioc-collector -f report.txt --defang-output --unique
```

### Threat Intelligence Feed'leri

#### CERT Feed'leri (6 Ülke)
```bash
# USOM (Türkiye) zararlı bağlantı listesi
ioc-collector --cert-feed TR

# CISA KEV (ABD) bilinen exploit veritabanı
ioc-collector --cert-feed US

# CERT-EU, NCSC-NL, CERT-FR, JPCERT
ioc-collector --cert-feed EU
ioc-collector --cert-feed NL
ioc-collector --cert-feed FR
ioc-collector --cert-feed JP

# Tüm CERT feed'lerini aynı anda
ioc-collector --cert-feed all --unique --export-json all_certs.json
```

#### abuse.ch Feed'leri (5 Kaynak)
```bash
# URLhaus — Zararlı URL'ler
ioc-collector --abuse-feed urlhaus

# MalBazaar — Malware hash'leri
ioc-collector --abuse-feed malbazaar

# ThreatFox — IOC mix (IP, Domain, URL, Hash)
ioc-collector --abuse-feed threatfox

# Feodo Tracker — Botnet C2 IP'leri
ioc-collector --abuse-feed feodo

# SSL Blacklist — Zararlı SSL sertifika IP'leri
ioc-collector --abuse-feed sslbl

# Tümünü çek
ioc-collector --abuse-feed all --unique
```

#### IP Blocklist'leri (5 Kaynak)
```bash
# Blocklist.de — Saldırgan IP'ler
ioc-collector --ip-blocklist blocklist_de

# Emerging Threats — Compromised IP'ler
ioc-collector --ip-blocklist emerging_threats

# Spamhaus DROP — Hijack edilmiş IP blokları
ioc-collector --ip-blocklist spamhaus

# Cinsscore + Talos
ioc-collector --ip-blocklist cinsscore
ioc-collector --ip-blocklist talos

# Tüm IP blocklist'leri
ioc-collector --ip-blocklist all --export-csv ip_blocklist.csv
```

#### Phishing / C2 Feed'leri (4 Kaynak)
```bash
# OpenPhish — Phishing URL'leri
ioc-collector --phishing-feed openphish

# PhishTank — Doğrulanmış phishing URL'leri (API key opsiyonel)
ioc-collector --phishing-feed phishtank

# Bambenek C2 — Botnet C2 domain'leri
ioc-collector --phishing-feed bambenek

# CyberCrime Tracker — C2 panel URL'leri
ioc-collector --phishing-feed cybercrime

# Tümü
ioc-collector --phishing-feed all --unique
```

#### GitHub IOC Repoları (7 Preset)
```bash
# Hazır preset'ler
ioc-collector --github-feed-preset maltrail          # Maltrail malware IOC
ioc-collector --github-feed-preset firehol           # Firehol IP blocklist
ioc-collector --github-feed-preset misp_warninglists # MISP false positive listeleri
ioc-collector --github-feed-preset yaraify           # YARAify hash/YARA
ioc-collector --github-feed-preset threathunter      # ATT&CK TTP bilgisi
ioc-collector --github-feed-preset eset_apt          # ESET APT IOC'ları
ioc-collector --github-feed-preset malpedia          # Malpedia malware bilgisi

# Tüm preset'ler
ioc-collector --github-feed-preset all

# Özel repo slug ile
ioc-collector --github-feed stamparm/maltrail

# Doğrudan raw URL
ioc-collector --github-feed-url https://raw.githubusercontent.com/user/repo/main/iocs.txt
```

#### Özel Feed Ekleme
```bash
# Kendi feed'inizi kalıcı olarak kaydedin
ioc-collector --add-feed "MyThreatFeed" "https://example.com/threat-feed.txt"

# Kayıtlı tüm feed'leri listeleyin
ioc-collector --list-feeds
```

### Enrichment (Zenginleştirme)

5 farklı API ile IOC'larınızı zenginleştirin. Her API için ilgili env variable'ı set etmeniz yeterli:

```bash
# Env variable'ları ayarlayın
export VT_API_KEY="your_virustotal_key"
export OTX_API_KEY="your_otx_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export SHODAN_API_KEY="your_shodan_key"
export GREYNOISE_API_KEY="your_greynoise_key"
```

```bash
# VirusTotal ile zenginleştir
ioc-collector -f suspicious.txt --enrich --enrich-max 10

# OTX AlienVault ile
ioc-collector -f report.txt --enrich-otx

# AbuseIPDB ile IP reputation
ioc-collector -f ips.txt --enrich-abuseipdb

# Shodan ile port/servis bilgisi
ioc-collector -f ips.txt --enrich-shodan

# GreyNoise ile noise/riot kontrolü
ioc-collector -f ips.txt --enrich-greynoise

# Birden fazla API'yi aynı anda
ioc-collector -f report.txt --enrich --enrich-otx --enrich-abuseipdb --enrich-max 5
```

| API | Env Variable | Ücretsiz | İçerik |
|---|---|---|---|
| **VirusTotal** | `VT_API_KEY` | (günlük limit) | IP, Domain, Hash reputation |
| **OTX AlienVault** | `OTX_API_KEY` | | Pulse IOC, IP, Domain, Hash |
| **AbuseIPDB** | `ABUSEIPDB_API_KEY` | (1000/gün) | IP abuse score, ISP, ülke |
| **Shodan** | `SHODAN_API_KEY` | (kısıtlı) | Açık portlar, OS, CVE'ler |
| **GreyNoise** | `GREYNOISE_API_KEY` | (community) | IP noise/riot sınıflandırma |

### Gelişmiş Ayarlar

```bash
# SSL doğrulamasını kapat (self-signed cert'ler için)
ioc-collector -u https://internal-feed.local --no-verify

# Proxy üzerinden bağlan
ioc-collector -u https://example.com --proxy http://user:pass@proxy:8080

# Metadata ekle
ioc-collector -f report.txt --tlp TLP:AMBER --confidence High --source-label "SOC-Team"

# Detaylı log çıktısı
ioc-collector -f report.txt -v
```

##  Desteklenen Kaynaklar

### Entegre Feed Tablosu

<table>
<tr><th>Kategori</th><th>Kaynak</th><th>Format</th><th>CLI Argümanı</th></tr>
<tr><td rowspan="6"><b> CERT</b></td>
  <td>USOM (TR)</td><td>HTML</td><td rowspan="6"><code>--cert-feed</code></td></tr>
  <tr><td>CISA KEV (US)</td><td>JSON</td></tr>
  <tr><td>CERT-EU</td><td>JSON/RSS</td></tr>
  <tr><td>NCSC-NL</td><td>RSS</td></tr>
  <tr><td>CERT-FR</td><td>RSS</td></tr>
  <tr><td>JPCERT</td><td>RDF</td></tr>
<tr><td rowspan="5"><b> abuse.ch</b></td>
  <td>URLhaus</td><td>CSV</td><td rowspan="5"><code>--abuse-feed</code></td></tr>
  <tr><td>MalBazaar</td><td>CSV</td></tr>
  <tr><td>ThreatFox</td><td>CSV</td></tr>
  <tr><td>Feodo Tracker</td><td>Text</td></tr>
  <tr><td>SSL Blacklist</td><td>CSV</td></tr>
<tr><td rowspan="5"><b> IP Blocklist</b></td>
  <td>Blocklist.de</td><td>Text</td><td rowspan="5"><code>--ip-blocklist</code></td></tr>
  <tr><td>Emerging Threats</td><td>Text</td></tr>
  <tr><td>Spamhaus DROP</td><td>Text</td></tr>
  <tr><td>Cinsscore</td><td>Text</td></tr>
  <tr><td>Talos Intelligence</td><td>Text</td></tr>
<tr><td rowspan="4"><b> Phishing/C2</b></td>
  <td>OpenPhish</td><td>Text</td><td rowspan="4"><code>--phishing-feed</code></td></tr>
  <tr><td>PhishTank</td><td>CSV</td></tr>
  <tr><td>Bambenek C2</td><td>Text</td></tr>
  <tr><td>CyberCrime Tracker</td><td>Text</td></tr>
<tr><td rowspan="7"><b> GitHub</b></td>
  <td>Maltrail</td><td>Text</td><td rowspan="7"><code>--github-feed-preset</code></td></tr>
  <tr><td>MISP Warning Lists</td><td>JSON</td></tr>
  <tr><td>Firehol IP Lists</td><td>Text</td></tr>
  <tr><td>YARAify</td><td>Text</td></tr>
  <tr><td>ThreatHunter Playbook</td><td>Text</td></tr>
  <tr><td>ESET APT IOCs</td><td>Text</td></tr>
  <tr><td>Malpedia</td><td>Text</td></tr>
</table>

##  Çıktı Formatları

| Format | Dosya | Kullanım |
|---|---|---|
| **JSON** | `--export-json out.json` | Makine okunabilir, metadata dahil |
| **CSV** | `--export-csv out.csv` | Splunk/Excel import |
| **Markdown** | `--export-md report.md` | Tablolar içeren şık rapor |
| **Text** | `--export-text out.txt` | Basit IOC listesi |
| **STIX 2.1** | `--export-stix bundle.json` | Threat Intel paylaşımı (TAXII uyumlu) |

Stdout formatı: `--format {json,csv,text,stix}`

##  Proje Yapısı

```
IOC-Collector/
├── ioc_collector/
│   ├── cli.py                      # CLI giriş noktası
│   ├── extractors/                 # 7 IOC extractor modülü
│   ├── sources/                    # 7 feed modülü + fetcher + manager
│   ├── formatters/                 # 5 çıktı formatlayıcı
│   └── utils/                      # Enrichment (5 API), defanger, validator
├── tests/                          # 15 test dosyası, 224 test
├── pyproject.toml                  # Paket konfigürasyonu
├── requirements.txt                # Bağımlılıklar
└── README.md
```

##  Testler

Proje **224 birim test** ile kapsamlı şekilde test edilmiştir:

```bash
# Tüm testleri çalıştır
python -m unittest discover tests -v

# Belirli bir test dosyası
python -m unittest tests.test_abuse_ch_feeds -v

# pytest ile (opsiyonel)
pytest tests/ -v
```

Test kapsamı:
-  Regex extraction (IPv4, IPv6, URL, Domain, Hash, CVE, MITRE)
-  Feed parsing (CSV, JSON, RSS, RDF, Text)
-  Enrichment API mock testleri (VirusTotal, OTX, AbuseIPDB, Shodan, GreyNoise)
-  CLI argüman doğrulama
-  Çıktı format testleri (CSV, Markdown, STIX)
-  Defang/refang işlemleri

## Konfigürasyon

### Feed Yönetimi

Feed'ler `~/.ioc_collector/feeds.yaml` dosyasında saklanır. `--add-feed` ile yeni feed ekleyebilir, `--list-feeds` ile mevcut feed'leri görebilirsiniz.

### Enrichment API Anahtarları

Enrichment API'leri environment variable üzerinden yapılandırılır:

```bash
# ~/.bashrc veya ~/.zshrc dosyanıza ekleyin
export VT_API_KEY="your_virustotal_api_key"
export OTX_API_KEY="your_otx_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export SHODAN_API_KEY="your_shodan_api_key"
export GREYNOISE_API_KEY="your_greynoise_api_key"
```

> **Not:** API anahtarları opsiyoneldir. Anahtar set edilmemişse ilgili enrichment otomatik olarak atlanır.

---
