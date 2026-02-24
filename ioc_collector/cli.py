import argparse
import sys
import logging
import os
from .parsers.file_parser import read_file, read_multiple_files
from .extractors.regex_extractor import extract_iocs
from .formatters.json_formatter import format_json
from .utils.defanger import defang
from .sources.feed_manager import FeedManager
from .sources.remote_fetcher import RemoteFetcher
from .sources.github_feed import GitHubFeed
from .sources.cert_feeds import CERTFeed
from .sources.abuse_ch_feeds import AbuseCHFeed
from .sources.ip_blocklist_feeds import IPBlocklistFeed
from .sources.phishing_feeds import PhishingFeed


def setup_logging(verbose: bool = False):
    """Logging yapılandırması"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(name)s — %(message)s",
    )


def create_parser():
    p = argparse.ArgumentParser(
        prog="ioc-collector",
        description="IOC Collector — Threat Intelligence IOC Extractor Tool",
        epilog="Örnek: ioc-collector -f report.txt --refang --unique --export-json iocs.json",
    )

    # Giriş kaynakları
    input_group = p.add_argument_group("Giriş Kaynakları")
    input_group.add_argument(
        "-f", "--file", nargs="+",
        help="Girdi dosyası yolu (birden fazla dosya kabul eder, stdin için '-')"
    )
    input_group.add_argument(
        "-u", "--url",
        help="IOC çekilecek URL"
    )
    input_group.add_argument(
        "--cert-feed",
        help="CERT feed çek (ülke kodu: TR, US, EU, NL, FR, JP veya 'all')"
    )
    input_group.add_argument(
        "--github-feed",
        help="GitHub IOC repo slug (ör: stamparm/maltrail)"
    )
    input_group.add_argument(
        "--github-feed-url",
        help="GitHub raw URL'den IOC çek"
    )
    input_group.add_argument(
        "--github-feed-preset",
        help="GitHub IOC repo preset'i (maltrail, misp_warninglists, firehol, yaraify, threathunter, eset_apt, malpedia veya all)"
    )
    input_group.add_argument(
        "--abuse-feed",
        choices=["urlhaus", "malbazaar", "threatfox", "feodo", "sslbl", "all"],
        help="abuse.ch feed seç (urlhaus, malbazaar, threatfox, feodo, sslbl veya all)"
    )
    input_group.add_argument(
        "--ip-blocklist",
        choices=["blocklist_de", "emerging_threats", "spamhaus", "cinsscore", "talos", "all"],
        help="IP blocklist feed seç (blocklist_de, emerging_threats, spamhaus, cinsscore, talos veya all)"
    )
    input_group.add_argument(
        "--phishing-feed",
        choices=["openphish", "bambenek", "phishtank", "cybercrime", "all"],
        help="Phishing/C2 feed seç (openphish, bambenek, phishtank, cybercrime veya all)"
    )
    input_group.add_argument(
        "--add-feed",
        nargs=2,
        metavar=("NAME", "URL"),
        help="Yeni bir feed ekle (FeedManager'a kaydeder)"
    )

    # Çıktı seçenekleri
    output_group = p.add_argument_group("Çıktı Seçenekleri")
    output_group.add_argument("--export-csv", help="CSV çıktı dosya yolu")
    output_group.add_argument("--export-json", help="JSON çıktı dosya yolu")
    output_group.add_argument("--export-md", help="Markdown rapor çıktı dosya yolu")
    output_group.add_argument("--export-text", help="Plain text rapor çıktı dosya yolu")
    output_group.add_argument("--export-stix", help="STIX 2.1 bundle çıktı dosya yolu")
    output_group.add_argument("--format", choices=["json", "csv", "text", "stix"], default="json", help="Stdout çıktı formatı (varsayılan: json)")

    # İşleme seçenekleri
    proc_group = p.add_argument_group("İşleme Seçenekleri")
    proc_group.add_argument("--refang", action="store_true", help="Defanged IOC'leri refang et")
    proc_group.add_argument("--unique", action="store_true", help="Duplicate IOC'leri kaldır")
    proc_group.add_argument("--defang-output", action="store_true", help="Çıktıyı defanged formatta ver")
    proc_group.add_argument(
        "--types",
        help="Sadece belirli IOC türlerini çıkar (virgülle ayrılmış: ip,hash,domain,url,email,cve,mitre)"
    )

    # Advanced Network Options
    net_group = p.add_argument_group("Ağ Ayarları")
    net_group.add_argument("--no-verify", action="store_true", help="SSL sertifika doğrulamasını kapat")
    net_group.add_argument("--proxy", help="Proxy sunucusu (http://user:pass@host:port)")

    # Metadata
    meta_group = p.add_argument_group("Metadata")
    meta_group.add_argument("--source-label", default="CLI", help="Kaynak etiketi")
    meta_group.add_argument(
        "--confidence", default="High",
        choices=["Low", "Medium", "High"],
        help="Varsayılan confidence seviyesi"
    )
    meta_group.add_argument(
        "--tlp", default="TLP:CLEAR",
        choices=["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"],
        help="Traffic Light Protocol sınıflandırması"
    )

    # Enrichment
    enrich_group = p.add_argument_group("Enrichment")
    enrich_group.add_argument(
        "--enrich", action="store_true",
        help="IOC'ları VirusTotal ile zenginleştir (VT_API_KEY env variable gerekli)"
    )
    enrich_group.add_argument(
        "--enrich-max", type=int, default=10,
        help="Maksimum enrichment sorgu sayısı (varsayılan: 10)"
    )
    enrich_group.add_argument(
        "--enrich-otx", action="store_true",
        help="AlienVault OTX ile IOC zenginleştirme (OTX_API_KEY env variable gerekli)"
    )
    enrich_group.add_argument(
        "--enrich-abuseipdb", action="store_true",
        help="AbuseIPDB ile IP reputation kontrolü (ABUSEIPDB_API_KEY env variable gerekli)"
    )
    enrich_group.add_argument(
        "--enrich-shodan", action="store_true",
        help="Shodan ile IP/port bilgisi (SHODAN_API_KEY env variable gerekli)"
    )
    enrich_group.add_argument(
        "--enrich-greynoise", action="store_true",
        help="GreyNoise ile IP noise/riot kontrolü (GREYNOISE_API_KEY env variable gerekli)"
    )

    # Diğer
    p.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    p.add_argument("--version", action="version", version="%(prog)s 1.2.0")
    p.add_argument("--list-feeds", action="store_true", help="Mevcut CERT ve GitHub feed'lerini listele")

    return p


def flatten_for_export(iocs: dict, source: str, default_confidence: str):
    """IOC sözlüğünü flat row listesine çevirir (CSV/export için)"""
    rows = []

    # Varsayılan confidence değerleri
    CONFIDENCE_MAP = {
        "ipv4": "Low",
        "ipv6": "Low",
        "domain": "Medium",
        "url": "Medium",
        "email": "High",
        "hash_md5": "High",
        "hash_sha1": "High",
        "hash_sha256": "High",
        "hash_sha512": "High",
        "cve": "High",
        "mitre": "High",
    }

    def get_confidence(ioc_type):
        return CONFIDENCE_MAP.get(ioc_type, default_confidence)

    def add_many(t, values, note):
        conf = get_confidence(t)
        
        for v in values:
            rows.append({
                "type": t,
                "value": v,
                "confidence": conf,
                "source": source,
                "note": note,
            })

    add_many("ipv4", iocs.get("ipv4", []), "Extracted IPv4 indicator")
    add_many("ipv6", iocs.get("ipv6", []), "Extracted IPv6 indicator")
    add_many("domain", iocs.get("domains", []), "Extracted domain indicator")
    add_many("url", iocs.get("urls", []), "Extracted URL indicator")
    add_many("email", iocs.get("emails", []), "Extracted email indicator")
    add_many("cve", iocs.get("cves", []), "Extracted CVE indicator")
    add_many("mitre", iocs.get("mitre_techniques", []), "Extracted MITRE technique ID")
    add_many("hash_md5", iocs.get("hash_md5", []), "Extracted MD5 hash")
    add_many("hash_sha1", iocs.get("hash_sha1", []), "Extracted SHA1 hash")
    add_many("hash_sha256", iocs.get("hash_sha256", []), "Extracted SHA256 hash")
    add_many("hash_sha512", iocs.get("hash_sha512", []), "Extracted SHA512 hash")

    return rows


def apply_defang_output(iocs: dict) -> dict:
    """Çıktıdaki IOC'ları defanged formata çevirir (#6.6)"""
    defanged = {}
    for k, v in iocs.items():
        if isinstance(v, list):
            defanged[k] = [defang(item) if isinstance(item, str) else item for item in v]
        else:
            defanged[k] = v
    return defanged


def filter_ioc_types(iocs: dict, types_str: str) -> dict:
    """Sadece belirli IOC türlerini filtreler"""
    allowed = {t.strip().lower() for t in types_str.split(",")}

    type_mapping = {
        "ip": ["ipv4", "ipv6"],
        "ipv4": ["ipv4"],
        "ipv6": ["ipv6"],
        "domain": ["domains"],
        "url": ["urls"],
        "email": ["emails"],
        "hash": ["hash_md5", "hash_sha1", "hash_sha256", "hash_sha512"],
        "md5": ["hash_md5"],
        "sha1": ["hash_sha1"],
        "sha256": ["hash_sha256"],
        "sha512": ["hash_sha512"],
        "cve": ["cves"],
        "mitre": ["mitre_techniques"],
    }

    keep_keys = set()
    for user_type in allowed:
        if user_type in type_mapping:
            keep_keys.update(type_mapping[user_type])

    # metadata her zaman kalır
    keep_keys.add("metadata")

    filtered = {}
    for k, v in iocs.items():
        if k in keep_keys:
            filtered[k] = v
        elif isinstance(v, list):
            filtered[k] = []
        else:
            filtered[k] = v

    return filtered


def main():
    parser = create_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger("ioc-collector")

    # Feed Manager Init
    feed_manager = FeedManager()

    # Handle --add-feed
    if args.add_feed:
        name, url = args.add_feed
        feed_manager.add_feed(name, url)
        print(f"[INFO] Feed eklendi: {name} -> {url}")
        sys.exit(0)

    try:
        # Feed listeleme
        if args.list_feeds:
            print(feed_manager.list_feeds())
            return
            
        # Init Remote Fetcher
        fetcher = RemoteFetcher(
            proxy=args.proxy if args.proxy else None,
            verify_ssl=not args.no_verify
        )

        if args.proxy:
            os.environ["HTTP_PROXY"] = args.proxy
            os.environ["HTTPS_PROXY"] = args.proxy

        # Girdi metni topla
        text_parts = []

        # Dosyalardan oku
        if args.file:
            if len(args.file) == 1 and args.file[0] == "-":
                text_parts.append(read_file("-"))
            elif len(args.file) == 1:
                text_parts.append(read_file(args.file[0]))
            else:
                text_parts.append(read_multiple_files(args.file))

        # URL'den oku
        if args.url:
            content = fetcher.fetch(args.url)
            if content:
                text_parts.append(content)
            else:
                logger.error(f"URL'den veri çekilemedi: {args.url}")

        # CERT feed
        if args.cert_feed:
            cert_feed_handler = CERTFeed(fetcher)
            target_feed = args.cert_feed.upper()
            
            if target_feed == "ALL":
                content = cert_feed_handler.fetch_all()
                if content:
                    text_parts.append(content)
                else:
                    logger.error("CERT feed'lerinden veri alınamadı.")
            elif target_feed == "TR":
                content = cert_feed_handler.fetch_tr_usom()
                if content: text_parts.append(content)
            elif target_feed == "US":
                content = cert_feed_handler.fetch_us_cisa_kev()
                if content: 
                    import json
                    text_parts.append(json.dumps(content))
            elif target_feed == "NL":
                content = cert_feed_handler.fetch_nl_ncsc()
                if content: text_parts.append(content)
            elif target_feed == "FR":
                content = cert_feed_handler.fetch_fr_cert()
                if content: text_parts.append(content)
            elif target_feed == "JP":
                content = cert_feed_handler.fetch_jp_cert()
                if content: text_parts.append(content)
            elif target_feed == "EU":
                content = cert_feed_handler.fetch_eu_cert()
                if content: text_parts.append(content)
            else:
                logger.warning(f"Desteklenmeyen CERT kodu: {target_feed} (TR, US, EU, NL, FR, JP, ALL)")

        # GitHub feed
        if args.github_feed or args.github_feed_url or args.github_feed_preset:
            gh_handler = GitHubFeed(fetcher)
            content = None
            
            if args.github_feed:
                # Expects "owner/repo"
                content = gh_handler.fetch_from_repo(args.github_feed)
            elif args.github_feed_url:
                content = gh_handler.fetch_raw_url(args.github_feed_url)
            elif args.github_feed_preset:
                if args.github_feed_preset.lower() == "all":
                    content = gh_handler.fetch_all_presets()
                else:
                    content = gh_handler.fetch_preset(args.github_feed_preset.lower())
            
            if content:
                text_parts.append(content)
            else:
                logger.error("GitHub feed verisi alınamadı.")

        # abuse.ch feed
        if args.abuse_feed:
            abuse_handler = AbuseCHFeed(fetcher)
            abuse_target = args.abuse_feed.lower()

            feed_methods = {
                "urlhaus": abuse_handler.fetch_urlhaus,
                "malbazaar": abuse_handler.fetch_malbazaar,
                "threatfox": abuse_handler.fetch_threatfox,
                "feodo": abuse_handler.fetch_feodo_tracker,
                "sslbl": abuse_handler.fetch_ssl_blacklist,
            }

            if abuse_target == "all":
                content = abuse_handler.fetch_all()
                if content:
                    text_parts.append(content)
                else:
                    logger.error("abuse.ch feed'lerinden veri alınamadı.")
            elif abuse_target in feed_methods:
                content = feed_methods[abuse_target]()
                if content:
                    text_parts.append(content)
                else:
                    logger.error(f"abuse.ch {abuse_target} feed verisi alınamadı.")

        # IP blocklist feed
        if args.ip_blocklist:
            ipbl_handler = IPBlocklistFeed(fetcher)
            ipbl_target = args.ip_blocklist.lower()

            ipbl_methods = {
                "blocklist_de": ipbl_handler.fetch_blocklist_de,
                "emerging_threats": ipbl_handler.fetch_emerging_threats,
                "spamhaus": ipbl_handler.fetch_spamhaus_drop,
                "cinsscore": ipbl_handler.fetch_cinsscore,
                "talos": ipbl_handler.fetch_talos,
            }

            if ipbl_target == "all":
                content = ipbl_handler.fetch_all()
                if content:
                    text_parts.append(content)
                else:
                    logger.error("IP blocklist feed'lerinden veri alınamadı.")
            elif ipbl_target in ipbl_methods:
                content = ipbl_methods[ipbl_target]()
                if content:
                    text_parts.append(content)
                else:
                    logger.error(f"IP blocklist {ipbl_target} feed verisi alınamadı.")

        # Phishing/C2 feed
        if args.phishing_feed:
            phish_handler = PhishingFeed(fetcher)
            phish_target = args.phishing_feed.lower()

            phish_methods = {
                "openphish": phish_handler.fetch_openphish,
                "bambenek": phish_handler.fetch_bambenek_c2,
                "phishtank": phish_handler.fetch_phishtank,
                "cybercrime": phish_handler.fetch_cybercrime_tracker,
            }

            if phish_target == "all":
                content = phish_handler.fetch_all()
                if content:
                    text_parts.append(content)
                else:
                    logger.error("Phishing feed'lerinden veri alınamadı.")
            elif phish_target in phish_methods:
                content = phish_methods[phish_target]()
                if content:
                    text_parts.append(content)
                else:
                    logger.error(f"Phishing {phish_target} feed verisi alınamadı.")

        if not text_parts:
            parser.error("En az bir giriş kaynağı belirtmelisiniz: -f, -u, --cert-feed, --github-feed, --abuse-feed, --ip-blocklist, --phishing-feed")

        text = "\n".join(text_parts)

        # IOC çıkar
        iocs = extract_iocs(text, do_refang=args.refang, unique=args.unique)

        # Tür filtreleme
        if args.types:
            iocs = filter_ioc_types(iocs, args.types)

        # Defang output
        if args.defang_output:
            iocs = apply_defang_output(iocs)

        # Export: CSV
        source_label = args.source_label
        if args.file:
            source_label = ", ".join(args.file) if len(args.file) <= 3 else f"{len(args.file)} dosya"
        elif args.url:
            source_label = args.url
        elif args.cert_feed:
            source_label = f"CERT-{args.cert_feed}"

        flat_rows = flatten_for_export(iocs, source_label, args.confidence)

        if args.export_csv:
            from .formatters.csv_formatter import format_csv
            csv_out = format_csv(flat_rows)
            with open(args.export_csv, "w", encoding="utf-8") as f:
                f.write(csv_out)
            logger.info(f"CSV export: {args.export_csv}")

        # Export: JSON (#5.4)
        if args.export_json:
            result = {
                "metadata": {
                    "source": source_label,
                    "total_iocs": len(flat_rows),
                },
                "iocs": iocs,
            }
            json_out = format_json(result)
            with open(args.export_json, "w", encoding="utf-8") as f:
                f.write(json_out)
            logger.info(f"JSON export: {args.export_json}")

        # Export: Markdown (#6.7)
        if args.export_md:
            from .formatters.md_report import format_markdown_report
            md_out = format_markdown_report(
                source=source_label,
                iocs=iocs,
                total=len(flat_rows),
                confidence=args.confidence,
            )
            with open(args.export_md, "w", encoding="utf-8") as f:
                f.write(md_out)
            logger.info(f"Markdown export: {args.export_md}")

        # Export: Text
        if args.export_text:
            from .formatters.text_formatter import format_text
            text_out = format_text(iocs, source=source_label)
            with open(args.export_text, "w", encoding="utf-8") as f:
                f.write(text_out)
            logger.info(f"Text export: {args.export_text}")

        # Export: STIX 2.1 (#6.3)
        if args.export_stix:
            from .formatters.stix_formatter import format_stix_bundle
            stix_out = format_stix_bundle(
                iocs=iocs,
                source=source_label,
                confidence=args.confidence,
                tlp=args.tlp,
            )
            with open(args.export_stix, "w", encoding="utf-8") as f:
                f.write(stix_out)
            logger.info(f"STIX export: {args.export_stix}")

        # Enrichment: VirusTotal (#6.2)
        enrichment_data = {}
        if args.enrich:
            from .utils.enrichment import VirusTotalEnrichment
            vt = VirusTotalEnrichment()
            if vt.is_configured():
                logger.info("VirusTotal enrichment başlatılıyor...")
                enrichment_data = vt.enrich_iocs(iocs, max_lookups=args.enrich_max)
                logger.info(f"Enrichment tamamlandı: {len(enrichment_data)} IOC zenginleştirildi")
            else:
                logger.warning("VT_API_KEY env variable set edilmemiş. Enrichment atlanıyor.")

        # Enrichment: OTX AlienVault
        otx_enrichment_data = {}
        if args.enrich_otx:
            from .utils.enrichment import OTXEnrichment
            otx = OTXEnrichment()
            if otx.is_configured():
                logger.info("OTX AlienVault enrichment başlatılıyor...")
                otx_enrichment_data = otx.enrich_iocs(iocs, max_lookups=args.enrich_max)
                logger.info(f"OTX Enrichment tamamlandı: {len(otx_enrichment_data)} IOC zenginleştirildi")
                enrichment_data.update(otx_enrichment_data)
            else:
                logger.warning("OTX_API_KEY env variable set edilmemiş. OTX enrichment atlanıyor.")

        # Enrichment: AbuseIPDB
        if args.enrich_abuseipdb:
            from .utils.enrichment import AbuseIPDBEnrichment
            abuse = AbuseIPDBEnrichment()
            if abuse.is_configured():
                logger.info("AbuseIPDB enrichment başlatılıyor...")
                abuse_data = abuse.enrich_iocs(iocs, max_lookups=args.enrich_max)
                logger.info(f"AbuseIPDB Enrichment tamamlandı: {len(abuse_data)} IOC zenginleştirildi")
                enrichment_data.update(abuse_data)
            else:
                logger.warning("ABUSEIPDB_API_KEY env variable set edilmemiş. AbuseIPDB enrichment atlanıyor.")

        # Enrichment: Shodan
        if args.enrich_shodan:
            from .utils.enrichment import ShodanEnrichment
            shodan = ShodanEnrichment()
            if shodan.is_configured():
                logger.info("Shodan enrichment başlatılıyor...")
                shodan_data = shodan.enrich_iocs(iocs, max_lookups=args.enrich_max)
                logger.info(f"Shodan Enrichment tamamlandı: {len(shodan_data)} IOC zenginleştirildi")
                enrichment_data.update(shodan_data)
            else:
                logger.warning("SHODAN_API_KEY env variable set edilmemiş. Shodan enrichment atlanıyor.")

        # Enrichment: GreyNoise
        if args.enrich_greynoise:
            from .utils.enrichment import GreyNoiseEnrichment
            gn = GreyNoiseEnrichment()
            if gn.is_configured():
                logger.info("GreyNoise enrichment başlatılıyor...")
                gn_data = gn.enrich_iocs(iocs, max_lookups=args.enrich_max)
                logger.info(f"GreyNoise Enrichment tamamlandı: {len(gn_data)} IOC zenginleştirildi")
                enrichment_data.update(gn_data)
            else:
                logger.warning("GREYNOISE_API_KEY env variable set edilmemiş. GreyNoise enrichment atlanıyor.")

        # Stdout çıktı (format seçeneğine göre)
        result = {
            "metadata": {
                "source": source_label,
                "total_iocs": len(flat_rows),
                "tlp": args.tlp,
            },
            "iocs": iocs,
        }
        if enrichment_data:
            result["enrichment"] = enrichment_data

        if args.format == "text":
            from .formatters.text_formatter import format_text
            print(format_text(iocs, source=source_label))
        elif args.format == "csv":
            from .formatters.csv_formatter import format_csv
            print(format_csv(flat_rows))
        elif args.format == "stix":
            from .formatters.stix_formatter import format_stix_bundle
            print(format_stix_bundle(iocs, source_label, args.confidence, args.tlp))
        else:
            print(format_json(result))

    except FileNotFoundError as e:
        print(f"[HATA] {e}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"[HATA] {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"[HATA] {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nİptal edildi.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Beklenmeyen hata: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()