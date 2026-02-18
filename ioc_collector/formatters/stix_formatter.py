"""
STIX 2.1 Formatter.
"""
import json
import uuid
from datetime import datetime, timezone


def _make_stix_id(prefix: str) -> str:
    """STIX uyumlu UUID oluştur"""
    return f"{prefix}--{uuid.uuid4()}"


def _stix_indicator(ioc_type: str, value: str, confidence: str = "High", tlp: str = "TLP:CLEAR") -> dict:
    """Tek bir IOC için STIX Indicator objesi oluştur"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    pattern_map = {
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "ipv6": f"[ipv6-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "email": f"[email-addr:value = '{value}']",
        "hash_md5": f"[file:hashes.MD5 = '{value}']",
        "hash_sha1": f"[file:hashes.'SHA-1' = '{value}']",
        "hash_sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "hash_sha512": f"[file:hashes.'SHA-512' = '{value}']",
    }

    confidence_map = {"Low": 25, "Medium": 50, "High": 75}

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _make_stix_id("indicator"),
        "created": now,
        "modified": now,
        "name": f"{ioc_type} indicator: {value}",
        "pattern": pattern_map.get(ioc_type, f"[artifact:payload_bin = '{value}']"),
        "pattern_type": "stix",
        "valid_from": now,
        "confidence": confidence_map.get(confidence, 50),
        "labels": ["malicious-activity"],
        "object_marking_refs": [_tlp_marking_ref(tlp)],
    }


def _tlp_marking_ref(tlp: str) -> str:
    """TLP marking-definition referansı"""
    tlp_refs = {
        "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "TLP:AMBER+STRICT": "marking-definition--826578e1-40a3-4b12-afc8-4a231d4d3c04",
        "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    }
    return tlp_refs.get(tlp.upper(), tlp_refs["TLP:CLEAR"])


def format_stix_bundle(iocs: dict, source: str = "IOC-Collector", confidence: str = "High", tlp: str = "TLP:CLEAR") -> str:
    """
    IOC sözlüğünden STIX 2.1 Bundle JSON döndürür.
    """
    objects = []

    type_key_map = {
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "domains": "domain",
        "urls": "url",
        "emails": "email",
        "hash_md5": "hash_md5",
        "hash_sha1": "hash_sha1",
        "hash_sha256": "hash_sha256",
        "hash_sha512": "hash_sha512",
    }

    for key, stix_type in type_key_map.items():
        items = iocs.get(key, [])
        if isinstance(items, list):
            for value in items:
                indicator = _stix_indicator(stix_type, value, confidence, tlp)
                objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": _make_stix_id("bundle"),
        "objects": objects,
    }

    return json.dumps(bundle, indent=2, ensure_ascii=False)
