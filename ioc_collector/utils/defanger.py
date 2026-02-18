import re


def refang(text: str) -> str:
    """Defanged IOC'leri normale çevirir."""
    replacements = [
        (r'hxxps://', 'https://'),
        (r'hxxp://', 'http://'),
        (r'\[://\]', '://'),
        (r'\[\.\]', '.'),
        (r'\(\.\)', '.'),
        (r'\{\.}', '.'),
        (r'\[@\]', '@'),
        (r'\[at\]', '@'),
        (r'\(at\)', '@'),
        (r'\[dot\]', '.'),
        (r'\(dot\)', '.'),
    ]
    result = text
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def defang(text: str) -> str:
    """IOC'leri güvenli paylaşım için defanged formata çevirir."""
    result = text
    result = result.replace('https://', 'hxxps://')
    result = result.replace('http://', 'hxxp://')
    result = result.replace('ftp://', 'fxp://')

    # URL'ler dışındaki nokta ve @ işaretlerini defang et
    # Protokolden sonraki kısımdaki nokta ve @'leri değiştir
    if '://' not in text:
        result = result.replace('.', '[.]')
        result = result.replace('@', '[@]')
    else:
        # URL ise sadece domain kısmındaki nokta ve @'leri değiştir
        parts = result.split('://', 1)
        if len(parts) == 2:
            protocol = parts[0]
            rest = parts[1]
            rest = rest.replace('.', '[.]')
            rest = rest.replace('@', '[@]')
            result = f"{protocol}://{rest}"

    return result