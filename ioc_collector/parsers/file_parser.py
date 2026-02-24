import os
import sys
import logging

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


def read_file(path: str) -> str:
    """Dosyayı okur."""
    # stdin desteği
    if path == "-":
        logger.info("stdin'den okuyor...")
        return sys.stdin.read()

    # Dosya varlık kontrolü
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dosya bulunamadı: {path}")

    if not os.path.isfile(path):
        raise ValueError(f"Belirtilen yol bir dosya değil: {path}")

    # İzin kontrolü
    if not os.access(path, os.R_OK):
        raise PermissionError(f"Dosya okuma izni yok: {path}")

    # Boyut kontrolü
    file_size = os.path.getsize(path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            f"Dosya boyutu çok büyük: {file_size / (1024*1024):.1f} MB "
            f"(maksimum: {MAX_FILE_SIZE / (1024*1024):.0f} MB)"
        )

    if file_size == 0:
        logger.warning(f"Dosya boş: {path}")
        return ""

    logger.info(f"Dosya okunuyor: {path} ({file_size / 1024:.1f} KB)")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def read_multiple_files(paths: list) -> str:
    """Birden fazla dosyayı okur."""
    contents = []
    for path in paths:
        try:
            content = read_file(path)
            contents.append(content)
        except (FileNotFoundError, PermissionError, ValueError) as e:
            logger.error(f"Dosya okunamadı: {e}")
            continue
    return "\n".join(contents)