#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import json
import logging
import platform
import socket
import ssl
import sys
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# ====================================
# Project constants and capture policy
# ====================================

# ----------- tool identity --------------

TOOL_NAME = "WebTrace"
TOOL_VERSION = "1.0.0"
DEFAULT_VIEWPORT = {"width": 1365, "height": 768}
NAVIGATION_TIMEOUT_MS = 60_000
NETWORK_IDLE_TIMEOUT_MS = 10_000
TLS_TIMEOUT_SECONDS = 10
THUMBNAIL_MAX_SIZE = (420, 420)

# ----------- evidence package layout --------------

SUBFOLDERS = (
    "evidence",
    "screenshots",
    "html",
    "mhtml",
    "pdf",
    "har",
    "warc",
    "metadata",
    "hashes",
    "logs",
    "reports",
)

# ----------- scope notes written into every capture --------------

DEFAULT_LIMITATIONS = [
    "This tool preserves publicly accessible pages and authorised cookie-based sessions only; it does not bypass access controls, solve CAPTCHAs, or use private APIs.",
    "WARC output is best-effort and is not a complete network-level crawl; HAR, MHTML, HTML, and screenshot artifacts are preserved as supporting evidence.",
    "Browser-rendered HTML from page.content() may differ from the original server response.",
    "Dynamic content, deleted content, geolocation, personalization, and later page changes may affect reproducibility.",
    "PDF generation depends on Chromium support and may not exactly match the interactive page view.",
]


# ====================================
# Time, URL, and small normalization helpers
# ====================================

# ----------- UTC-only timestamp helpers --------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class UTCFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        return iso_utc(datetime.fromtimestamp(record.created, timezone.utc))


def folder_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


# ----------- URL and cookie value normalization --------------

def validate_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must be an absolute http:// or https:// URL.")


def normalize_same_site(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower().replace("-", "_")
    mapping = {
        "strict": "Strict",
        "lax": "Lax",
        "none": "None",
        "no_restriction": "None",
    }
    return mapping.get(normalized)


def parse_cookie_expiry(cookie: dict[str, Any]) -> float | None:
    for key in ("expires", "expirationDate", "expiry", "expiration_date"):
        if key not in cookie:
            continue
        try:
            expires = float(cookie[key])
        except (TypeError, ValueError):
            return None
        return expires if expires > 0 else None
    return None


# ====================================
# Cookie import and signing-key validation
# ====================================

# Playwright BrowserContext.add_cookies API:
#   https://playwright.dev/python/docs/api/class-browsercontext#browser-context-add-cookies

# ----------- cookie JSON parsing --------------

def extract_cookie_list(raw_data: Any) -> list[dict[str, Any]]:
    if isinstance(raw_data, list):
        candidates = raw_data
    elif isinstance(raw_data, dict) and isinstance(raw_data.get("cookies"), list):
        candidates = raw_data["cookies"]
    else:
        raise ValueError("Cookie JSON must be a list of cookies or an object with a 'cookies' list.")

    cookies = [item for item in candidates if isinstance(item, dict)]
    if len(cookies) != len(candidates):
        raise ValueError("Cookie JSON contains entries that are not objects.")
    return cookies


# ----------- browser-cookie mapping --------------

def load_cookies(cookies_path: Path, target_url: str) -> tuple[list[dict[str, Any]], int, int]:
    parsed_url = urlparse(target_url)
    target_host = parsed_url.hostname or ""
    raw_data = json.loads(cookies_path.read_text(encoding="utf-8"))
    source_cookies = extract_cookie_list(raw_data)

    loaded: list[dict[str, Any]] = []
    skipped = 0

    for source in source_cookies:
        name = str(source.get("name", ""))
        value = source.get("value")

        if not name or value is None:
            skipped += 1
            continue

        source_domain = str(source.get("domain") or target_host)

        cookie_path = str(source.get("path") or "/")
        if not cookie_path.startswith("/"):
            cookie_path = f"/{cookie_path}"

        cookie: dict[str, Any] = {
            "name": name,
            "value": str(value),
            "domain": source_domain.lstrip("."),
            "path": cookie_path,
            "secure": bool(source.get("secure", parsed_url.scheme == "https")),
            "httpOnly": bool(source.get("httpOnly", source.get("http_only", False))),
        }

        expires = parse_cookie_expiry(source)
        if expires is not None:
            cookie["expires"] = expires

        same_site = normalize_same_site(source.get("sameSite", source.get("same_site")))
        if same_site is not None:
            cookie["sameSite"] = same_site

        loaded.append(cookie)

    return loaded, len(source_cookies), skipped


# Ed25519 signing in cryptography:
#   https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

# ----------- operator signing key validation --------------

def validate_signing_key_file(signing_key_path: Path) -> None:
    if not signing_key_path.is_file():
        raise ValueError(f"Signing key does not exist: {signing_key_path}")

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise ValueError("cryptography is required to use --signing-key.") from exc

    private_key = serialization.load_pem_private_key(signing_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key in PEM format.")


# ====================================
# Filesystem, logging, and hashing basics
# ====================================

# ----------- capture folder creation --------------

def make_capture_folder(output_root: Path, case_id: str, started: datetime) -> Path:
    case_folder = output_root / case_id
    base_name = folder_timestamp(started)
    capture_folder = case_folder / base_name
    counter = 1
    while capture_folder.exists():
        capture_folder = case_folder / f"{base_name}-{counter:02d}"
        counter += 1

    for subfolder in SUBFOLDERS:
        (capture_folder / subfolder).mkdir(parents=True, exist_ok=False)
    return capture_folder


# ----------- logging setup and teardown --------------

def setup_logging(log_path: Path) -> logging.Logger:
    logger = logging.getLogger("webtrace.capture")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = UTCFormatter("{asctime} {levelname} {message}", style="{")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def close_logger(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        handler.flush()
        handler.close()
        logger.removeHandler(handler)


# ----------- file paths and hashes --------------

def relative_path(capture_folder: Path, path: Path) -> str:
    return path.relative_to(capture_folder).as_posix()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_mtime_utc(path: Path) -> str:
    return iso_utc(datetime.fromtimestamp(path.stat().st_mtime, timezone.utc))


def safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)
    return cleaned.strip("._") or "artifact"


# ----------- URL target de-duplication --------------

def parsed_port(parsed_url: Any) -> int:
    if parsed_url.port is not None:
        return parsed_url.port
    return 443 if parsed_url.scheme == "https" else 80


def unique_url_targets(*urls: str) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, int]] = set()
    targets: list[dict[str, Any]] = []
    for url in urls:
        if not url:
            continue
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        key = (parsed.scheme, parsed.hostname.lower(), parsed_port(parsed))
        if key in seen:
            continue
        seen.add(key)
        targets.append({"url": url, "scheme": key[0], "hostname": key[1], "port": key[2]})
    return targets


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ====================================
# Chain of custody helpers
# ====================================

# ----------- append one custody row --------------

def append_chain_entry(
    capture_folder: Path,
    case_id: str,
    evidence_id: str,
    operator: str,
    action: str,
    artifact: str = "",
    sha256: str = "",
    notes: str = "",
) -> None:
    chain_path = capture_folder / "chain_of_custody.csv"
    new_file = not chain_path.exists()
    with chain_path.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "case_id",
                "evidence_id",
                "timestamp_utc",
                "operator",
                "action",
                "artifact",
                "sha256",
                "notes",
            ],
        )
        if new_file:
            writer.writeheader()
        writer.writerow(
            {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "timestamp_utc": iso_utc(utc_now()),
                "operator": operator,
                "action": action,
                "artifact": artifact,
                "sha256": sha256,
                "notes": notes,
            }
        )


# ----------- record an artifact and its hash --------------

def record_artifact(
    capture_folder: Path,
    files_created: set[str],
    case_id: str,
    evidence_id: str,
    operator: str,
    action: str,
    path: Path,
    notes: str = "",
) -> None:
    rel = relative_path(capture_folder, path)
    files_created.add(rel)
    append_chain_entry(
        capture_folder=capture_folder,
        case_id=case_id,
        evidence_id=evidence_id,
        operator=operator,
        action=action,
        artifact=rel,
        sha256=sha256_file(path),
        notes=notes,
    )


# ----------- simple text and JSON writers --------------

def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


# ====================================
# DNS and TLS metadata collection
# ====================================

# Python ssl:
#   https://docs.python.org/3/library/ssl.html
# cryptography X.509 reference:
#   https://cryptography.io/en/latest/x509/reference/
# Stack Overflow note on getpeercert DER/PEM behavior:
#   https://stackoverflow.com/questions/31270898/python-get-ssl-certificate-information-getpeercert

# ----------- DNS result formatting --------------

def dns_family_name(family: int) -> str:
    try:
        return socket.AddressFamily(family).name
    except ValueError:
        return str(family)


def dns_socket_type_name(socktype: int) -> str:
    try:
        return socket.SocketKind(socktype).name
    except ValueError:
        return str(socktype)


# ----------- local resolver lookup --------------

def collect_dns_resolution(original_url: str, final_url: str) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for target in unique_url_targets(original_url, final_url):
        entry: dict[str, Any] = {
            "url": target["url"],
            "hostname": target["hostname"],
            "port": target["port"],
            "scheme": target["scheme"],
            "resolved_at_utc": iso_utc(utc_now()),
            "resolver": "system resolver via socket.getaddrinfo",
            "records": [],
            "errors": [],
        }
        seen_records: set[tuple[str, int, str]] = set()
        try:
            infos = socket.getaddrinfo(target["hostname"], target["port"], type=socket.SOCK_STREAM)
            for family, socktype, proto, canonname, sockaddr in infos:
                address = str(sockaddr[0])
                address_port = int(sockaddr[1]) if len(sockaddr) > 1 else target["port"]
                key = (address, address_port, dns_family_name(family))
                if key in seen_records:
                    continue
                seen_records.add(key)
                entry["records"].append(
                    {
                        "address": address,
                        "port": address_port,
                        "family": dns_family_name(family),
                        "socket_type": dns_socket_type_name(socktype),
                        "protocol": proto,
                        "canonical_name": canonname,
                    }
                )
        except Exception as exc:  # noqa: BLE001 - metadata collection should not stop capture.
            entry["errors"].append(str(exc))
        entries.append(entry)

    return {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "collected_at_utc": iso_utc(utc_now()),
        "method": "Python socket.getaddrinfo using the local system resolver",
        "targets": entries,
    }


# ----------- X.509 parsing helpers --------------

def x509_name_to_list(name: Any) -> list[dict[str, str]]:
    return [
        {
            "oid": attribute.oid.dotted_string,
            "name": getattr(attribute.oid, "_name", attribute.oid.dotted_string),
            "value": str(attribute.value),
        }
        for attribute in name
    ]


def x509_time_to_utc(value: Any) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return iso_utc(value)


# ----------- leaf certificate extraction --------------

def collect_leaf_certificate_details(der_bytes: bytes) -> dict[str, Any]:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der_bytes)
    pem_text = ssl.DER_cert_to_PEM_cert(der_bytes)

    dns_names: list[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = list(extension.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = []

    public_key = cert.public_key()
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after

    return {
        "sha256": sha256_bytes(der_bytes),
        "serial_number_hex": format(cert.serial_number, "x"),
        "subject": x509_name_to_list(cert.subject),
        "issuer": x509_name_to_list(cert.issuer),
        "not_valid_before_utc": x509_time_to_utc(not_before),
        "not_valid_after_utc": x509_time_to_utc(not_after),
        "dns_names": dns_names,
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_hash_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "public_key_type": public_key.__class__.__name__,
        "public_key_size": getattr(public_key, "key_size", None),
        "version": cert.version.name,
        "pem": pem_text,
    }


# ----------- TLS socket collection with verified-first fallback --------------

def fetch_tls_leaf_certificate(hostname: str, port: int) -> tuple[dict[str, Any], bytes | None]:
    entry: dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "collected_at_utc": iso_utc(utc_now()),
        "validation_attempted": True,
        "validation_succeeded": False,
        "validation_error": "",
        "tls_version": "",
        "cipher": None,
        "compression": None,
        "leaf_certificate": None,
        "errors": [],
    }

    contexts = [ssl.create_default_context()]
    try:
        with socket.create_connection((hostname, port), timeout=TLS_TIMEOUT_SECONDS) as raw_socket:
            with contexts[0].wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                entry["validation_succeeded"] = True
                entry["tls_version"] = tls_socket.version()
                entry["cipher"] = tls_socket.cipher()
                entry["compression"] = tls_socket.compression()
                der_bytes = tls_socket.getpeercert(binary_form=True)
                if der_bytes:
                    entry["leaf_certificate"] = collect_leaf_certificate_details(der_bytes)
                return entry, der_bytes
    except Exception as exc:  # noqa: BLE001 - retry unverified to preserve certificate details.
        entry["validation_error"] = str(exc)

    try:
        unverified_context = ssl._create_unverified_context()  # noqa: S323 - deliberate evidence collection fallback.
        with socket.create_connection((hostname, port), timeout=TLS_TIMEOUT_SECONDS) as raw_socket:
            with unverified_context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                entry["tls_version"] = tls_socket.version()
                entry["cipher"] = tls_socket.cipher()
                entry["compression"] = tls_socket.compression()
                der_bytes = tls_socket.getpeercert(binary_form=True)
                if der_bytes:
                    entry["leaf_certificate"] = collect_leaf_certificate_details(der_bytes)
                return entry, der_bytes
    except Exception as exc:  # noqa: BLE001
        entry["errors"].append(str(exc))
        return entry, None


# ----------- DNS/TLS artifact writers --------------

def collect_tls_metadata(original_url: str, final_url: str, certificate_output_dir: Path) -> dict[str, Any]:
    certificate_output_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for target in unique_url_targets(original_url, final_url):
        if target["scheme"] != "https":
            entries.append(
                {
                    "url": target["url"],
                    "hostname": target["hostname"],
                    "port": target["port"],
                    "skipped": True,
                    "reason": "TLS certificate metadata is only collected for HTTPS URLs.",
                }
            )
            continue

        entry, der_bytes = fetch_tls_leaf_certificate(target["hostname"], target["port"])
        entry["url"] = target["url"]
        if der_bytes:
            pem_path = certificate_output_dir / f"{safe_name(target['hostname'])}_{target['port']}_leaf.pem"
            write_text(pem_path, ssl.DER_cert_to_PEM_cert(der_bytes))
            entry["leaf_certificate_pem_file"] = pem_path.name
        entries.append(entry)

    return {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "collected_at_utc": iso_utc(utc_now()),
        "method": "Python ssl socket connection with SNI; verification attempted first, unverified fallback records leaf details when needed.",
        "targets": entries,
    }


def write_network_artifacts(
    capture_folder: Path,
    original_url: str,
    final_url: str,
    files_created: set[str],
    case_id: str,
    evidence_id: str,
    operator: str,
    logger: logging.Logger,
    errors: list[str],
) -> None:
    dns_path = capture_folder / "metadata" / "dns_resolution.json"
    tls_path = capture_folder / "metadata" / "tls_certificate_metadata.json"
    cert_dir = capture_folder / "metadata" / "tls_certificates"

    try:
        write_json(dns_path, collect_dns_resolution(original_url, final_url))
        logger.info(f"DNS metadata saved to {dns_path}")
        record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "DNS metadata saved", dns_path)
    except Exception as exc:  # noqa: BLE001
        message = f"DNS metadata collection failed: {exc}"
        errors.append(message)
        logger.exception("DNS metadata collection failed")

    try:
        tls_metadata = collect_tls_metadata(original_url, final_url, cert_dir)
        write_json(tls_path, tls_metadata)
        logger.info(f"TLS certificate metadata saved to {tls_path}")
        record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "TLS metadata saved", tls_path)
        for pem_path in sorted(cert_dir.glob("*.pem")):
            record_artifact(
                capture_folder,
                files_created,
                case_id,
                evidence_id,
                operator,
                "TLS leaf certificate PEM saved",
                pem_path,
            )
    except Exception as exc:  # noqa: BLE001
        message = f"TLS metadata collection failed: {exc}"
        errors.append(message)
        logger.exception("TLS metadata collection failed")


# ====================================
# Screenshot thumbnails
# ====================================

# Pillow Image module:
# https://pillow.readthedocs.io/en/stable/reference/Image.html

# ----------- derivative thumbnail and index generation --------------

def create_screenshot_thumbnail_index(
    capture_folder: Path,
    files_created: set[str],
    case_id: str,
    evidence_id: str,
    operator: str,
    logger: logging.Logger,
    known_limitations: list[str],
    errors: list[str],
) -> None:
    index_json_path = capture_folder / "screenshots" / "thumbnail_index.json"
    index_html_path = capture_folder / "screenshots" / "thumbnail_index.html"
    thumbnail_dir = capture_folder / "screenshots" / "thumbnails"
    thumbnail_dir.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    try:
        from PIL import Image

        screenshot_paths = sorted(
            path for path in (capture_folder / "screenshots").glob("*.png") if path.is_file() and path.parent != thumbnail_dir
        )
        for screenshot_path in screenshot_paths:
            with Image.open(screenshot_path) as image:
                original_width, original_height = image.size
                thumbnail = image.copy()
                thumbnail.thumbnail(THUMBNAIL_MAX_SIZE)
                thumbnail_path = thumbnail_dir / f"{screenshot_path.stem}_thumbnail.png"
                thumbnail.save(thumbnail_path, "PNG")

            entry = {
                "original_file": relative_path(capture_folder, screenshot_path),
                "thumbnail_file": relative_path(capture_folder, thumbnail_path),
                "original_sha256": sha256_file(screenshot_path),
                "thumbnail_sha256": sha256_file(thumbnail_path),
                "original_size_bytes": screenshot_path.stat().st_size,
                "thumbnail_size_bytes": thumbnail_path.stat().st_size,
                "original_dimensions": {"width": original_width, "height": original_height},
                "thumbnail_max_dimensions": {"width": THUMBNAIL_MAX_SIZE[0], "height": THUMBNAIL_MAX_SIZE[1]},
                "created_utc": iso_utc(utc_now()),
            }
            entries.append(entry)
            record_artifact(
                capture_folder,
                files_created,
                case_id,
                evidence_id,
                operator,
                "screenshot thumbnail saved",
                thumbnail_path,
            )
    except ImportError as exc:
        message = "Pillow is not installed; screenshot thumbnails were not generated."
        known_limitations.append(message)
        errors.append(str(exc))
        logger.warning(message)
    except Exception as exc:  # noqa: BLE001
        message = f"Screenshot thumbnail generation failed: {exc}"
        known_limitations.append(message)
        errors.append(message)
        logger.exception("Screenshot thumbnail generation failed")

    index_data = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "created_utc": iso_utc(utc_now()),
        "note": "Thumbnails are derivative viewing aids only; original screenshots remain the primary evidence.",
        "thumbnails": entries,
    }
    write_json(index_json_path, index_data)

    html_lines = [
        "<!doctype html>",
        "<html>",
        "<head>",
        '  <meta charset="utf-8">',
        "  <title>Screenshot Thumbnail Index</title>",
        "  <style>body{font-family:Arial,sans-serif;margin:2rem;}figure{display:inline-block;margin:0 1rem 1rem 0;vertical-align:top;}img{border:1px solid #999;max-width:420px;height:auto;}figcaption{max-width:420px;font-size:0.9rem;word-break:break-word;}</style>",
        "</head>",
        "<body>",
        "  <h1>Screenshot Thumbnail Index</h1>",
        "  <p>Derivative thumbnails for quick review. Use original screenshot files for evidence examination.</p>",
    ]
    if entries:
        for entry in entries:
            thumb_href = html.escape(Path(entry["thumbnail_file"]).relative_to("screenshots").as_posix())
            original_name = html.escape(entry["original_file"])
            thumb_hash = html.escape(entry["thumbnail_sha256"])
            original_hash = html.escape(entry["original_sha256"])
            html_lines.extend(
                [
                    "  <figure>",
                    f'    <a href="{thumb_href}"><img src="{thumb_href}" alt="{original_name}"></a>',
                    f"    <figcaption><strong>{original_name}</strong><br>Original SHA-256: {original_hash}<br>Thumbnail SHA-256: {thumb_hash}</figcaption>",
                    "  </figure>",
                ]
            )
    else:
        html_lines.append("  <p>No screenshot thumbnails were generated.</p>")
    html_lines.extend(["</body>", "</html>", ""])
    write_text(index_html_path, "\n".join(html_lines))

    record_artifact(
        capture_folder,
        files_created,
        case_id,
        evidence_id,
        operator,
        "screenshot thumbnail index saved",
        index_json_path,
    )
    record_artifact(
        capture_folder,
        files_created,
        case_id,
        evidence_id,
        operator,
        "screenshot thumbnail HTML index saved",
        index_html_path,
    )


# ====================================
# Capture configuration metadata
# ====================================

# ----------- command-line redaction --------------

def sanitized_argv(argv: list[str]) -> list[str]:
    sanitized: list[str] = []
    redact_next: str | None = None
    for value in argv:
        if redact_next is not None:
            sanitized.append(redact_next)
            redact_next = None
            continue
        sanitized.append(value)
        if value == "--cookies":
            redact_next = "<cookie-file-redacted>"
        elif value == "--signing-key":
            redact_next = "<signing-key-file-redacted>"
    return sanitized


# ----------- runtime configuration snapshot --------------

def write_capture_config(
    capture_folder: Path,
    args: argparse.Namespace,
    evidence_id: str,
    start: datetime,
    browser_result: dict[str, Any],
    cookies_path: Path | None,
    signing_key_path: Path | None,
    files_created: set[str],
    case_id: str,
    operator: str,
    logger: logging.Logger,
) -> Path:
    config_path = capture_folder / "metadata" / "capture_config.json"
    source_file = Path(__file__).resolve()
    cookie_source: dict[str, Any] = {"provided": cookies_path is not None}
    if cookies_path is not None:
        cookie_source.update(
            {
                "file_name": cookies_path.name,
                "exists_at_capture_time": cookies_path.exists(),
            }
        )
        if cookies_path.exists():
            cookie_source.update(
                {
                    "sha256": sha256_file(cookies_path),
                    "size_bytes": cookies_path.stat().st_size,
                    "modified_time_utc": file_mtime_utc(cookies_path),
                }
            )

    signing_key_source: dict[str, Any] = {"provided": signing_key_path is not None}
    if signing_key_path is not None:
        signing_key_source.update(
            {
                "file_name": signing_key_path.name,
                "exists_at_capture_time": signing_key_path.exists(),
            }
        )
        if signing_key_path.exists():
            signing_key_source.update(
                {
                    "sha256": sha256_file(signing_key_path),
                    "size_bytes": signing_key_path.stat().st_size,
                    "modified_time_utc": file_mtime_utc(signing_key_path),
                }
            )

    config = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "config_created_utc": iso_utc(utc_now()),
        "case_id": args.case_id,
        "evidence_id": evidence_id,
        "capture_folder": str(capture_folder),
        "operator": args.operator,
        "original_url": args.url,
        "final_url": browser_result.get("final_url", ""),
        "capture_start_utc": iso_utc(start),
        "sanitized_argv": sanitized_argv(sys.argv),
        "runtime": {
            "python_version": platform.python_version(),
            "os_platform": platform.platform(),
            "executable": sys.executable,
            "source_file": str(source_file),
            "source_file_sha256": sha256_file(source_file) if source_file.exists() else "",
        },
        "browser_capture_settings": {
            "browser_name": browser_result.get("browser_name", "chromium"),
            "browser_version": browser_result.get("browser_version", ""),
            "viewport": browser_result.get("viewport", DEFAULT_VIEWPORT),
            "navigation_wait_until": "domcontentloaded",
            "navigation_timeout_ms": NAVIGATION_TIMEOUT_MS,
            "network_idle_timeout_ms": NETWORK_IDLE_TIMEOUT_MS,
            "har_record_content": "embed",
            "screenshot_full_page": True,
            "mhtml_method": "Chrome DevTools Protocol Page.captureSnapshot",
            "pdf_print_background": True,
        },
        "optional_cookie_source": cookie_source,
        "optional_signing_key_source": signing_key_source,
        "integrity_settings": {
            "hash_algorithm": "SHA-256",
            "manifest_files": ["hashes/manifest.json", "hashes/manifest.sha256"],
            "signed_manifest": True,
            "signature_algorithm": "Ed25519",
            "signature_files": [
                "hashes/manifest.sig",
                "hashes/manifest_public_key.pem",
                "hashes/signature_metadata.json",
            ],
        },
        "network_metadata_settings": {
            "dns_method": "socket.getaddrinfo using local system resolver",
            "tls_timeout_seconds": TLS_TIMEOUT_SECONDS,
            "tls_verification_attempted": True,
        },
        "scope_controls": {
            "public_or_owned_pages_only": True,
            "does_not_bypass_access_controls": True,
            "does_not_solve_captchas": True,
            "does_not_use_private_apis": True,
            "auth_like_cookies_allowed": True,
            "all_valid_cookies_loaded": True
        },
    }
    write_json(config_path, config)
    logger.info(f"Capture config saved to {config_path}")
    record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "capture config saved", config_path)
    return config_path


# ====================================
# WARC writer
# ====================================

# warcio project:
# https://github.com/webrecorder/warcio

# ----------- best-effort WARC metadata and main response --------------

def build_warc(
    capture_folder: Path,
    original_url: str,
    final_url: str,
    response_status: int | None,
    response_status_text: str,
    response_headers: dict[str, str],
    main_response_text: str | None,
    logger: logging.Logger,
    known_limitations: list[str],
    errors: list[str],
) -> Path | None:
    warc_path = capture_folder / "warc" / "capture.warc.gz"
    try:
        from warcio.statusandheaders import StatusAndHeaders
        from warcio.warcwriter import WARCWriter
    except ImportError as exc:
        message = "warcio is not installed; WARC output was not created."
        known_limitations.append(message)
        errors.append(str(exc))
        logger.warning(message)
        return None

    metadata_payload = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "original_url": original_url,
        "final_url": final_url,
        "created_utc": iso_utc(utc_now()),
        "warc_scope": "Best-effort WARC. Includes target metadata and the main HTML response only when available.",
    }

    try:
        with warc_path.open("wb") as stream:
            writer = WARCWriter(stream, gzip=True)
            metadata_record = writer.create_warc_record(
                original_url,
                "metadata",
                payload=BytesIO(json.dumps(metadata_payload, indent=2).encode("utf-8")),
                warc_headers_dict={"Content-Type": "application/json"},
            )
            writer.write_record(metadata_record)

            if main_response_text is not None and response_status is not None:
                headers = list(response_headers.items())
                status_text = (response_status_text or "").strip() or "OK"
                http_headers = StatusAndHeaders(
                    f"{response_status} {status_text}",
                    headers,
                    protocol="HTTP/1.1",
                )
                response_record = writer.create_warc_record(
                    final_url or original_url,
                    "response",
                    payload=BytesIO(main_response_text.encode("utf-8")),
                    http_headers=http_headers,
                )
                writer.write_record(response_record)
            else:
                limitation = "Main HTML response body was not available for WARC response record."
                known_limitations.append(limitation)
                logger.warning(limitation)
    except Exception as exc:  # noqa: BLE001 - evidence preservation should continue.
        message = f"WARC creation failed: {exc}"
        known_limitations.append(message)
        errors.append(message)
        logger.exception("WARC creation failed")
        return None

    known_limitations.append(
        "WARC contains target metadata and, when available, the main HTML response only; it is not a full request/response WARC capture."
    )
    logger.info(f"WARC saved to {warc_path}")
    return warc_path


# ====================================
# Browser capture with Playwright Chromium
# ====================================

# Playwright Page API:
#   https://playwright.dev/python/docs/api/class-page
# Playwright network guide:
#   https://playwright.dev/python/docs/network
# Playwright Browser.new_context options, including HAR recording:
#   https://playwright.dev/python/docs/api/class-browser#browser-new-context
# Playwright BrowserContext.close writes pending context artifacts such as HAR:
#   https://playwright.dev/python/docs/api/class-browsercontext#browser-context-close
# Chrome DevTools Protocol Page.captureSnapshot:
#   https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-captureSnapshot

# ----------- small adapter for Playwright values that may be properties or callables --------------

def call_maybe(value: Any) -> Any:
    return value() if callable(value) else value


# ----------- full browser evidence collection --------------

def run_browser_capture(
    capture_folder: Path,
    url: str,
    cookies_path: Path | None,
    files_created: set[str],
    case_id: str,
    evidence_id: str,
    operator: str,
    known_limitations: list[str],
    errors: list[str],
    logger: logging.Logger,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "final_url": "",
        "page_title": "",
        "browser_name": "chromium",
        "browser_version": "",
        "user_agent": "",
        "viewport": DEFAULT_VIEWPORT,
        "cookies_requested": cookies_path is not None,
        "cookies_loaded_count": 0,
        "cookies_skipped_count": 0,
    }

    har_path = capture_folder / "har" / "capture.har"
    screenshot_path = capture_folder / "screenshots" / "full_page.png"
    html_path = capture_folder / "html" / "page.html"
    mhtml_path = capture_folder / "mhtml" / "snapshot.mhtml"
    pdf_path = capture_folder / "pdf" / "page.pdf"

    response_status: int | None = None
    response_status_text = ""
    response_headers: dict[str, str] = {}
    main_response_text: str | None = None
    warc_saved = False
    har_saved = False

    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        message = "Playwright is not installed; browser capture could not run."
        errors.append(message)
        known_limitations.append(message)
        logger.exception(message)
        append_chain_entry(
            capture_folder,
            case_id,
            evidence_id,
            operator,
            "WARC limitation logged",
            "metadata/capture_log.txt",
            "",
            "Browser capture could not run, so no response was available for WARC.",
        )
        return result

    playwright = None
    browser = None
    context = None

    try:
        logger.info(f"Starting Chromium capture for {url}")
        playwright = sync_playwright().start()
        browser = playwright.chromium.launch(headless=True)
        result["browser_version"] = browser.version
        context = browser.new_context(
            viewport=DEFAULT_VIEWPORT,
            record_har_path=str(har_path),
            record_har_content="embed",
        )
        if cookies_path is not None:
            limitation = (
                "Cookie import is optional and loads all valid cookies from the provided cookie file. "
                "Only use this with cookies and accounts you are authorised to use."
            )
            known_limitations.append(limitation)
            try:
                cookies, total_cookies, skipped_cookies = load_cookies(cookies_path, url)
                if cookies:
                    context.add_cookies(cookies)
                result["cookies_loaded_count"] = len(cookies)
                result["cookies_skipped_count"] = skipped_cookies
                logger.info(
                    f"Cookie file requested; loaded {len(cookies)} cookie(s), "
                    f"skipped {skipped_cookies} of {total_cookies}"
                )
            except Exception as exc:  # noqa: BLE001 - capture can continue without optional cookies.
                message = f"Cookie file could not be loaded: {exc}"
                errors.append(message)
                known_limitations.append(message)
                logger.warning(message)

        page = context.new_page()

        def log_response(response: Any) -> None:
            try:
                status = response.status
                if 300 <= status < 400:
                    location = response.headers.get("location", "")
                    logger.info(f"Redirect response: {response.url} status={status} location={location}")
            except Exception as exc:  # noqa: BLE001 - event logging must not interrupt capture.
                logger.warning(f"Could not log response event: {exc}")

        def log_request_failed(request: Any) -> None:
            try:
                failure = call_maybe(getattr(request, "failure", "unknown"))
                logger.warning(f"Request failed: {request.url} reason={failure}")
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"Could not log failed request event: {exc}")

        page.on("response", log_response)
        page.on("requestfailed", log_request_failed)

        response = None
        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=60_000)
            logger.info("Initial navigation completed")
            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
                logger.info("Network idle reached")
            except PlaywrightTimeoutError:
                limitation = "Network idle was not reached before timeout; capture continued with available page state."
                known_limitations.append(limitation)
                logger.warning(limitation)
        except PlaywrightTimeoutError as exc:
            message = f"Page load timed out: {exc}"
            errors.append(message)
            logger.exception("Page load timed out")
        except Exception as exc:  # noqa: BLE001
            message = f"Page load failed: {exc}"
            errors.append(message)
            logger.exception("Page load failed")

        result["final_url"] = page.url
        logger.info(f"Final URL after navigation: {result['final_url']}")

        if response is not None:
            response_status = response.status
            response_status_text = str(call_maybe(getattr(response, "status_text", "")) or "")
            response_headers = dict(response.headers)
            logger.info(f"Main response status: {response_status} {response_status_text}")
            content_type = response_headers.get("content-type", "")
            if "text/html" in content_type.lower() or content_type.lower().startswith("text/"):
                try:
                    main_response_text = response.text()
                except Exception as exc:  # noqa: BLE001
                    message = f"Could not read main response body for WARC: {exc}"
                    known_limitations.append(message)
                    logger.warning(message)
            else:
                limitation = f"Main response content type was not HTML/text ({content_type}); WARC response body was not stored."
                known_limitations.append(limitation)
                logger.warning(limitation)
        else:
            limitation = "No main navigation response was available for WARC."
            known_limitations.append(limitation)
            logger.warning(limitation)

        try:
            result["page_title"] = page.title()
            logger.info(f"Page title captured: {result['page_title']}")
        except Exception as exc:  # noqa: BLE001
            message = f"Could not read page title: {exc}"
            errors.append(message)
            logger.warning(message)

        try:
            result["user_agent"] = page.evaluate("() => navigator.userAgent")
            logger.info(f"User agent captured: {result['user_agent']}")
        except Exception as exc:  # noqa: BLE001
            message = f"Could not read user agent: {exc}"
            errors.append(message)
            logger.warning(message)

        try:
            page.screenshot(path=str(screenshot_path), full_page=True)
            logger.info(f"Screenshot saved to {screenshot_path}")
            record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "screenshot saved", screenshot_path)
        except Exception as exc:  # noqa: BLE001
            message = f"Screenshot capture failed: {exc}"
            errors.append(message)
            logger.exception("Screenshot capture failed")

        try:
            html_source = page.content()
            write_text(html_path, html_source)
            logger.info(f"HTML saved to {html_path}")
            record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "HTML saved", html_path)
        except Exception as exc:  # noqa: BLE001
            message = f"HTML capture failed: {exc}"
            errors.append(message)
            logger.exception("HTML capture failed")

        try:
            cdp = context.new_cdp_session(page)
            snapshot = cdp.send("Page.captureSnapshot", {"format": "mhtml"})
            write_text(mhtml_path, snapshot.get("data", ""))
            logger.info(f"MHTML snapshot saved to {mhtml_path}")
            record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "MHTML saved", mhtml_path)
        except Exception as exc:  # noqa: BLE001
            message = f"MHTML snapshot failed: {exc}"
            errors.append(message)
            logger.exception("MHTML snapshot failed")

        try:
            page.pdf(path=str(pdf_path), print_background=True)
            logger.info(f"PDF saved to {pdf_path}")
            record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "PDF saved", pdf_path)
        except Exception as exc:  # noqa: BLE001
            message = f"PDF generation failed or is unsupported: {exc}"
            known_limitations.append(message)
            logger.warning(message)

    except Exception as exc:  # noqa: BLE001 - partial evidence package should still be finalized.
        message = f"Browser capture failed: {exc}"
        errors.append(message)
        logger.exception("Browser capture failed")

    finally:
        if context is not None:
            try:
                context.close()
                if har_path.exists():
                    har_saved = True
                    logger.info(f"HAR saved to {har_path}")
                    record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "HAR saved", har_path)
            except Exception as exc:  # noqa: BLE001
                message = f"Closing browser context or writing HAR failed: {exc}"
                errors.append(message)
                logger.exception("Closing browser context or writing HAR failed")
        if browser is not None:
            try:
                browser.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"Closing browser failed: {exc}")
        if playwright is not None:
            try:
                playwright.stop()
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"Stopping Playwright failed: {exc}")

    warc_path = build_warc(
        capture_folder=capture_folder,
        original_url=url,
        final_url=result["final_url"],
        response_status=response_status,
        response_status_text=response_status_text,
        response_headers=response_headers,
        main_response_text=main_response_text,
        logger=logger,
        known_limitations=known_limitations,
        errors=errors,
    )
    if warc_path is not None:
        warc_saved = True
        record_artifact(capture_folder, files_created, case_id, evidence_id, operator, "WARC saved", warc_path)
    else:
        append_chain_entry(
            capture_folder,
            case_id,
            evidence_id,
            operator,
            "WARC limitation logged",
            "metadata/capture_log.txt",
            "",
            "WARC output could not be created; see metadata/capture_log.txt.",
        )

    if not har_saved:
        limitation = "HAR output was not created, usually because the browser context could not complete."
        known_limitations.append(limitation)
        logger.warning(limitation)
    if not warc_saved:
        logger.warning("WARC was not saved; limitation recorded")

    return result


# ====================================
# Reports, manifests, and signatures
# ====================================

# ----------- human-readable limitation log --------------

def write_capture_log_text(
    path: Path,
    capture_folder: Path,
    known_limitations: list[str],
    errors: list[str],
) -> None:
    lines = [
        f"{TOOL_NAME} capture notes",
        f"Capture folder: {capture_folder}",
        "",
        "Known limitations:",
    ]
    lines.extend(f"- {item}" for item in known_limitations)
    lines.append("")
    lines.append("Errors:")
    if errors:
        lines.extend(f"- {item}" for item in errors)
    else:
        lines.append("- None recorded.")
    lines.append("")
    write_text(path, "\n".join(lines))


# ----------- project-relative display paths for reports --------------

def display_capture_folder_path(capture_folder: Path) -> str:
    project_root = Path(__file__).resolve().parent
    resolved = capture_folder.resolve()
    try:
        relative = resolved.relative_to(project_root)
        return f"./{relative.as_posix()}"
    except ValueError:
        return str(resolved)


# ----------- Markdown evidence summary --------------

def write_report(path: Path, metadata: dict[str, Any], capture_folder: Path) -> None:
    files = metadata.get("files_created", [])
    verify_folder = display_capture_folder_path(capture_folder)
    lines = [
        "# Evidence Summary",
        "",
        f"- Case ID: {metadata.get('case_id', '')}",
        f"- Evidence ID: {metadata.get('evidence_id', '')}",
        f"- Original URL: {metadata.get('original_url', '')}",
        f"- Final URL: {metadata.get('final_url', '')}",
        f"- Page title: {metadata.get('page_title', '')}",
        f"- Capture start UTC: {metadata.get('capture_start_utc', '')}",
        f"- Capture end UTC: {metadata.get('capture_end_utc', '')}",
        f"- Operator: {metadata.get('operator', '')}",
        "",
        "## Files Captured",
        "",
    ]
    if files:
        lines.extend(f"- `{item}`" for item in files)
    else:
        lines.append("- No artifact files were captured.")

    lines.extend(
        [
            "",
            "## SHA-256 Manifest",
            "",
            "- `hashes/manifest.json`",
            "- `hashes/manifest.sha256`",
            "- `hashes/manifest.sig`",
            "- `hashes/manifest_public_key.pem`",
            "- `hashes/signature_metadata.json`",
            "",
            "## Supplementary Metadata",
            "",
            "- `metadata/capture_config.json`",
            "- `metadata/dns_resolution.json`",
            "- `metadata/tls_certificate_metadata.json`",
            "- `screenshots/thumbnail_index.html`",
            "- `screenshots/thumbnail_index.json`",
            "",
            "## Known Limitations",
            "",
            "Known limitations are recorded in `metadata/capture_metadata.json` and `metadata/capture_log.txt`.",
            "",
            "## Verification Instructions",
            "",
            "Run:",
            "",
            "```bash",
            f'python preserve.py verify --case-folder "{verify_folder}"',
            "```",
            "",
        ]
    )
    write_text(path, "\n".join(lines))


# ----------- SHA-256 manifest generation --------------

def generate_hash_manifests(capture_folder: Path) -> list[dict[str, Any]]:
    manifest_json_path = capture_folder / "hashes" / "manifest.json"
    manifest_sha_path = capture_folder / "hashes" / "manifest.sha256"
    excluded = {
        manifest_json_path.relative_to(capture_folder).as_posix(),
        manifest_sha_path.relative_to(capture_folder).as_posix(),
        "hashes/manifest.sig",
        "hashes/manifest_public_key.pem",
        "hashes/signature_metadata.json",
    }

    entries: list[dict[str, Any]] = []
    for path in sorted(item for item in capture_folder.rglob("*") if item.is_file()):
        rel = path.relative_to(capture_folder).as_posix()
        if rel in excluded:
            continue
        stat = path.stat()
        entries.append(
            {
                "relative_path": rel,
                "sha256": sha256_file(path),
                "size_bytes": stat.st_size,
                "modified_time_utc": file_mtime_utc(path),
            }
        )

    manifest_data = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "generated_utc": iso_utc(utc_now()),
        "hash_algorithm": "SHA-256",
        "signature_required": True,
        "note": "Manifest files are excluded from their own manifest so verification remains stable.",
        "files": entries,
    }
    write_json(manifest_json_path, manifest_data)

    sha_lines = [f"{entry['sha256']}  {entry['relative_path']}" for entry in entries]
    write_text(manifest_sha_path, "\n".join(sha_lines) + ("\n" if sha_lines else ""))
    return entries


# ----------- Ed25519 manifest signing --------------

def sign_hash_manifest(
    capture_folder: Path,
    signing_key_path: Path | None,
    known_limitations: list[str],
    errors: list[str],
) -> None:
    manifest_json_path = capture_folder / "hashes" / "manifest.json"
    signature_path = capture_folder / "hashes" / "manifest.sig"
    public_key_path = capture_folder / "hashes" / "manifest_public_key.pem"
    signature_metadata_path = capture_folder / "hashes" / "signature_metadata.json"

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:
        message = "cryptography is not installed; signed manifest was not created."
        known_limitations.append(message)
        errors.append(str(exc))
        return

    try:
        if signing_key_path is not None:
            private_key_data = signing_key_path.read_bytes()
            private_key = serialization.load_pem_private_key(private_key_data, password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("Signing key must be an Ed25519 private key in PEM format.")
            key_source = {
                "type": "operator_provided_ed25519_private_key",
                "file_name": signing_key_path.name,
                "file_sha256": sha256_file(signing_key_path),
            }
        else:
            private_key = Ed25519PrivateKey.generate()
            key_source = {
                "type": "capture_generated_ephemeral_ed25519_key",
                "note": "No private key was written to the evidence package. Preserve the public key and signature externally for stronger custody.",
            }

        public_key = private_key.public_key()
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Unexpected public key type for Ed25519 signing.")

        manifest_bytes = manifest_json_path.read_bytes()
        signature = private_key.sign(manifest_bytes)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        write_text(signature_path, base64.b64encode(signature).decode("ascii") + "\n")
        public_key_path.write_bytes(public_pem)
        signature_metadata = {
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "created_utc": iso_utc(utc_now()),
            "algorithm": "Ed25519",
            "signed_file": "hashes/manifest.json",
            "signature_file": "hashes/manifest.sig",
            "public_key_file": "hashes/manifest_public_key.pem",
            "manifest_sha256": sha256_file(manifest_json_path),
            "signature_sha256": sha256_file(signature_path),
            "public_key_sha256": sha256_file(public_key_path),
            "key_source": key_source,
            "important_note": "The signature protects hashes/manifest.json. For strongest evidentiary value, export the signature and public key to independent custody immediately after capture.",
        }
        write_json(signature_metadata_path, signature_metadata)

    except Exception as exc:  # noqa: BLE001
        message = f"Manifest signing failed: {exc}"
        known_limitations.append(message)
        errors.append(message)


# ----------- Ed25519 manifest verification --------------

def verify_manifest_signature(capture_folder: Path) -> tuple[bool, str]:
    manifest_json_path = capture_folder / "hashes" / "manifest.json"
    signature_path = capture_folder / "hashes" / "manifest.sig"
    public_key_path = capture_folder / "hashes" / "manifest_public_key.pem"

    if not signature_path.exists() or not public_key_path.exists():
        return False, "signature or public key file missing"

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            return False, "public key is not an Ed25519 key"
        signature = base64.b64decode(signature_path.read_text(encoding="utf-8").strip(), validate=True)
        public_key.verify(signature, manifest_json_path.read_bytes())
        return True, "manifest signature valid"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


# ====================================
# Main capture workflow
# ====================================

# ----------- capture command implementation --------------

def capture(args: argparse.Namespace) -> int:
    try:
        validate_http_url(args.url)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    signing_key_path = Path(args.signing_key).expanduser().resolve() if args.signing_key else None
    if signing_key_path is not None:
        try:
            validate_signing_key_file(signing_key_path)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    start = utc_now()
    output_root = Path(args.output).expanduser().resolve()
    capture_folder = make_capture_folder(output_root, args.case_id, start)
    files_created: set[str] = set()
    known_limitations = list(DEFAULT_LIMITATIONS)
    errors: list[str] = []
    evidence_id = str(uuid.uuid4())
    cookies_path = Path(args.cookies).expanduser().resolve() if args.cookies else None
    if signing_key_path is None:
        known_limitations.append(
            "Signed manifest uses a capture-generated ephemeral Ed25519 key because no --signing-key was provided; this detects package changes but is not an external identity trust anchor."
        )

    log_path = capture_folder / "logs" / "capture.log"
    logger = setup_logging(log_path)
    files_created.add(relative_path(capture_folder, log_path))

    append_chain_entry(
        capture_folder,
        args.case_id,
        evidence_id,
        args.operator,
        "capture started",
        "",
        "",
        args.notes or "",
    )
    files_created.add("chain_of_custody.csv")
    logger.info("Capture started")
    logger.info(f"Case ID: {args.case_id}")
    logger.info(f"Evidence ID: {evidence_id}")
    logger.info(f"Original URL: {args.url}")

    browser_result: dict[str, Any] = {
        "final_url": "",
        "page_title": "",
        "browser_name": "chromium",
        "browser_version": "",
        "user_agent": "",
        "viewport": DEFAULT_VIEWPORT,
        "cookies_requested": bool(args.cookies),
        "cookies_loaded_count": 0,
        "cookies_skipped_count": 0,
    }

    try:
        browser_result = run_browser_capture(
            capture_folder=capture_folder,
            url=args.url,
            cookies_path=cookies_path,
            files_created=files_created,
            case_id=args.case_id,
            evidence_id=evidence_id,
            operator=args.operator,
            known_limitations=known_limitations,
            errors=errors,
            logger=logger,
        )
    except Exception as exc:  # noqa: BLE001 - never leave without package details.
        message = f"Unexpected capture failure: {exc}"
        errors.append(message)
        logger.exception("Unexpected capture failure")

    write_network_artifacts(
        capture_folder=capture_folder,
        original_url=args.url,
        final_url=browser_result.get("final_url", ""),
        files_created=files_created,
        case_id=args.case_id,
        evidence_id=evidence_id,
        operator=args.operator,
        logger=logger,
        errors=errors,
    )
    create_screenshot_thumbnail_index(
        capture_folder=capture_folder,
        files_created=files_created,
        case_id=args.case_id,
        evidence_id=evidence_id,
        operator=args.operator,
        logger=logger,
        known_limitations=known_limitations,
        errors=errors,
    )
    try:
        write_capture_config(
            capture_folder=capture_folder,
            args=args,
            evidence_id=evidence_id,
            start=start,
            browser_result=browser_result,
            cookies_path=cookies_path,
            signing_key_path=signing_key_path,
            files_created=files_created,
            case_id=args.case_id,
            operator=args.operator,
            logger=logger,
        )
    except Exception as exc:  # noqa: BLE001
        message = f"Capture config generation failed: {exc}"
        errors.append(message)
        logger.exception("Capture config generation failed")

    end = utc_now()

    metadata_path = capture_folder / "metadata" / "capture_metadata.json"
    capture_log_text_path = capture_folder / "metadata" / "capture_log.txt"
    report_path = capture_folder / "reports" / "evidence_summary.md"

    files_created.update(
        {
            relative_path(capture_folder, metadata_path),
            relative_path(capture_folder, capture_log_text_path),
            relative_path(capture_folder, report_path),
            "hashes/manifest.json",
            "hashes/manifest.sha256",
            "hashes/manifest.sig",
            "hashes/manifest_public_key.pem",
            "hashes/signature_metadata.json",
        }
    )

    metadata = {
        "case_id": args.case_id,
        "evidence_id": evidence_id,
        "operator": args.operator,
        "original_url": args.url,
        "final_url": browser_result.get("final_url", ""),
        "page_title": browser_result.get("page_title", ""),
        "capture_start_utc": iso_utc(start),
        "capture_end_utc": iso_utc(end),
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "python_version": platform.python_version(),
        "os_platform": platform.platform(),
        "browser_name": browser_result.get("browser_name", "chromium"),
        "browser_version": browser_result.get("browser_version", ""),
        "user_agent": browser_result.get("user_agent", ""),
        "viewport": browser_result.get("viewport", DEFAULT_VIEWPORT),
        "cookies_requested": browser_result.get("cookies_requested", False),
        "cookies_loaded_count": browser_result.get("cookies_loaded_count", 0),
        "cookies_skipped_count": browser_result.get("cookies_skipped_count", 0),
        "notes": args.notes or "",
        "files_created": sorted(files_created),
        "known_limitations": sorted(set(known_limitations)),
        "errors": errors,
    }

    write_capture_log_text(capture_log_text_path, capture_folder, metadata["known_limitations"], errors)
    write_json(metadata_path, metadata)
    write_report(report_path, metadata, capture_folder)
    logger.info(f"Metadata saved to {metadata_path}")
    logger.info(f"Evidence summary saved to {report_path}")
    logger.info(f"Capture log notes saved to {capture_log_text_path}")

    append_chain_entry(
        capture_folder,
        args.case_id,
        evidence_id,
        args.operator,
        "hash manifest generated",
        "hashes/manifest.json; hashes/manifest.sha256",
        "",
        "Manifest files are excluded from their own manifest.",
    )
    append_chain_entry(
        capture_folder,
        args.case_id,
        evidence_id,
        args.operator,
        "capture completed",
        "",
        "",
        "Capture package finalized before manifest hashing.",
    )

    logger.info("Closing capture log before final hash manifest generation")
    close_logger(logger)
    generate_hash_manifests(capture_folder)
    sign_hash_manifest(capture_folder, signing_key_path, known_limitations, errors)

    print(f"Capture folder: {capture_folder}")
    if errors:
        print(f"Capture completed with {len(errors)} recorded error(s). See metadata/capture_metadata.json.")
        return 1
    print("Capture completed successfully.")
    return 0


# ====================================
# Verification workflow
# ====================================

# Stack Overflow discussion on Path.relative_to behavior:
#   https://stackoverflow.com/questions/38083555/using-pathlibs-relative-to-for-directories-on-the-same-level

# ----------- verify command implementation --------------

def verify(args: argparse.Namespace) -> int:
    capture_folder = Path(args.case_folder).expanduser().resolve()
    manifest_path = capture_folder / "hashes" / "manifest.json"
    if not manifest_path.exists():
        print(f"FAIL manifest missing: {manifest_path}", file=sys.stderr)
        return 1

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL could not read manifest: {exc}", file=sys.stderr)
        return 1

    entries = manifest.get("files", [])
    if not isinstance(entries, list):
        print("FAIL manifest format is invalid: 'files' must be a list", file=sys.stderr)
        return 1

    passed = 0
    failed = 0
    signature_files_present = (capture_folder / "hashes" / "manifest.sig").exists() or (
        capture_folder / "hashes" / "manifest_public_key.pem"
    ).exists()
    if manifest.get("signature_required", False) or signature_files_present:
        signature_ok, signature_message = verify_manifest_signature(capture_folder)
        if signature_ok:
            print("PASS hashes/manifest.json signature")
            passed += 1
        else:
            print(f"FAIL hashes/manifest.json signature {signature_message}")
            failed += 1
    else:
        print("WARN hashes/manifest.json signature not present in this legacy capture")

    for entry in entries:
        rel = entry.get("relative_path", "")
        expected_sha = entry.get("sha256", "")
        path = (capture_folder / rel).resolve()

        try:
            path.relative_to(capture_folder)
        except ValueError:
            print(f"FAIL {rel} path escapes capture folder")
            failed += 1
            continue

        if not path.exists():
            print(f"FAIL {rel} missing")
            failed += 1
            continue

        actual_sha = sha256_file(path)
        if actual_sha == expected_sha:
            print(f"PASS {rel}")
            passed += 1
        else:
            print(f"FAIL {rel} expected={expected_sha} actual={actual_sha}")
            failed += 1

    total = passed + failed
    print(f"Summary: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1


# ====================================
# Signing key generation and CLI wiring
# ====================================

# Python argparse:
#   https://docs.python.org/3/library/argparse.html
# Ed25519 signing in cryptography:
#   https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

# ----------- generate-key command implementation --------------

def generate_key(args: argparse.Namespace) -> int:
    private_key_path = Path(args.private_key).expanduser().resolve()
    public_key_path = Path(args.public_key).expanduser().resolve()
    if not args.force and (private_key_path.exists() or public_key_path.exists()):
        print("Error: key file already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        public_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        public_key_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        try:
            private_key_path.chmod(0o600)
        except OSError:
            pass
    except Exception as exc:  # noqa: BLE001
        print(f"Error: key generation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Private key: {private_key_path}")
    print(f"Public key: {public_key_path}")
    return 0


# ----------- argparse command tree --------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preserve.py",
        description="Preserve publicly accessible web pages in a forensic-style evidence package.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture", help="Capture a public web page.")
    capture_parser.add_argument("--url", required=True, help="Public http:// or https:// URL to capture.")
    capture_parser.add_argument("--case-id", required=True, help="Case identifier, for example CASE-001.")
    capture_parser.add_argument("--operator", required=True, help="Name of the operator performing the capture.")
    capture_parser.add_argument("--output", required=True, help="Output folder for case packages.")
    capture_parser.add_argument("--notes", default="", help="Optional case notes.")
    capture_parser.add_argument(
        "--cookies",
        help=(
            "Optional JSON cookie file for owned/test pages. All valid cookies from the file are loaded; "
            "cookie values are not logged or copied."
        ),
    )
    capture_parser.add_argument(
        "--signing-key",
        help=(
            "Optional Ed25519 private key PEM used to sign hashes/manifest.json. "
            "If omitted, a capture-generated ephemeral key signs the manifest and only the public key is saved."
        ),
    )
    capture_parser.set_defaults(func=capture)

    verify_parser = subparsers.add_parser("verify", help="Verify an existing capture package.")
    verify_parser.add_argument("--case-folder", required=True, help="Path to a specific capture folder.")
    verify_parser.set_defaults(func=verify)

    key_parser = subparsers.add_parser("generate-key", help="Generate an Ed25519 signing key pair.")
    key_parser.add_argument("--private-key", required=True, help="Output path for the private signing key PEM.")
    key_parser.add_argument("--public-key", required=True, help="Output path for the public verification key PEM.")
    key_parser.add_argument("--force", action="store_true", help="Overwrite key files if they already exist.")
    key_parser.set_defaults(func=generate_key)
    return parser


# ----------- process entrypoint --------------

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
