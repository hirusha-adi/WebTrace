#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bleach
import markdown
from flask import Flask, abort, jsonify, render_template, request, send_file, url_for
from markupsafe import Markup

from preserve import sha256_file, verify_manifest_signature


# ====================================
# Viewer constants and preview policy
# ====================================

# ----------- file type groups --------------

TEXT_EXTENSIONS = {
    ".csv",
    ".css",
    ".har",
    ".html",
    ".htm",
    ".json",
    ".log",
    ".md",
    ".mhtml",
    ".pem",
    ".sha256",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
IMAGE_EXTENSIONS = {".gif", ".jpeg", ".jpg", ".png", ".webp"}
PREVIEW_TEXT_LIMIT_BYTES = 2 * 1024 * 1024

# ----------- Markdown sanitizing policy --------------

MARKDOWN_ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS).union(
    {
        "blockquote",
        "br",
        "code",
        "dd",
        "div",
        "dl",
        "dt",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "img",
        "p",
        "pre",
        "span",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "tr",
    }
)
MARKDOWN_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "abbr": ["title"],
    "img": ["alt", "src", "title"],
    "th": ["align"],
    "td": ["align"],
}


# ====================================
# Small formatting and rendering helpers
# ====================================

# Python-Markdown:
#   https://python-markdown.github.io/
# Bleach clean:
#   https://bleach.readthedocs.io/en/latest/clean.html

# ----------- UTC and file-size display --------------

def utc_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ----------- safe JSON loading --------------

def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


# ----------- Markdown report rendering --------------

def render_markdown_report(markdown_text: str) -> Markup:
    if not markdown_text.strip():
        return Markup('<p class="text-sm text-zinc-500">No evidence summary was generated.</p>')

    html_text = markdown.markdown(
        markdown_text,
        extensions=["fenced_code", "sane_lists", "tables"],
        output_format="html5",
    )
    cleaned = bleach.clean(
        html_text,
        tags=MARKDOWN_ALLOWED_TAGS,
        attributes=MARKDOWN_ALLOWED_ATTRIBUTES,
        protocols=["http", "https", "mailto"],
        strip=True,
    )
    return Markup(cleaned)


# ====================================
# Path safety and file summaries
# ====================================

# Stack Overflow note on static file serving and traversal risk:
#   https://stackoverflow.com/questions/20646822/how-to-serve-static-files-in-flask

# ----------- path containment guard --------------

def ensure_inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        abort(404)
    return resolved


# ----------- file table rows --------------

def file_summary(capture_path: Path, path: Path) -> dict[str, Any]:
    stat = path.stat()
    relative = path.relative_to(capture_path).as_posix()
    return {
        "relative_path": relative,
        "name": path.name,
        "folder": path.parent.relative_to(capture_path).as_posix() if path.parent != capture_path else ".",
        "extension": path.suffix.lower(),
        "size_bytes": stat.st_size,
        "size_display": format_size(stat.st_size),
        "modified_time_utc": utc_from_timestamp(stat.st_mtime),
        "is_image": path.suffix.lower() in IMAGE_EXTENSIONS,
        "is_text": path.suffix.lower() in TEXT_EXTENSIONS,
    }


# ----------- capture-folder file discovery --------------

def list_capture_files(capture_path: Path) -> list[dict[str, Any]]:
    return [file_summary(capture_path, path) for path in sorted(capture_path.rglob("*")) if path.is_file()]


# ====================================
# Capture metadata and integrity checks
# ====================================

# ----------- metadata loader --------------

def capture_metadata(capture_path: Path) -> dict[str, Any]:
    return load_json(capture_path / "metadata" / "capture_metadata.json")


# ----------- web-view integrity summary --------------

def verify_capture(capture_path: Path) -> dict[str, Any]:
    manifest_path = capture_path / "hashes" / "manifest.json"
    if not manifest_path.exists():
        return {"status": "missing", "passed": 0, "failed": 1, "total": 0, "message": "manifest.json missing"}

    manifest = load_json(manifest_path)
    entries = manifest.get("files", [])
    if not isinstance(entries, list):
        return {"status": "invalid", "passed": 0, "failed": 1, "total": 0, "message": "manifest file list invalid"}

    passed = 0
    failed = 0
    missing = 0
    changed: list[str] = []
    for entry in entries:
        rel = entry.get("relative_path", "")
        expected = entry.get("sha256", "")
        path = ensure_inside(capture_path, capture_path / rel)
        if not path.exists():
            missing += 1
            failed += 1
            changed.append(rel)
            continue
        if sha256_file(path) == expected:
            passed += 1
        else:
            failed += 1
            changed.append(rel)

    signature_required = bool(manifest.get("signature_required", False))
    signature_files_present = (capture_path / "hashes" / "manifest.sig").exists() or (
        capture_path / "hashes" / "manifest_public_key.pem"
    ).exists()
    signature_status = "legacy-unsigned"
    signature_message = "Signature not present in legacy capture."
    if signature_required or signature_files_present:
        signature_ok, signature_message = verify_manifest_signature(capture_path)
        signature_status = "pass" if signature_ok else "fail"
        if signature_ok:
            passed += 1
        else:
            failed += 1
            changed.append("hashes/manifest.json signature")

    status = "pass" if failed == 0 else "fail"
    return {
        "status": status,
        "passed": passed,
        "failed": failed,
        "missing": missing,
        "total": passed + failed,
        "changed": changed[:25],
        "signature_status": signature_status,
        "signature_message": signature_message,
    }


# ====================================
# Case, capture, and artifact summaries
# ====================================

# ----------- case list rows --------------

def case_summary(cases_root: Path, case_path: Path) -> dict[str, Any]:
    captures = [path for path in sorted(case_path.iterdir()) if path.is_dir()]
    latest = captures[-1] if captures else None
    metadata = capture_metadata(latest) if latest else {}
    return {
        "case_id": case_path.name,
        "capture_count": len(captures),
        "latest_capture": latest.name if latest else "",
        "latest_title": metadata.get("page_title", ""),
        "latest_url": metadata.get("final_url") or metadata.get("original_url", ""),
        "path": case_path.relative_to(cases_root).as_posix(),
    }


# ----------- capture list rows --------------

def capture_summary(capture_path: Path) -> dict[str, Any]:
    metadata = capture_metadata(capture_path)
    manifest = load_json(capture_path / "hashes" / "manifest.json")
    return {
        "capture_id": capture_path.name,
        "case_id": metadata.get("case_id", capture_path.parent.name),
        "evidence_id": metadata.get("evidence_id", ""),
        "title": metadata.get("page_title", ""),
        "original_url": metadata.get("original_url", ""),
        "final_url": metadata.get("final_url", ""),
        "operator": metadata.get("operator", ""),
        "start": metadata.get("capture_start_utc", ""),
        "end": metadata.get("capture_end_utc", ""),
        "file_count": len(manifest.get("files", [])) if isinstance(manifest.get("files"), list) else 0,
        "verification": verify_capture(capture_path),
    }


# ----------- high-value artifact groups for the detail page --------------

def important_artifacts(capture_path: Path) -> dict[str, list[dict[str, Any]]]:
    groups = {
        "Visual": [
            "screenshots/full_page.png",
            "screenshots/thumbnails/full_page_thumbnail.png",
            "screenshots/thumbnail_index.html",
            "pdf/page.pdf",
        ],
        "Page Source": ["html/page.html", "mhtml/snapshot.mhtml", "har/capture.har", "warc/capture.warc.gz"],
        "Metadata": [
            "metadata/capture_metadata.json",
            "metadata/capture_config.json",
            "metadata/dns_resolution.json",
            "metadata/tls_certificate_metadata.json",
            "metadata/capture_log.txt",
            "reports/evidence_summary.md",
        ],
        "Integrity": [
            "hashes/manifest.json",
            "hashes/manifest.sha256",
            "hashes/manifest.sig",
            "hashes/manifest_public_key.pem",
            "hashes/signature_metadata.json",
            "chain_of_custody.csv",
        ],
    }

    output: dict[str, list[dict[str, Any]]] = {}
    for group, relatives in groups.items():
        output[group] = []
        for rel in relatives:
            path = capture_path / rel
            if path.exists():
                output[group].append(file_summary(capture_path, path))
    return output


# ====================================
# Flask application and routes
# ====================================

# Stack Overflow note on send_file versus send_from_directory:
#   https://stackoverflow.com/questions/38252955/what-is-the-difference-between-flasks-send-file-and-send-from-directory

# ----------- app factory --------------

def create_app(cases_root: str | Path = "cases") -> Flask:
    app = Flask(__name__)
    root = Path(cases_root).expanduser().resolve()
    app.config["CASES_ROOT"] = root

    # ----------- safe path builders --------------

    def case_path(case_id: str) -> Path:
        return ensure_inside(root, root / case_id)

    def capture_path(case_id: str, capture_id: str) -> Path:
        path = ensure_inside(root, root / case_id / capture_id)
        if not path.is_dir():
            abort(404)
        return path

    def artifact_path(case_id: str, capture_id: str, relative_path: str) -> Path:
        capture = capture_path(case_id, capture_id)
        path = ensure_inside(capture, capture / relative_path)
        if not path.is_file():
            abort(404)
        return path

    # ----------- template globals --------------

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {"cases_root": root}

    # ----------- HTML page routes --------------

    @app.route("/")
    def index() -> str:
        root.mkdir(parents=True, exist_ok=True)
        cases = [case_summary(root, path) for path in sorted(root.iterdir()) if path.is_dir()]
        return render_template("index.html", cases=cases)

    @app.route("/case/<case_id>")
    def case_detail(case_id: str) -> str:
        path = case_path(case_id)
        if not path.is_dir():
            abort(404)
        captures = [capture_summary(item) for item in sorted(path.iterdir(), reverse=True) if item.is_dir()]
        return render_template("case.html", case_id=case_id, captures=captures)

    @app.route("/case/<case_id>/<capture_id>")
    def capture_detail(case_id: str, capture_id: str) -> str:
        capture = capture_path(case_id, capture_id)
        metadata = capture_metadata(capture)
        summary = capture_summary(capture)
        files = list_capture_files(capture)
        artifacts = important_artifacts(capture)
        reports = {
            "summary": (capture / "reports" / "evidence_summary.md").read_text(encoding="utf-8")
            if (capture / "reports" / "evidence_summary.md").exists()
            else "",
            "log": (capture / "logs" / "capture.log").read_text(encoding="utf-8", errors="replace")
            if (capture / "logs" / "capture.log").exists()
            else "",
        }
        reports["summary_html"] = render_markdown_report(reports["summary"])
        return render_template(
            "capture.html",
            case_id=case_id,
            capture_id=capture_id,
            capture=summary,
            metadata=metadata,
            verification=summary["verification"],
            files=files,
            artifacts=artifacts,
            reports=reports,
        )

    # ----------- artifact serving routes --------------

    @app.route("/artifact/<case_id>/<capture_id>/<path:relative_path>")
    def artifact(case_id: str, capture_id: str, relative_path: str):
        path = artifact_path(case_id, capture_id, relative_path)
        return send_file(path, mimetype=mimetypes.guess_type(path.name)[0], as_attachment=False)

    @app.route("/download/<case_id>/<capture_id>/<path:relative_path>")
    def download(case_id: str, capture_id: str, relative_path: str):
        path = artifact_path(case_id, capture_id, relative_path)
        return send_file(path, as_attachment=True, download_name=path.name)

    # ----------- JSON API routes for previews and integrity --------------

    @app.route("/api/file/<case_id>/<capture_id>/<path:relative_path>")
    def file_preview(case_id: str, capture_id: str, relative_path: str):
        capture = capture_path(case_id, capture_id)
        path = artifact_path(case_id, capture_id, relative_path)
        summary = file_summary(capture, path)
        ext = path.suffix.lower()
        artifact_url = url_for("artifact", case_id=case_id, capture_id=capture_id, relative_path=relative_path)
        download_url = url_for("download", case_id=case_id, capture_id=capture_id, relative_path=relative_path)

        if ext in IMAGE_EXTENSIONS:
            return jsonify({"mode": "image", "file": summary, "url": artifact_url, "download_url": download_url})
        if ext == ".pdf":
            return jsonify({"mode": "pdf", "file": summary, "url": artifact_url, "download_url": download_url})
        if ext in TEXT_EXTENSIONS and path.stat().st_size <= PREVIEW_TEXT_LIMIT_BYTES:
            return jsonify(
                {
                    "mode": "text",
                    "file": summary,
                    "content": path.read_text(encoding="utf-8", errors="replace"),
                    "download_url": download_url,
                }
            )
        return jsonify(
            {
                "mode": "binary",
                "file": summary,
                "message": "Preview is not available for this file type or size.",
                "download_url": download_url,
            }
        )

    @app.route("/api/verify/<case_id>/<capture_id>")
    def verify_api(case_id: str, capture_id: str):
        return jsonify(verify_capture(capture_path(case_id, capture_id)))

    return app


# ====================================
# CLI entrypoint
# ====================================

# ----------- web.py command-line parser --------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Browse WebTrace case folders.")
    parser.add_argument("--cases", default="./cases", help="Path to the cases directory.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind.")
    parser.add_argument("--port", default=5000, type=int, help="Port to bind.")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode.")
    return parser


# ----------- process entrypoint --------------

def main() -> int:
    args = build_parser().parse_args()
    app = create_app(args.cases)
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
