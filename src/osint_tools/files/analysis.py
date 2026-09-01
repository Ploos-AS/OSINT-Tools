from __future__ import annotations

from pathlib import PurePosixPath

SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png", "image/png", (".png",)),
    (b"%PDF-", "pdf", "application/pdf", (".pdf",)),
    (b"GIF87a", "gif", "image/gif", (".gif",)),
    (b"GIF89a", "gif", "image/gif", (".gif",)),
    (b"\xff\xd8\xff", "jpeg", "image/jpeg", (".jpg", ".jpeg")),
    (b"PK\x03\x04", "zip", "application/zip", (".zip",)),
    (b"\x1f\x8b", "gzip", "application/gzip", (".gz", ".gzip")),
    (b"\x7fELF", "elf", "application/x-elf", (".elf",)),
    (b"MZ", "pe", "application/vnd.microsoft.portable-executable", (".exe", ".dll")),
)

KNOWN_EXTENSIONS = {extension for _, _, _, extensions in SIGNATURES for extension in extensions}


def safe_filename(value: str) -> str:
    value = "".join("\ufffd" if ord(char) < 32 or ord(char) == 127 else char for char in value)
    return (value or "unnamed")[:512]


def extension_for(filename: str) -> str:
    logical = filename.replace("\\", "/")
    return PurePosixPath(logical).suffix.lower()[:32]


def identify(sample: bytes, filename: str) -> dict:
    extension = extension_for(filename)
    detected_type = "binary"
    mime_type = "application/octet-stream"
    expected_extensions: tuple[str, ...] = ()
    for signature, kind, mime, extensions in SIGNATURES:
        if sample.startswith(signature):
            detected_type, mime_type, expected_extensions = kind, mime, extensions
            break
    else:
        if not sample:
            detected_type, mime_type = "empty", "application/x-empty"
        else:
            try:
                sample.decode("utf-8")
                if not any(byte < 9 or 13 < byte < 32 for byte in sample):
                    detected_type, mime_type = "text", "text/plain"
                    expected_extensions = (".txt", ".log", ".csv", ".md")
            except UnicodeDecodeError:
                pass
    mismatch = None
    if extension and (expected_extensions or extension in KNOWN_EXTENSIONS):
        mismatch = extension not in expected_extensions
    return {"extension": extension, "detected_type": detected_type, "mime_type": mime_type, "extension_mismatch": mismatch}
