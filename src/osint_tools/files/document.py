from __future__ import annotations

import xml.etree.ElementTree as ET
import zipfile

FORMATS = {"word/document.xml": "docx", "xl/workbook.xml": "xlsx", "ppt/presentation.xml": "pptx"}
ODF = {"application/vnd.oasis.opendocument.text": "odt", "application/vnd.oasis.opendocument.spreadsheet": "ods", "application/vnd.oasis.opendocument.presentation": "odp"}


def _xml_metadata(raw: bytes) -> dict:
    root = ET.fromstring(raw)
    values = {}
    allowed = {"title", "creator", "created", "modified", "lastModifiedBy", "application", "company"}
    for element in root.iter():
        name = element.tag.rsplit("}", 1)[-1]
        if name in allowed and element.text:
            values[name] = element.text[:2048]
    return values


def analyze_document(path, max_bytes: int) -> dict | None:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            kind = next((value for required, value in FORMATS.items() if required in names), None)
            if "mimetype" in names:
                with archive.open("mimetype") as member:
                    mime = member.read(256).decode("ascii", "replace")
                kind = ODF.get(mime, kind)
            if not kind: return None
            metadata = {}
            malformed = False
            for name in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
                if name not in names: continue
                info = archive.getinfo(name)
                if info.file_size > max_bytes: continue
                try:
                    with archive.open(info) as member: raw = member.read(max_bytes + 1)
                    if len(raw) > max_bytes: continue
                    metadata.update(_xml_metadata(raw))
                except (ET.ParseError, RuntimeError, ValueError): malformed = True
            active = any(name.lower().endswith("vbaproject.bin") for name in names)
            embedded = any("/embeddings/" in ("/" + name.lower()) for name in names)
            return {"status": "success", "format": kind, "metadata": metadata, "vba_present": active, "embedded_objects_present": embedded, "malformed_metadata": malformed}
    except (zipfile.BadZipFile, OSError):
        return None
