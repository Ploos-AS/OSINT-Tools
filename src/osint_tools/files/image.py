from __future__ import annotations

from PIL import ExifTags, Image, UnidentifiedImageError

from .budget import AnalysisLimits

EXIF_FIELDS = {271: "make", 272: "model", 274: "orientation", 305: "software", 306: "datetime", 36867: "datetime_original"}


def analyze_image(path, limits: AnalysisLimits) -> dict | None:
    try:
        with Image.open(path) as image:
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > limits.max_image_pixels:
                return {"status": "limited", "reason": "max_image_pixels", "width": width, "height": height}
            result = {"status": "success", "format": image.format, "width": width, "height": height, "mode": image.mode, "frames": min(int(getattr(image, "n_frames", 1)), 10000)}
            try:
                exif = image.getexif()
                selected = {}
                for tag, name in EXIF_FIELDS.items():
                    value = exif.get(tag)
                    if value is not None:
                        selected[name] = str(value)[:1024]
                gps = exif.get_ifd(ExifTags.IFD.GPSInfo) if exif and hasattr(ExifTags, "IFD") else {}
                if gps:
                    selected["gps"] = {str(ExifTags.GPSTAGS.get(key, key)): str(value)[:512] for key, value in list(gps.items())[:16]}
                result["exif_present"] = bool(exif)
                result["exif"] = selected
            except Exception:
                result["exif_present"] = True
                result["exif"] = {}
                result["exif_status"] = "malformed"
            return result
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return {"status": "failed", "reason": "malformed_image"}
