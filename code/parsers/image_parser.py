"""Image parser for screenshot evidence files."""

import importlib
import os
import shutil
from typing import List, Tuple, Optional, Dict, Any

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from ..evidence_record import EvidenceFact, ParsingStatus
except (ImportError, ValueError):
    from evidence_record import EvidenceFact, ParsingStatus


class ImageEvidenceParser:
    """Inspects screenshot artifacts and checks for OCR availability."""

    def __init__(self):
        self.has_ocr = self._check_ocr_tool()

    def _check_ocr_tool(self) -> bool:
        # Check pytesseract and tesseract executable in PATH
        try:
            importlib.import_module("pytesseract")
            if shutil.which("tesseract"):
                return True
        except ImportError:
            pass
        return False

    def parse_image_file(
        self,
        file_id: str,
        file_path: str,
        absolute_path: str,
        captured_at: str
    ) -> Tuple[List[EvidenceFact], ParsingStatus, Optional[str], Dict[str, Any]]:
        """Inspect PNG image file.

        If no OCR engine is available, returns metadata and UNSUPPORTED_NO_OCR_TOOL status
        without fabricating textual contents.
        """
        if not os.path.exists(absolute_path):
            return [], ParsingStatus.ERROR, f"File not found: {absolute_path}", {}

        metadata: Dict[str, Any] = {}
        if HAS_PIL:
            try:
                with Image.open(absolute_path) as img:
                    metadata = {
                        "format": img.format,
                        "size": img.size,
                        "mode": img.mode,
                    }
            except Exception as e:
                return [], ParsingStatus.ERROR, f"Failed to open image: {e}", {}

        if not self.has_ocr:
            msg = (
                f"No local OCR tool (pytesseract + tesseract binary) installed. "
                f"Image {file_id} ({os.path.basename(file_path)}) preserved with visual metadata {metadata}."
            )
            return [], ParsingStatus.UNSUPPORTED_NO_OCR_TOOL, msg, metadata

        return [], ParsingStatus.UNSUPPORTED_NO_OCR_TOOL, "OCR not configured.", metadata
