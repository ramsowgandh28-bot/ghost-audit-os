"""Evidence record models for Ghost Data Still Exists.

Defines structured models for extracted evidence facts, file metadata, and parsing diagnostics.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List


class EvidenceFileType(str, Enum):
    SQL = "sql"
    JSON = "json"
    LOG = "log"
    TXT = "txt"
    PDF = "pdf"
    PNG = "png"
    UNKNOWN = "unknown"


class ParsingStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    UNSUPPORTED_NO_PDF_LIBRARY = "UNSUPPORTED_NO_PDF_LIBRARY"
    UNSUPPORTED_NO_OCR_TOOL = "UNSUPPORTED_NO_OCR_TOOL"
    ERROR = "ERROR"


@dataclass
class EvidenceFileMetadata:
    """Metadata and parsing status for a single evidence file from evidence_files.csv."""
    file_id: str
    file_path: str
    absolute_path: str
    origin: str
    captured_at: str
    file_type: EvidenceFileType
    file_size_bytes: int = 0
    exists: bool = True
    is_readable: bool = True
    record_count: int = 0
    parsing_status: ParsingStatus = ParsingStatus.SUCCESS
    error_message: Optional[str] = None


@dataclass
class EvidenceFact:
    """A single factual observation extracted from an evidence artifact."""
    file_id: str
    source_path: str
    system_id: str
    resource_id: str
    data_category: Optional[str] = None
    user_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    email_hash: Optional[str] = None
    observed_state: str = "PRESENT"  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, BLOCKED, DISABLED
    operation_hint: Optional[str] = None
    captured_at: str = ""
    event_timestamp: Optional[str] = None
    raw_excerpt: str = ""
    is_claim: bool = False  # True for activity/workflow log claims, False for direct database/state facts
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def matches_identity(
        self,
        user_id: Optional[str],
        emails: set,
        phones: set,
        email_hashes: set
    ) -> bool:
        """Check if this fact links to a user based on exact, grounded identifiers."""
        if user_id and self.user_id and self.user_id == user_id:
            return True
        if self.email and self.email.strip().lower() in emails:
            return True
        if self.phone and self.phone.strip() in phones:
            return True
        if self.email_hash and self.email_hash.strip().lower() in email_hashes:
            return True
        return False
