"""Evidence index and multi-format parser manager for Ghost Data Still Exists.

Indexes all participant-facing evidence under dataset/evidence/ and provides
time-aware, grounded retrieval respecting audit_at cutoffs.
"""

import os
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set, Any

try:
    from .models import EvidenceFile
    from .loaders import load_evidence_files
    from .evidence_record import (
        EvidenceFact,
        EvidenceFileMetadata,
        EvidenceFileType,
        ParsingStatus,
    )
    from .parsers.sql_parser import SqlEvidenceParser
    from .parsers.json_parser import JsonEvidenceParser
    from .parsers.log_parser import LogEvidenceParser
    from .parsers.document_parser import DocumentEvidenceParser
    from .parsers.image_parser import ImageEvidenceParser
    from .identity import ResolvedIdentity
except (ImportError, ValueError):
    from models import EvidenceFile
    from loaders import load_evidence_files
    from evidence_record import (
        EvidenceFact,
        EvidenceFileMetadata,
        EvidenceFileType,
        ParsingStatus,
    )
    from parsers.sql_parser import SqlEvidenceParser
    from parsers.json_parser import JsonEvidenceParser
    from parsers.log_parser import LogEvidenceParser
    from parsers.document_parser import DocumentEvidenceParser
    from parsers.image_parser import ImageEvidenceParser
    from identity import ResolvedIdentity


class EvidenceIndex:
    """Manages indexing, parsing, and time-aware retrieval of all evidence files."""

    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.manifest_path = os.path.join(dataset_dir, "evidence_files.csv")

        # Modular parsers
        self.sql_parser = SqlEvidenceParser()
        self.json_parser = JsonEvidenceParser()
        self.log_parser = LogEvidenceParser()
        self.doc_parser = DocumentEvidenceParser()
        self.image_parser = ImageEvidenceParser()

        # Indexes
        self.file_metadata: Dict[str, EvidenceFileMetadata] = {}
        self.all_facts: List[EvidenceFact] = []
        self._facts_by_file_id: Dict[str, List[EvidenceFact]] = defaultdict(list)
        self._facts_by_user_id: Dict[str, List[EvidenceFact]] = defaultdict(list)
        self._facts_by_email: Dict[str, List[EvidenceFact]] = defaultdict(list)
        self._facts_by_phone: Dict[str, List[EvidenceFact]] = defaultdict(list)
        self._facts_by_hash: Dict[str, List[EvidenceFact]] = defaultdict(list)
        self._facts_by_resource_id: Dict[str, List[EvidenceFact]] = defaultdict(list)

        # Build index
        self._load_and_parse_manifest()

    def _determine_file_type(self, file_path: str) -> EvidenceFileType:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".sql":
            return EvidenceFileType.SQL
        elif ext == ".json":
            return EvidenceFileType.JSON
        elif ext == ".log":
            return EvidenceFileType.LOG
        elif ext == ".txt":
            return EvidenceFileType.TXT
        elif ext == ".pdf":
            return EvidenceFileType.PDF
        elif ext in (".png", ".jpg", ".jpeg"):
            return EvidenceFileType.PNG
        return EvidenceFileType.UNKNOWN

    def _load_and_parse_manifest(self):
        """Load evidence_files.csv and parse all 94 evidence files."""
        evidence_entries = load_evidence_files(self.manifest_path)

        for entry in evidence_entries:
            fid = entry.file_id
            rel_path = entry.file_path
            # Normalize path separators
            norm_rel_path = rel_path.replace("/", os.sep).replace("\\", os.sep)
            abs_path = os.path.join(self.dataset_dir, norm_rel_path)

            file_type = self._determine_file_type(rel_path)
            exists = os.path.exists(abs_path)
            readable = os.access(abs_path, os.R_OK) if exists else False
            file_size = os.path.getsize(abs_path) if exists else 0

            meta = EvidenceFileMetadata(
                file_id=fid,
                file_path=rel_path,
                absolute_path=abs_path,
                origin=entry.origin,
                captured_at=entry.captured_at,
                file_type=file_type,
                file_size_bytes=file_size,
                exists=exists,
                is_readable=readable,
            )

            if not exists or not readable:
                meta.parsing_status = ParsingStatus.ERROR
                meta.error_message = "File does not exist or is not readable"
                self.file_metadata[fid] = meta
                continue

            # Parse according to format
            facts: List[EvidenceFact] = []
            err_msg: Optional[str] = None
            status = ParsingStatus.SUCCESS

            if file_type == EvidenceFileType.SQL:
                facts, err_msg = self.sql_parser.parse_file(fid, rel_path, abs_path, entry.captured_at)
                if err_msg:
                    status = ParsingStatus.PARTIAL if facts else ParsingStatus.ERROR

            elif file_type == EvidenceFileType.JSON:
                facts, err_msg = self.json_parser.parse_file(fid, rel_path, abs_path, entry.captured_at)
                if err_msg:
                    status = ParsingStatus.PARTIAL if facts else ParsingStatus.ERROR

            elif file_type == EvidenceFileType.LOG:
                facts, err_msg = self.log_parser.parse_file(fid, rel_path, abs_path, entry.captured_at)
                if err_msg:
                    status = ParsingStatus.PARTIAL if facts else ParsingStatus.ERROR

            elif file_type == EvidenceFileType.TXT:
                facts, err_msg = self.doc_parser.parse_txt_file(fid, rel_path, abs_path, entry.captured_at)
                if err_msg:
                    status = ParsingStatus.PARTIAL if facts else ParsingStatus.ERROR

            elif file_type == EvidenceFileType.PDF:
                facts, status, err_msg = self.doc_parser.parse_pdf_file(fid, rel_path, abs_path, entry.captured_at)

            elif file_type == EvidenceFileType.PNG:
                facts, status, err_msg, _ = self.image_parser.parse_image_file(fid, rel_path, abs_path, entry.captured_at)

            meta.record_count = len(facts)
            meta.parsing_status = status
            meta.error_message = err_msg
            self.file_metadata[fid] = meta

            # Register facts
            for fact in facts:
                self.all_facts.append(fact)
                self._facts_by_file_id[fid].append(fact)
                if fact.user_id:
                    self._facts_by_user_id[fact.user_id.strip()].append(fact)
                if fact.email:
                    self._facts_by_email[fact.email.strip().lower()].append(fact)
                if fact.phone:
                    self._facts_by_phone[fact.phone.strip()].append(fact)
                if fact.email_hash:
                    self._facts_by_hash[fact.email_hash.strip().lower()].append(fact)
                if fact.resource_id:
                    self._facts_by_resource_id[fact.resource_id.strip()].append(fact)

    def get_diagnostic_report(self) -> Dict[str, Any]:
        """Produce a diagnostic breakdown of parsing results across all 94 files."""
        total_files = len(self.file_metadata)
        counts_by_type = defaultdict(int)
        counts_by_status = defaultdict(int)
        total_facts = len(self.all_facts)

        for meta in self.file_metadata.values():
            counts_by_type[meta.file_type.value] += 1
            counts_by_status[meta.parsing_status.value] += 1

        return {
            "total_files": total_files,
            "counts_by_type": dict(counts_by_type),
            "counts_by_status": dict(counts_by_status),
            "total_extracted_facts": total_facts,
            "indexed_users_with_facts": len(self._facts_by_user_id),
            "indexed_emails_with_facts": len(self._facts_by_email),
            "indexed_resource_ids": len(self._facts_by_resource_id),
        }

    def query_facts_for_identity(
        self,
        resolved_identity: ResolvedIdentity,
        audit_at: str
    ) -> List[EvidenceFact]:
        """Retrieve all evidence facts linked to a resolved identity as of audit_at cutoff.

        Enforces strict temporal constraints:
        - Excludes any evidence file where captured_at > audit_at.
        - Excludes any individual fact where event_timestamp > audit_at.
        - Only matches grounded identifiers valid up to audit_at.
        """
        if not resolved_identity.is_matched or resolved_identity.is_ambiguous:
            return []

        matched_facts: List[EvidenceFact] = []
        seen_fact_signatures = set()

        # Candidate pools
        candidate_facts: List[EvidenceFact] = []

        # 1. By user_id
        if resolved_identity.user_id:
            candidate_facts.extend(self._facts_by_user_id.get(resolved_identity.user_id, []))

        # 2. By all emails active or historical up to audit_at
        for email in resolved_identity.all_emails_at_cutoff:
            candidate_facts.extend(self._facts_by_email.get(email.strip().lower(), []))

        # 3. By phone numbers up to audit_at
        for phone in resolved_identity.all_phones_at_cutoff:
            candidate_facts.extend(self._facts_by_phone.get(phone.strip(), []))

        # 4. By email hashes up to audit_at
        for h in resolved_identity.all_email_hashes_at_cutoff:
            candidate_facts.extend(self._facts_by_hash.get(h.strip().lower(), []))

        for fact in candidate_facts:
            # Check 1: File capture cutoff
            if fact.captured_at and fact.captured_at > audit_at:
                continue

            # Check 2: Event timestamp cutoff
            if fact.event_timestamp and fact.event_timestamp > audit_at:
                continue

            # Check 3: Exact grounded link confirmation
            if not fact.matches_identity(
                resolved_identity.user_id,
                resolved_identity.all_emails_at_cutoff,
                resolved_identity.all_phones_at_cutoff,
                resolved_identity.all_email_hashes_at_cutoff
            ):
                continue

            # Avoid duplicates across index lookups
            sig = (fact.file_id, fact.system_id, fact.resource_id, fact.observed_state, fact.event_timestamp)
            if sig in seen_fact_signatures:
                continue
            seen_fact_signatures.add(sig)

            matched_facts.append(fact)

        # 5. Expand by confirmed resource IDs (correlating status checks/readbacks for known user resources)
        known_res_ids = {f.resource_id for f in matched_facts if f.resource_id and not f.resource_id.startswith("log_entry_")}
        for res_id in known_res_ids:
            for res_fact in self._facts_by_resource_id.get(res_id, []):
                if res_fact.captured_at and res_fact.captured_at > audit_at:
                    continue
                if res_fact.event_timestamp and res_fact.event_timestamp > audit_at:
                    continue
                # Do not re-add if already present or contradicts confirmed identity of a different user
                if res_fact.user_id and res_fact.user_id != resolved_identity.user_id:
                    continue
                if res_fact.email and res_fact.email.strip().lower() not in resolved_identity.all_emails_at_cutoff:
                    continue

                sig = (res_fact.file_id, res_fact.system_id, res_fact.resource_id, res_fact.observed_state, res_fact.event_timestamp)
                if sig in seen_fact_signatures:
                    continue
                seen_fact_signatures.add(sig)
                matched_facts.append(res_fact)

        return matched_facts
