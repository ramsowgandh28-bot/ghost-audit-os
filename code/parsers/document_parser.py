"""Document parser for TXT and PDF evidence files.

Parses plain-text handover files and ReportLab-generated PDF documents using
pure Python standard-library ASCII85 and Flate (zlib) decompression.
"""

import base64
import os
import re
import zlib
from typing import List, Tuple, Optional

try:
    from ..evidence_record import EvidenceFact, ParsingStatus
except (ImportError, ValueError):
    from evidence_record import EvidenceFact, ParsingStatus


class DocumentEvidenceParser:
    """Parses plain text documents and extracts facts from PDF documents."""

    def parse_txt_file(
        self,
        file_id: str,
        file_path: str,
        absolute_path: str,
        captured_at: str
    ) -> Tuple[List[EvidenceFact], Optional[str]]:
        """Parse structured text handover files."""
        if not os.path.exists(absolute_path):
            return [], f"File not found: {absolute_path}"

        try:
            with open(absolute_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return [], f"Failed to read TXT file {file_id}: {e}"

        facts: List[EvidenceFact] = []

        handover_regex = re.compile(
            r"^-\s*([\d\-:TZ\.]+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.*)$"
        )

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            match = handover_regex.match(line)
            if match:
                ts, service, res_id, category, status, id_val = [g.strip() for g in match.groups()]

                user_id = None
                email = None
                phone = None
                if "@" in id_val:
                    email = id_val
                elif id_val.startswith("user_"):
                    user_id = id_val
                elif id_val.startswith("+"):
                    phone = id_val

                st_upper = status.upper()
                if st_upper == "NOT_FOUND":
                    obs_state = "ABSENT"
                elif st_upper in ("FOUND", "IDENTIFIABLE"):
                    obs_state = "PRESENT"
                elif st_upper == "REDACTED":
                    obs_state = "REDACTED"
                elif st_upper == "ANONYMIZED":
                    obs_state = "ANONYMIZED"
                elif st_upper == "ACTIVE":
                    obs_state = "ACTIVE"
                elif st_upper == "BLOCKED":
                    obs_state = "BLOCKED"
                elif st_upper == "DISABLED":
                    obs_state = "DISABLED"
                else:
                    obs_state = st_upper

                facts.append(EvidenceFact(
                    file_id=file_id,
                    source_path=file_path,
                    system_id=service,
                    resource_id=res_id,
                    data_category=category,
                    user_id=user_id,
                    email=email,
                    phone=phone,
                    observed_state=obs_state,
                    captured_at=captured_at,
                    event_timestamp=ts,
                    raw_excerpt=line,
                    extra_metadata={"status_label": status, "line_no": line_no}
                ))

        return facts, None

    def parse_pdf_file(
        self,
        file_id: str,
        file_path: str,
        absolute_path: str,
        captured_at: str
    ) -> Tuple[List[EvidenceFact], ParsingStatus, Optional[str]]:
        """Extract text chunks and structured facts from PDF documents.

        Uses standard-library ASCII85 and zlib decompression to extract ReportLab text.
        """
        if not os.path.exists(absolute_path):
            return [], ParsingStatus.ERROR, f"File not found: {absolute_path}"

        try:
            with open(absolute_path, "rb") as fp:
                raw = fp.read()
        except Exception as e:
            return [], ParsingStatus.ERROR, f"Failed to read PDF file: {e}"

        texts: List[str] = []
        pos = 0
        while True:
            s_idx = raw.find(b"stream", pos)
            if s_idx == -1:
                break
            start = s_idx + 6
            if raw[start:start+2] == b"\r\n":
                start += 2
            elif raw[start:start+1] in (b"\n", b"\r"):
                start += 1
            e_idx = raw.find(b"endstream", start)
            if e_idx == -1:
                break
            s_data = raw[start:e_idx].strip()
            pos = e_idx + 9

            decomp = None
            try:
                decomp = zlib.decompress(s_data)
            except Exception:
                try:
                    a85 = base64.a85decode(s_data, adobe=True)
                    decomp = zlib.decompress(a85)
                except Exception:
                    pass

            if decomp:
                tjs = re.findall(rb'\(((?:[^()\\]|\\.)*)\)\s*Tj', decomp)
                for t in tjs:
                    clean = t.replace(b'\\(', b'(').replace(b'\\)', b')').replace(b'\\\\', b'\\')
                    texts.append(clean.decode('latin1', 'ignore').strip())

        if not texts:
            return [], ParsingStatus.PARTIAL, "No text elements found in PDF streams"

        full_doc = " \n ".join(texts)
        facts: List[EvidenceFact] = []

        # 1. Look for Support References e.g. "support_001" or "CS-4827"
        supp_matches = re.findall(r"\b(support_\d+)\b", full_doc)
        for supp_res in set(supp_matches):
            email_match = re.search(r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b", full_doc)
            user_match = re.search(r"\b(user_\d+)\b", full_doc)
            facts.append(EvidenceFact(
                file_id=file_id,
                source_path=file_path,
                system_id="support_platform",
                resource_id=supp_res,
                data_category="SUPPORT_ATTACHMENT",
                user_id=user_match.group(1) if user_match else None,
                email=email_match.group(1) if email_match else None,
                observed_state="PRESENT",
                captured_at=captured_at,
                event_timestamp=captured_at,
                raw_excerpt=f"PDF support record: {supp_res} email={email_match.group(1) if email_match else None}",
            ))

        # 2. Look for Security Audit records e.g. "audit_record_003"
        audit_matches = re.findall(r"\b(audit_record_\d+)\b", full_doc)
        for aud_res in set(audit_matches):
            user_match = re.search(r"\b(user_\d+)\b", full_doc)
            facts.append(EvidenceFact(
                file_id=file_id,
                source_path=file_path,
                system_id="security_service",
                resource_id=aud_res,
                data_category="SECURITY_AUDIT_LOG",
                user_id=user_match.group(1) if user_match else None,
                observed_state="PRESENT",
                captured_at=captured_at,
                event_timestamp=captured_at,
                raw_excerpt=f"PDF security record: {aud_res} user={user_match.group(1) if user_match else None}",
            ))

        # 3. Look for Customer / Account statements e.g. "account_history" / "user_18"
        user_matches = re.findall(r"\b(user_\d+)\b", full_doc)
        email_matches = re.findall(r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b", full_doc)
        order_matches = re.findall(r"\b(ORD-\d+)\b", full_doc)

        for u in set(user_matches):
            # Check legal retention lines: e.g. "ORD-20264118 | user_08 | Card dispute | ... Retain until 04 May 2033"
            for line in texts:
                if u in line and "Retain until" in line:
                    facts.append(EvidenceFact(
                        file_id=file_id,
                        source_path=file_path,
                        system_id="legal_service",
                        resource_id=f"legal_{u}",
                        data_category="LEGAL_HOLD_RECORD",
                        user_id=u,
                        observed_state="PRESENT",
                        captured_at=captured_at,
                        event_timestamp=captured_at,
                        raw_excerpt=line[:120],
                    ))

            # General account history
            if "CUSTOMER STATEMENT" in full_doc:
                for em in set(email_matches):
                    facts.append(EvidenceFact(
                        file_id=file_id,
                        source_path=file_path,
                        system_id="account_service",
                        resource_id=f"statement_{u}",
                        data_category="USER_PROFILE",
                        user_id=u,
                        email=em,
                        observed_state="PRESENT",
                        captured_at=captured_at,
                        event_timestamp=captured_at,
                        raw_excerpt=f"Customer statement for {u} ({em})",
                    ))

        return facts, ParsingStatus.SUCCESS, None
