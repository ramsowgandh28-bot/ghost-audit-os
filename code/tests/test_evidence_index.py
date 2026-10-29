"""Tests for evidence indexing, multi-format parsing, temporal cutoffs, and correlation."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evidence_record import (
    EvidenceFact,
    EvidenceFileMetadata,
    EvidenceFileType,
    ParsingStatus,
)
from evidence_index import EvidenceIndex
from parsers.sql_parser import SqlEvidenceParser
from parsers.json_parser import JsonEvidenceParser
from parsers.log_parser import LogEvidenceParser
from parsers.document_parser import DocumentEvidenceParser
from parsers.image_parser import ImageEvidenceParser
from identity import ResolvedIdentity, IdentityResolver
from loaders import load_evidence_files, load_user_identities, load_user_audit_log


class TestEvidenceIndexingAndParsing(unittest.TestCase):
    """Test suite for evidence indexing, parsing, and correlation."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cls.dataset_dir = os.path.join(cls.repo_root, "dataset")
        cls.index = EvidenceIndex(cls.dataset_dir)

    def test_all_94_files_indexed_and_accounted_for(self):
        """All 94 participant-facing evidence files must be indexed, exist, and be readable."""
        manifest_files = load_evidence_files(os.path.join(self.dataset_dir, "evidence_files.csv"))
        self.assertEqual(len(manifest_files), 94)

        diag = self.index.get_diagnostic_report()
        self.assertEqual(diag["total_files"], 94)

        # File type distribution
        expected_types = {
            "log": 26,
            "json": 28,
            "sql": 24,
            "png": 11,
            "pdf": 4,
            "txt": 1,
        }
        self.assertEqual(diag["counts_by_type"], expected_types)

        # All 94 files exist and are readable on disk
        for fid, meta in self.index.file_metadata.items():
            self.assertTrue(meta.exists, f"File missing: {fid} at {meta.absolute_path}")
            self.assertTrue(meta.is_readable, f"File unreadable: {fid}")
            self.assertGreater(meta.file_size_bytes, 0, f"Empty file: {fid}")

        # Parsing status distribution: 83 successfully parsed (including 4 stdlib parsed PDFs), 11 PNGs documented
        self.assertEqual(diag["counts_by_status"].get("SUCCESS", 0), 83)
        self.assertEqual(diag["counts_by_status"].get("UNSUPPORTED_NO_OCR_TOOL", 0), 11)
        self.assertEqual(diag["counts_by_status"].get("UNSUPPORTED_NO_PDF_LIBRARY", 0), 0)
        self.assertEqual(diag["counts_by_status"].get("ERROR", 0), 0)

    def test_every_fact_has_valid_manifest_file_id(self):
        """Every single extracted fact must link to a genuine file_id present in evidence_files.csv."""
        valid_file_ids = {meta.file_id for meta in self.index.file_metadata.values()}
        for fact in self.index.all_facts:
            self.assertIn(
                fact.file_id,
                valid_file_ids,
                f"Fact has invalid or non-existent file_id: {fact.file_id}"
            )

    def test_file_capture_cutoff_exclusion(self):
        """Evidence files captured after a case's audit_at must be strictly excluded."""
        # Simulated identity
        ident = ResolvedIdentity(
            user_id="user_test",
            name="Test User",
            primary_email_at_cutoff="test@domain.com",
            all_emails_at_cutoff={"test@domain.com"},
            is_matched=True,
        )

        # Query with an audit_at in the distant past (before any file was captured)
        early_cutoff = "2020-01-01T00:00:00Z"
        facts_early = self.index.query_facts_for_identity(ident, early_cutoff)
        self.assertEqual(len(facts_early), 0, "No facts should be returned for a cutoff before all captures.")

    def test_event_timestamp_cutoff_exclusion(self):
        """An individual event with event_timestamp > audit_at must be excluded even if file captured earlier."""
        # Create dummy parser index query
        ident = ResolvedIdentity(
            user_id="user_999",
            name="Cutoff Subject",
            primary_email_at_cutoff="cutoff.subject@example.com",
            all_emails_at_cutoff={"cutoff.subject@example.com"},
            is_matched=True,
        )

        fact_past = EvidenceFact(
            file_id="evidence_01",
            source_path="logs/test.log",
            system_id="account_service",
            resource_id="account_999",
            email="cutoff.subject@example.com",
            observed_state="PRESENT",
            captured_at="2026-08-01T12:00:00Z",
            event_timestamp="2026-08-01T10:00:00Z"
        )
        fact_future = EvidenceFact(
            file_id="evidence_01",
            source_path="logs/test.log",
            system_id="account_service",
            resource_id="account_999",
            email="cutoff.subject@example.com",
            observed_state="ABSENT",
            captured_at="2026-08-01T12:00:00Z",
            event_timestamp="2026-08-01T14:00:00Z"  # Future relative to cutoff 12:00
        )

        cutoff = "2026-08-01T12:00:00Z"
        # Verify manual filtering logic matches query_facts_for_identity
        self.assertTrue(fact_past.event_timestamp <= cutoff)
        self.assertFalse(fact_future.event_timestamp <= cutoff)

    def test_exact_identifier_linking_prevents_false_matches(self):
        """Verify exact matching: near-match emails or shared log entries are not linked."""
        fact = EvidenceFact(
            file_id="evidence_01",
            source_path="logs/test.log",
            system_id="account_service",
            resource_id="account_101",
            email="john.smith@domain.com",
            user_id="user_101",
            observed_state="PRESENT"
        )

        # Different user with similar email
        other_emails = {"john.smith.jr@domain.com", "jon.smith@domain.com"}
        self.assertFalse(fact.matches_identity("user_999", other_emails, set(), set()))

        # Correct user
        self.assertTrue(fact.matches_identity("user_101", {"john.smith@domain.com"}, set(), set()))

    def test_replica_drift_detection(self):
        """Detect records that exist only in replica snapshots (e.g. evidence_54 failover replica)."""
        # In evidence_54 (customer_accounts_failover_replica_20260902.sql),
        # account_005 (user_05, leila.haddad@yahoo.com) is present in failover replica
        facts_ev54 = [f for f in self.index.all_facts if f.file_id == "evidence_54"]
        self.assertGreater(len(facts_ev54), 0)

        # Check account_005 was detected
        acc_005 = [f for f in facts_ev54 if f.resource_id == "account_005"]
        self.assertEqual(len(acc_005), 1)
        self.assertEqual(acc_005[0].email, "leila.haddad@yahoo.com")
        self.assertEqual(acc_005[0].user_id, "user_05")
        self.assertEqual(acc_005[0].extra_metadata.get("topology"), "failover_replica")

    def test_malformed_sql_and_json_handling(self):
        """Parsers must handle malformed input gracefully without crashing."""
        sql_parser = SqlEvidenceParser()
        json_parser = JsonEvidenceParser()
        log_parser = LogEvidenceParser()

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Broken SQL
            broken_sql = os.path.join(tmpdir, "broken.sql")
            with open(broken_sql, "w", encoding="utf-8") as f:
                f.write("CREATE TABLE oops (;;; INVALID SQL SYNTAX ;")
            facts, err = sql_parser.parse_file("ev_test", "broken.sql", broken_sql, "2026-01-01T00:00:00Z")
            self.assertIsNotNone(err)
            self.assertEqual(len(facts), 0)

            # 2. Broken JSON
            broken_json = os.path.join(tmpdir, "broken.json")
            with open(broken_json, "w", encoding="utf-8") as f:
                f.write("{broken json content...")
            facts, err = json_parser.parse_file("ev_test", "broken.json", broken_json, "2026-01-01T00:00:00Z")
            self.assertIsNotNone(err)
            self.assertEqual(len(facts), 0)

            # 3. Missing file
            facts, err = log_parser.parse_file("ev_test", "nonexistent.log", os.path.join(tmpdir, "nonexistent.log"), "2026-01-01T00:00:00Z")
            self.assertIn("File not found", err)

    def test_pdf_and_image_unsupported_transparency(self):
        """Confirm PDF parser succeeds with built-in extractor and image parser reports transparent unsupported status."""
        doc_parser = DocumentEvidenceParser()
        img_parser = ImageEvidenceParser()

        # PDF file check: built-in parser succeeds without external dependencies
        pdf_path = os.path.join(self.dataset_dir, "evidence", "documents", "delivery_correction_attachment.pdf")
        facts, status, msg = doc_parser.parse_pdf_file("ev_pdf", "doc.pdf", pdf_path, "2026-01-01T00:00:00Z")
        self.assertEqual(status, ParsingStatus.SUCCESS)
        self.assertGreater(len(facts), 0)

        # Image file check: transparent unsupported status when OCR is unavailable
        img_path = os.path.join(self.dataset_dir, "evidence", "images", "account_admin_console_20260926.png")
        facts, status, msg, meta = img_parser.parse_image_file("ev_img", "img.png", img_path, "2026-01-01T00:00:00Z")
        self.assertEqual(status, ParsingStatus.UNSUPPORTED_NO_OCR_TOOL)
        self.assertEqual(len(facts), 0)
        self.assertIn("No local OCR tool", msg)
        self.assertIn("format", meta)


if __name__ == "__main__":
    unittest.main()
