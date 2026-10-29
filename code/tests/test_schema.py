"""Tests for CSV schema loading, format enforcement, and malformed input handling."""

import os
import unittest
import io

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loaders import (
    load_deletion_requests,
    load_user_identities,
    load_user_audit_log,
    load_system_activity,
    load_deletion_rules,
    load_evidence_files,
    load_output_csv,
    validate_steps_json,
    validate_iso8601,
    SchemaValidationError,
)
from models import DeletionStatus, ReportedStatus


class TestSchemaValidation(unittest.TestCase):
    """Test suite for CSV loaders and validation rules."""

    @classmethod
    def setUpClass(cls):
        # Locate dataset directory relative to repository
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cls.dataset_dir = os.path.join(repo_root, "dataset")

    def test_load_all_real_dataset_csvs(self):
        """Verify that all 8 real dataset CSVs load cleanly without any schema error."""
        # 1. deletion_requests.csv
        reqs = load_deletion_requests(os.path.join(self.dataset_dir, "deletion_requests.csv"))
        self.assertEqual(len(reqs), 518)

        # 2. sample_deletion_requests.csv
        sample_reqs = load_deletion_requests(os.path.join(self.dataset_dir, "sample_deletion_requests.csv"))
        self.assertEqual(len(sample_reqs), 32)

        # 3. user_identities.csv
        identities = load_user_identities(os.path.join(self.dataset_dir, "user_identities.csv"))
        self.assertEqual(len(identities), 850)

        # 4. user_audit_log.csv
        audit_log = load_user_audit_log(os.path.join(self.dataset_dir, "user_audit_log.csv"))
        self.assertEqual(len(audit_log), 306)

        # 5. system_activity.csv
        activities = load_system_activity(os.path.join(self.dataset_dir, "system_activity.csv"))
        self.assertEqual(len(activities), 4011)

        # 6. deletion_rules.csv
        rules = load_deletion_rules(os.path.join(self.dataset_dir, "deletion_rules.csv"))
        self.assertEqual(len(rules), 15)

        # 7. evidence_files.csv
        evidence = load_evidence_files(os.path.join(self.dataset_dir, "evidence_files.csv"))
        self.assertEqual(len(evidence), 94)

        # 8. sample_output.csv
        sample_out = load_output_csv(os.path.join(self.dataset_dir, "sample_output.csv"))
        self.assertEqual(len(sample_out), 32)

    def test_malformed_iso8601_timestamps(self):
        """Reject invalid or non-ISO8601 timestamps."""
        valid_ts = ["2026-08-18T09:14:00Z", "2026-08-18T09:14:00+00:00", "2026-08-18T09:14:00.123Z"]
        for ts in valid_ts:
            self.assertTrue(validate_iso8601(ts))

        invalid_ts = [
            "",
            "2026/08/18 09:14:00",
            "18-08-2026T09:14:00Z",
            "2026-13-40T00:00:00Z",
            "yesterday",
            "2026-08-18",
        ]
        for ts in invalid_ts:
            with self.assertRaises(SchemaValidationError):
                validate_iso8601(ts)

    def test_missing_header_columns(self):
        """Reject CSVs with missing required headers."""
        bad_csv = "case_id,email,requested_at\ncase_01,test@example.com,2026-08-01T00:00:00Z\n"
        with self.assertRaises(SchemaValidationError) as ctx:
            load_deletion_requests(io.StringIO(bad_csv))
        self.assertIn("Header mismatch", str(ctx.exception))

    def test_extra_header_columns(self):
        """Reject CSVs with unexpected extra headers."""
        bad_csv = "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text,extra_col\n"
        with self.assertRaises(SchemaValidationError) as ctx:
            load_deletion_requests(io.StringIO(bad_csv))
        self.assertIn("Header mismatch", str(ctx.exception))

    def test_duplicate_primary_key(self):
        """Reject duplicate primary keys such as duplicate case_id or user_id."""
        duplicate_case_csv = (
            "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
            "case_01,a@example.com,2026-08-01T00:00:00Z,COMPLETE,2026-08-02T00:00:00Z,2026-08-03T00:00:00Z,delete\n"
            "case_01,b@example.com,2026-08-01T00:00:00Z,COMPLETE,2026-08-02T00:00:00Z,2026-08-03T00:00:00Z,delete\n"
        )
        with self.assertRaises(SchemaValidationError) as ctx:
            load_deletion_requests(io.StringIO(duplicate_case_csv))
        self.assertIn("duplicate case_id", str(ctx.exception))

    def test_invalid_reported_status(self):
        """Reject invalid values for reported_status."""
        bad_status_csv = (
            "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
            "case_01,a@example.com,2026-08-01T00:00:00Z,DONE_ALREADY,2026-08-02T00:00:00Z,2026-08-03T00:00:00Z,delete\n"
        )
        with self.assertRaises(SchemaValidationError) as ctx:
            load_deletion_requests(io.StringIO(bad_status_csv))
        self.assertIn("invalid reported_status", str(ctx.exception))

    def test_steps_json_non_applicable_must_be_empty(self):
        """NOT_APPLICABLE cases must have steps_json=[]"""
        valid_not_applicable = "[]"
        validate_steps_json(valid_not_applicable, DeletionStatus.NOT_APPLICABLE.value)

        invalid_not_applicable = '[{"step_no": 1, "phase": "FINDING", "system_id": "sys", "resource_id": "res", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_01"}]'
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_steps_json(invalid_not_applicable, DeletionStatus.NOT_APPLICABLE.value)
        self.assertIn("NOT_APPLICABLE status must have empty steps_json", str(ctx.exception))

    def test_steps_json_consecutive_numbering(self):
        """Reject steps where step_no is not consecutive starting at 1."""
        bad_numbering = '[{"step_no": 2, "phase": "VERIFICATION", "system_id": "sys", "resource_id": "res", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "ev_01"}]'
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_steps_json(bad_numbering, DeletionStatus.COMPLETE.value)
        self.assertIn("step numbering must be consecutive starting at 1", str(ctx.exception))

    def test_steps_json_phase_order_violation(self):
        """Reject steps where phase order violates FINDING -> REMEDIATION -> VERIFICATION."""
        bad_phase_order = [
            {"step_no": 1, "phase": "VERIFICATION", "system_id": "sys", "resource_id": "res1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
            {"step_no": 2, "phase": "FINDING", "system_id": "sys", "resource_id": "res2", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev1"}
        ]
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_steps_json(bad_phase_order, DeletionStatus.INCOMPLETE.value)
        self.assertIn("phase order violation", str(ctx.exception))

    def test_steps_json_invalid_operation_and_state(self):
        """Reject steps with unknown or disallowed operations or states."""
        bad_op = [
            {"step_no": 1, "phase": "FINDING", "system_id": "sys", "resource_id": "res1", "operation": "PURGE_NOW", "state": "PRESENT", "evidence_id": "ev1"}
        ]
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_steps_json(bad_op, DeletionStatus.INCOMPLETE.value)
        self.assertIn("invalid operation", str(ctx.exception))

        bad_state = [
            {"step_no": 1, "phase": "FINDING", "system_id": "sys", "resource_id": "res1", "operation": "REPORT_REMAINING_RECORD", "state": "MAYBE", "evidence_id": "ev1"}
        ]
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_steps_json(bad_state, DeletionStatus.INCOMPLETE.value)
        self.assertIn("invalid state", str(ctx.exception))

    def test_steps_json_invalid_evidence_rules(self):
        """Verify evidence ID rules: findings must have evidence; incomplete remediation must have empty evidence."""
        # Finding with empty evidence_id
        bad_finding = [
            {"step_no": 1, "phase": "FINDING", "system_id": "sys", "resource_id": "res1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": ""}
        ]
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_steps_json(bad_finding, DeletionStatus.INCOMPLETE.value)
        self.assertIn("FINDING steps must cite evidence", str(ctx.exception))

        # Remediation with non-empty evidence_id
        bad_remediation = [
            {"step_no": 1, "phase": "FINDING", "system_id": "sys", "resource_id": "res1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev1"},
            {"step_no": 2, "phase": "REMEDIATION", "system_id": "sys", "resource_id": "res1", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": "ev1"}
        ]
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_steps_json(bad_remediation, DeletionStatus.INCOMPLETE.value)
        self.assertIn("must have empty evidence_id", str(ctx.exception))

    def test_malformed_json_syntax(self):
        """Reject unparseable JSON in steps_json."""
        with self.assertRaises(SchemaValidationError):
            validate_steps_json("[{broken json", DeletionStatus.COMPLETE.value)


if __name__ == "__main__":
    unittest.main()
