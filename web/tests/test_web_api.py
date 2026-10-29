"""Automated Integration & API Test Suite for Ghost Audit OS Web Server.

Tests:
- API endpoint health & metadata
- Input schema validation (clean, malformed, missing)
- Background audit job runner & status polling
- Results pagination, filtering, search, and PII masking
- 12-rule structural contract validation
- Public benchmark evaluation metrics reproducibility
- Artifact downloads & path traversal security protections
"""

import io
import json
import os
import sys
import unittest

# Ensure web package is on sys.path
web_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if web_dir not in sys.path:
    sys.path.insert(0, web_dir)

from app import app
from audit_service import audit_manager, mask_email


class TestWebAPI(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_01_index_html_renders(self):
        """Root GET / must render HTML with 200 status code and security headers."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Ghost Audit OS", response.data)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")

    def test_02_health_endpoint(self):
        """GET /api/health must report healthy status and loaded cases."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("engine_state", data)
        self.assertTrue(data["output_available"])

    def test_03_datasets_info(self):
        """GET /api/datasets/info must list all 94 evidence files and 8 datasets."""
        response = self.client.get("/api/datasets/info")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["evidence_total"], 94)
        self.assertGreaterEqual(data["evidence_available"], 90)
        self.assertEqual(len(data["datasets"]), 8)

    def test_04_validate_input_default_and_sample(self):
        """POST /api/validate/input must validate default and sample datasets."""
        # 1. Default scored dataset (518 cases)
        res1 = self.client.post("/api/validate/input", json={"dataset_type": "default"})
        self.assertEqual(res1.status_code, 200)
        d1 = res1.get_json()
        self.assertTrue(d1["success"])
        self.assertEqual(d1["total_rows"], 518)

        # 2. Sample dataset (32 cases)
        res2 = self.client.post("/api/validate/input", json={"dataset_type": "sample"})
        self.assertEqual(res2.status_code, 200)
        d2 = res2.get_json()
        self.assertTrue(d2["success"])
        self.assertEqual(d2["total_rows"], 32)

    def test_05_validate_input_malformed_and_missing_file(self):
        """POST /api/validate/input must reject malformed CSV headers and missing columns."""
        # Bad CSV header
        bad_csv = io.BytesIO(b"case_id,wrong_email,missing_requested_at\ncase_01,foo@example.com,2026-09-01\n")
        res = self.client.post(
            "/api/validate/input",
            data={"file": (bad_csv, "test_malformed.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Header mismatch", data["error"])

    def test_06_audit_status_endpoint(self):
        """GET /api/audit/status must return current status snapshot."""
        response = self.client.get("/api/audit/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("status", data)
        self.assertIn("counts", data)

    def test_07_audit_results_pagination_and_filtering(self):
        """GET /api/audit/results must support pagination, status filtering, and search."""
        # 1. Pagination
        res = self.client.get("/api/audit/results?page=1&page_size=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(data["items"]), 10)
        self.assertEqual(data["current_page"], 1)

        # 2. Status filtering for COMPLETE
        res_comp = self.client.get("/api/audit/results?status=COMPLETE&page_size=500")
        self.assertEqual(res_comp.status_code, 200)
        d_comp = res_comp.get_json()
        self.assertEqual(d_comp["total_items"], 188)
        self.assertTrue(all(item["deletion_status"] == "COMPLETE" for item in d_comp["items"]))

        # 3. Status filtering for NOT_APPLICABLE
        res_na = self.client.get("/api/audit/results?status=NOT_APPLICABLE")
        self.assertEqual(res_na.status_code, 200)
        d_na = res_na.get_json()
        self.assertEqual(d_na["total_items"], 10)
        self.assertTrue(all(item["steps_count"] == 0 for item in d_na["items"]))

        # 4. Search by case ID
        res_search = self.client.get("/api/audit/results?search=case_100")
        self.assertEqual(res_search.status_code, 200)
        d_search = res_search.get_json()
        self.assertGreaterEqual(d_search["total_items"], 1)
        self.assertEqual(d_search["items"][0]["case_id"], "case_100")

    def test_08_pii_masking_toggle(self):
        """Verify that PII masking masks emails in responses."""
        res_masked = self.client.get("/api/audit/results?search=case_100&mask_pii=true")
        item_masked = res_masked.get_json()["items"][0]
        self.assertIn("***", item_masked["email"])

        res_unmasked = self.client.get("/api/audit/results?search=case_100&mask_pii=false")
        item_unmasked = res_unmasked.get_json()["items"][0]
        self.assertNotIn("***", item_unmasked["email"])

    def test_09_case_detail_endpoint(self):
        """GET /api/audit/results/<case_id> returns full step breakdown."""
        res = self.client.get("/api/audit/results/case_100")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        c = data["case"]
        self.assertEqual(c["case_id"], "case_100")
        self.assertIn("steps", c)
        self.assertGreater(len(c["steps"]), 0)

        # 404 on invalid case
        res404 = self.client.get("/api/audit/results/non_existent_case_9999")
        self.assertEqual(res404.status_code, 404)

    def test_10_output_contract_validator(self):
        """POST /api/validate/output runs 12-point contract validation and returns 100% pass."""
        res = self.client.post("/api/validate/output")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["is_valid"])
        self.assertEqual(data["total_errors"], 0)
        self.assertEqual(len(data["rules"]), 12)
        self.assertTrue(all(r["passed"] for r in data["rules"]))

    def test_11_public_benchmark_runner(self):
        """POST /api/benchmark/run reproduces 100% status accuracy on public samples."""
        res = self.client.post("/api/benchmark/run")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        m = data["metrics"]
        self.assertEqual(m["status_accuracy"]["score"], 100.0)
        self.assertEqual(m["status_accuracy"]["numerator"], 32)
        self.assertEqual(m["status_accuracy"]["denominator"], 32)
        self.assertGreater(m["step_precision"]["score"], 75.0)
        self.assertGreater(m["step_recall"]["score"], 70.0)
        self.assertEqual(m["field_accuracy"]["score"], 100.0)
        self.assertEqual(len(data["cases"]), 32)

    def test_12_downloads_output_and_reports(self):
        """Verify file download endpoints for output.csv and reports."""
        # 1. output.csv
        res_csv = self.client.get("/api/download/output.csv")
        self.assertEqual(res_csv.status_code, 200)
        self.assertIn("text/csv", res_csv.headers.get("Content-Type", ""))
        self.assertIn("case_id,deletion_status,steps_json", res_csv.data.decode("utf-8")[:100])

        # 2. evaluation report
        res_eval = self.client.get("/api/download/report/evaluation")
        self.assertEqual(res_eval.status_code, 200)

        # 3. usage report
        res_usage = self.client.get("/api/download/report/usage")
        self.assertEqual(res_usage.status_code, 200)

        # 4. validation json report
        res_val = self.client.get("/api/download/report/validation")
        self.assertEqual(res_val.status_code, 200)
        val_data = json.loads(res_val.data)
        self.assertTrue(val_data["is_valid"])

    def test_13_artifact_downloads_and_security(self):
        """Verify downloads of verified submission packages and test path traversal protection."""
        # 1. code.zip
        res_code = self.client.get("/api/download/artifact/code.zip")
        self.assertEqual(res_code.status_code, 200)
        self.assertEqual(res_code.headers.get("Content-Type"), "application/zip")

        # 2. log.txt
        res_log = self.client.get("/api/download/artifact/log.txt")
        self.assertEqual(res_log.status_code, 200)

        # 3. agent-trace.zip
        res_trace = self.client.get("/api/download/artifact/agent-trace.zip")
        self.assertEqual(res_trace.status_code, 200)

        # 4. Path traversal attempt must be rejected
        res_bad1 = self.client.get("/api/download/artifact/../../etc/passwd")
        self.assertIn(res_bad1.status_code, [400, 404])

        res_bad2 = self.client.get("/api/download/artifact/unauthorized.sh")
        self.assertEqual(res_bad2.status_code, 400)


if __name__ == "__main__":
    unittest.main()
