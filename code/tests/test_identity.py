"""Tests for historical identity resolution and temporal cutoff enforcement."""

import os
import unittest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import UserIdentity, UserAuditLogEntry
from identity import IdentityResolver, normalize_email, normalize_phone


class TestIdentityResolution(unittest.TestCase):
    """Test suite for historical identity resolution."""

    def test_normalize_email(self):
        """Verify email normalization handles casing and whitespace properly."""
        self.assertEqual(normalize_email("  Amina.Elmasri@Gmail.com  "), "amina.elmasri@gmail.com")
        self.assertEqual(normalize_email("USER@DOMAIN.COM"), "user@domain.com")
        self.assertEqual(normalize_email(""), "")
        self.assertEqual(normalize_email(None), "")

    def test_current_and_historical_email_matching(self):
        """Match users by either their current email or historical email."""
        identities = [
            UserIdentity(
                user_id="user_10",
                name="Nadia Petrescu",
                email="n.petrescu@yahoo.com",
                phone="+40 723 481 638",
                email_hash="hash_3",
                updated_at="2026-04-12T14:38:26Z"
            )
        ]
        audit_log = [
            UserAuditLogEntry(
                audit_id="audit_01",
                user_id="user_10",
                event_time="2025-12-13T08:17:43Z",
                field_name="email",
                old_value="nadia.ionescu@yahoo.com",
                new_value="nadia.petrescu@yahoo.com"
            ),
            UserAuditLogEntry(
                audit_id="audit_02",
                user_id="user_10",
                event_time="2026-04-12T14:38:26Z",
                field_name="email",
                old_value="nadia.petrescu@yahoo.com",
                new_value="n.petrescu@yahoo.com"
            )
        ]
        resolver = IdentityResolver(identities, audit_log)

        # Match via current email
        cutoff = "2026-09-01T00:00:00Z"
        res_current = resolver.find_user_by_email_at("n.petrescu@yahoo.com", cutoff)
        self.assertTrue(res_current.is_matched)
        self.assertEqual(res_current.user_id, "user_10")
        self.assertEqual(res_current.primary_email_at_cutoff, "n.petrescu@yahoo.com")
        self.assertIn("nadia.ionescu@yahoo.com", res_current.historical_emails_at_cutoff)
        self.assertIn("nadia.petrescu@yahoo.com", res_current.historical_emails_at_cutoff)

        # Match via oldest historical email with mixed case & spaces
        res_hist = resolver.find_user_by_email_at("  Nadia.Ionescu@Yahoo.com ", cutoff)
        self.assertTrue(res_hist.is_matched)
        self.assertEqual(res_hist.user_id, "user_10")

    def test_cutoff_temporal_enforcement_boundary(self):
        """Ensure changes occurring after audit_at are strictly excluded."""
        # Timeline:
        # Event time: 2026-06-01T12:00:00Z -> email changed from old@test.com to new@test.com
        identities = [
            UserIdentity(
                user_id="user_99",
                name="Test User",
                email="new@test.com",
                phone="+1 555 0100",
                email_hash="hash_new",
                updated_at="2026-06-01T12:00:00Z"
            )
        ]
        audit_log = [
            UserAuditLogEntry(
                audit_id="audit_99",
                user_id="user_99",
                event_time="2026-06-01T12:00:00Z",
                field_name="email",
                old_value="old@test.com",
                new_value="new@test.com"
            )
        ]
        resolver = IdentityResolver(identities, audit_log)

        # 1. Cutoff immediately BEFORE change: 2026-06-01T11:59:59Z
        cutoff_before = "2026-06-01T11:59:59Z"
        res_before = resolver.find_user_by_email_at("old@test.com", cutoff_before)
        self.assertTrue(res_before.is_matched)
        self.assertEqual(res_before.user_id, "user_99")
        self.assertEqual(res_before.primary_email_at_cutoff, "old@test.com")
        self.assertEqual(len(res_before.historical_emails_at_cutoff), 0)
        self.assertNotIn("new@test.com", res_before.all_emails_at_cutoff)

        # Querying new@test.com before cutoff should NOT match user_99 as of cutoff
        res_future_email = resolver.find_user_by_email_at("new@test.com", cutoff_before)
        self.assertFalse(res_future_email.is_matched)
        self.assertEqual(res_future_email.ambiguity_reason, "email_change_occurred_after_cutoff")

        # 2. Cutoff EXACTLY AT change: 2026-06-01T12:00:00Z
        cutoff_exact = "2026-06-01T12:00:00Z"
        res_exact = resolver.find_user_by_email_at("new@test.com", cutoff_exact)
        self.assertTrue(res_exact.is_matched)
        self.assertEqual(res_exact.user_id, "user_99")
        self.assertEqual(res_exact.primary_email_at_cutoff, "new@test.com")
        self.assertIn("old@test.com", res_exact.historical_emails_at_cutoff)

        # 3. Cutoff immediately AFTER change: 2026-06-01T12:00:01Z
        cutoff_after = "2026-06-01T12:00:01Z"
        res_after = resolver.find_user_by_email_at("new@test.com", cutoff_after)
        self.assertTrue(res_after.is_matched)
        self.assertEqual(res_after.primary_email_at_cutoff, "new@test.com")
        self.assertIn("old@test.com", res_after.historical_emails_at_cutoff)

    def test_duplicate_identity_conflict(self):
        """If two distinct users share an email address, flag ambiguity without false merge."""
        identities = [
            UserIdentity(
                user_id="user_A",
                name="Alice One",
                email="shared@example.com",
                phone="+1 555 1111",
                email_hash="hash_a",
                updated_at="2026-01-01T00:00:00Z"
            ),
            UserIdentity(
                user_id="user_B",
                name="Alice Two",
                email="shared@example.com",
                phone="+1 555 2222",
                email_hash="hash_b",
                updated_at="2026-01-01T00:00:00Z"
            ),
        ]
        resolver = IdentityResolver(identities, [])
        res = resolver.find_user_by_email_at("shared@example.com", "2026-06-01T00:00:00Z")
        self.assertFalse(res.is_matched)
        self.assertTrue(res.is_ambiguous)
        self.assertIn("duplicate_identity_conflict", res.ambiguity_reason)

    def test_prevent_false_merges_on_similar_names(self):
        """Never merge distinct users simply because names are similar."""
        identities = [
            UserIdentity(
                user_id="user_01",
                name="John Smith",
                email="john.smith@domain.com",
                phone="+1 555 0001",
                email_hash="hash_1",
                updated_at="2026-01-01T00:00:00Z"
            ),
            UserIdentity(
                user_id="user_02",
                name="Jon Smith",
                email="jon.smith@domain.com",
                phone="+1 555 0002",
                email_hash="hash_2",
                updated_at="2026-01-01T00:00:00Z"
            ),
        ]
        resolver = IdentityResolver(identities, [])
        res1 = resolver.find_user_by_email_at("john.smith@domain.com", "2026-05-01T00:00:00Z")
        res2 = resolver.find_user_by_email_at("jon.smith@domain.com", "2026-05-01T00:00:00Z")
        self.assertEqual(res1.user_id, "user_01")
        self.assertEqual(res2.user_id, "user_02")
        self.assertNotEqual(res1.user_id, res2.user_id)
        # Ensure user_01 does not contain user_02's email
        self.assertNotIn("jon.smith@domain.com", res1.all_emails_at_cutoff)


    def test_multi_step_history_reconstruction(self):
        """Verify accurate interval reconstruction when a user changes email and phone multiple times."""
        # e0 -> e1 -> e2
        # p0 -> p1
        identities = [
            UserIdentity(
                user_id="user_multi",
                name="Multi User",
                email="e2@test.com",
                phone="+1 555 0002",
                email_hash="h2",
                updated_at="2026-06-01T00:00:00Z"
            )
        ]
        audit_log = [
            UserAuditLogEntry(
                audit_id="a1",
                user_id="user_multi",
                event_time="2025-01-01T00:00:00Z",
                field_name="email",
                old_value="e0@test.com",
                new_value="e1@test.com"
            ),
            UserAuditLogEntry(
                audit_id="a2",
                user_id="user_multi",
                event_time="2026-01-01T00:00:00Z",
                field_name="email",
                old_value="e1@test.com",
                new_value="e2@test.com"
            ),
            UserAuditLogEntry(
                audit_id="a3",
                user_id="user_multi",
                event_time="2025-06-01T00:00:00Z",
                field_name="phone",
                old_value="+1 555 0000",
                new_value="+1 555 0001"
            ),
            UserAuditLogEntry(
                audit_id="a4",
                user_id="user_multi",
                event_time="2026-06-01T00:00:00Z",
                field_name="phone",
                old_value="+1 555 0001",
                new_value="+1 555 0002"
            ),
        ]
        resolver = IdentityResolver(identities, audit_log)

        # Midpoint cutoff: 2025-08-01T00:00:00Z (after e1, after p1, but BEFORE e2 and p2)
        cutoff_mid = "2025-08-01T00:00:00Z"
        res_mid = resolver.find_user_by_email_at("e1@test.com", cutoff_mid)
        self.assertTrue(res_mid.is_matched)
        self.assertEqual(res_mid.primary_email_at_cutoff, "e1@test.com")
        self.assertIn("e0@test.com", res_mid.historical_emails_at_cutoff)
        self.assertNotIn("e2@test.com", res_mid.all_emails_at_cutoff)
        self.assertEqual(res_mid.primary_phone_at_cutoff, "+1 555 0001")
        self.assertIn("+1 555 0000", res_mid.historical_phones_at_cutoff)
        self.assertNotIn("+1 555 0002", res_mid.all_phones_at_cutoff)


if __name__ == "__main__":
    unittest.main()
